// Agent SDK. An agent holds a long-term key known only to its registry and
// record keepers, and a separate presentation key per relying party (pairwise
// mode) or per presentation (ephemeral mode), so nothing it shows one relying
// party can be matched against what it shows another.
import { generateSigningKey, signJws, nowSeconds, randomId, digestOf, publicOf, decodeJws } from '../lib/crypto.js';
import { postJson, getJson, postSigned, ServiceError } from '../lib/http.js';
import { present, unpackSdJwt } from '../lib/sd-jwt.js';
import { detailMatches, toRar } from '../lib/scope.js';
import { RP_METADATA_PATH } from '../lib/protocol.js';
import { buildPresentationRequest } from '../lib/presentation.js';
import { TYP as RK_TYP, TOKEN_EXCHANGE } from '../recordkeeper/recordkeeper.js';

const REFRESH_MARGIN_SECONDS = 30;

export class Agent {
  constructor({ name, trust }) {
    this.name = name;
    this.trust = trust;
    this.longTermKey = generateSigningKey();
    this.registry = null;
    this.registrationId = null;
    this.receipt = null;
    this.records = [];
    this.grants = [];
    this.contexts = new Map(); // audience -> pairwise context
    this.rpMetadata = new Map();
  }

  attach({ registry, registrationId, receipt, records }) {
    this.registry = registry;
    this.registrationId = registrationId;
    this.receipt = receipt;
    this.records = records ?? [];
  }

  /** grant: the grant JWS, which the agent presents as the subject token in token exchange. */
  addGrant({ grantId, rk, grant }) {
    this.grants.unshift({ grantId, rk, grant });
  }

  /** New long-term key and receipt (after a transfer or key rotation): every per-RP credential starts over. */
  rekey(newKey, receipt) {
    this.longTermKey = newKey;
    this.receipt = receipt;
    this.contexts.clear();
    this.grants = [];
  }

  /** Fetch a current receipt, e.g. after an ancestor changed hands. Old grants no longer bind, so they are dropped. */
  async refreshReceipt() {
    const res = await this.call(`${this.registry.url}/v1/registrations/${this.registrationId}/receipt`, {});
    if (res.receipt !== this.receipt) {
      const changed = res.version !== peek(this.receipt).version;
      this.receipt = res.receipt;
      if (changed) {
        this.contexts.clear();
        this.grants = [];
      }
    }
    return res;
  }

  /** A request to the agent's registry, signed (RFC 9421) with its long-term key. */
  call(url, params) {
    return postSigned(url, params, this.longTermKey, { keyid: `registration:${this.registrationId}` });
  }

  // -------------------------------------------------------------------------
  // Credentials for one audience
  // -------------------------------------------------------------------------

  async contextFor(audience, { mode = 'pairwise', grantId } = {}) {
    let ctx = mode === 'pairwise' ? this.contexts.get(audience) : null;
    const now = nowSeconds();
    if (!ctx) ctx = { audience, mode, key: generateSigningKey() };
    if (!ctx.attestation || ctx.expiresAt - REFRESH_MARGIN_SECONDS < now) {
      const res = await this.call(`${this.registry.url}/v1/attestations`, { audience, mode, cnf_jwk: publicOf(ctx.key.publicJwk) });
      ctx.attestation = res.attestation;
      ctx.ppid = res.ppid;
      ctx.expiresAt = res.expires_at;
      ctx.authorization = null;
    }
    const grant = grantId ? this.grants.find((g) => g.grantId === grantId) : this.grants[0];
    if (grant && (!ctx.authorization || ctx.authorizationGrant !== grant.grantId || ctx.authorizationExpiresAt - REFRESH_MARGIN_SECONDS < now)) {
      const res = await this.exchangeToken(grant, ctx.attestation, audience);
      ctx.authorization = res.access_token;
      ctx.authorizationGrant = grant.grantId;
      ctx.authorizationExpiresAt = now + res.expires_in;
    }
    if (mode === 'pairwise') this.contexts.set(audience, ctx);
    return ctx;
  }

  /**
   * RFC 8693 Token Exchange at the authorization record keeper: the grant is the
   * subject token, the accountability credential the actor token; the agent
   * authenticates with an RFC 7523 JWT assertion signed by its long-term key.
   */
  async exchangeToken(grant, accountability, audience) {
    const now = nowSeconds();
    const clientId = `urn:aaf:registration:${this.registrationId}`;
    const assertion = signJws(
      { iss: clientId, sub: clientId, aud: `${grant.rk.id}/token`, iat: now, exp: now + 60, jti: randomId('ca', 12) },
      this.longTermKey,
      { typ: 'JWT', embedJwk: true },
    );
    const form = new URLSearchParams({
      grant_type: TOKEN_EXCHANGE.grantType,
      subject_token: grant.grant,
      subject_token_type: TOKEN_EXCHANGE.subjectTokenType,
      actor_token: accountability,
      actor_token_type: TOKEN_EXCHANGE.actorTokenType,
      requested_token_type: TOKEN_EXCHANGE.requestedTokenType,
      audience,
      client_assertion_type: TOKEN_EXCHANGE.clientAssertionType,
      client_assertion: assertion,
    });
    let res;
    try {
      res = await fetch(`${grant.rk.url}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form, signal: AbortSignal.timeout(5000) });
    } catch (err) {
      throw new ServiceError(0, 'unreachable', `could not reach ${grant.rk.url}: ${err.message}`);
    }
    const json = await res.json();
    if (!res.ok) throw new ServiceError(res.status, json.error, json.error_description);
    return json;
  }

  /** Fields of the agent's own attestation, as the agent sees them (all disclosures). */
  ownView(ctx) {
    return unpackSdJwt(ctx.attestation).payload;
  }

  // -------------------------------------------------------------------------
  // Acting at a relying party
  // -------------------------------------------------------------------------

  async metadataFor(rpUrl) {
    if (!this.rpMetadata.has(rpUrl)) this.rpMetadata.set(rpUrl, await getJson(`${rpUrl}${RP_METADATA_PATH}`));
    return this.rpMetadata.get(rpUrl);
  }

  /**
   * Ask a relying party to perform an action.
   * opts.disclose: { identity: bool, attributes: [names], provenance: bool, purpose: bool }
   *   (defaults: reveal only what the relying party's metadata requests and the principal allowed)
   * opts.approval: an approval credential to carry
   * opts.headers: extra headers, e.g. a service's passkey approval reference (aaf-approval-ref)
   */
  async act(rpUrl, action, params = {}, opts = {}) {
    const meta = await this.metadataFor(rpUrl);
    const ctx = await this.contextFor(meta.id, { mode: opts.mode ?? 'pairwise', grantId: opts.grantId });
    const requested = meta.requests ?? {};
    const disclose = {
      identity: opts.disclose?.identity ?? Boolean(requested.identity),
      attributes: opts.disclose?.attributes ?? requested.attributes ?? [],
      provenance: opts.disclose?.provenance ?? Boolean(requested.provenance),
      purpose: opts.disclose?.purpose ?? false,
    };

    const accountability = present(ctx.attestation, (d) => {
      if (d.name && ['legal_name', 'jurisdiction', 'registration_number', 'lei'].includes(d.name)) return disclose.identity;
      if (d.value && typeof d.value === 'object' && 'claims' in d.value && 'verification' in d.value) {
        return disclose.attributes.includes(Object.keys(d.value.claims)[0]);
      }
      if (d.value && typeof d.value === 'object' && 'role' in d.value && 'rk' in d.value) {
        return d.value.role !== 'provenance' || disclose.provenance;
      }
      return false;
    });
    const authorization = ctx.authorization
      ? present(ctx.authorization, (d) => {
          // RAR authorization_details entries: reveal only those covering this action.
          if (d.value && typeof d.value === 'object' && 'type' in d.value) return detailMatches(d.value, action);
          if (d.name === 'purpose' || d.name === 'context') return disclose.purpose;
          return false;
        })
      : undefined;

    const url = `${rpUrl}/actions/${action}`;
    const { body, headers } = buildPresentationRequest({ url, rpId: meta.id, params, accountability, authorization, approval: opts.approval, key: ctx.key });
    const presentation = { accountability, authorization, approval: opts.approval };
    const started = performance.now();
    const res = await fetch(url, { method: 'POST', headers: { ...headers, ...(opts.headers ?? {}) }, body });
    const response = await res.json();
    const latencyMs = Math.round((performance.now() - started) * 10) / 10;

    const agentLog = await this.logActivity(ctx, {
      txn: response.txn,
      event: 'action',
      details: { action, params_digest: digestOf(params), outcome: response.decision, at_rp: meta.id },
    });
    return { httpStatus: res.status, ...response, ppid: ctx.ppid, mode: ctx.mode, latencyMs, presentation, agentLog };
  }

  /** The agent's own account of what it did, written to the activity record keeper named in its registration. */
  async logActivity(ctx, { txn, event, details }) {
    const pointer = this.records.find((r) => r.role === 'activity');
    if (!pointer) return null;
    const rk = this.trust.recordKeeper(pointer.rk);
    const entry = signJws(
      { subject: ctx.ppid, txn: txn ?? null, writer_role: 'agent', event, details, at: new Date().toISOString() },
      ctx.key,
      { typ: RK_TYP.activity, embedJwk: true },
    );
    try {
      return (await postJson(`${rk.url}/v1/activity`, { entry })).receipt;
    } catch {
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Acting as a principal for sub-agents (the "authorizing agent" of Figure 0)
  // -------------------------------------------------------------------------

  async registerSubagent(child, { registry = this.registry, label, records, provider = null, expiresIn = null, lineage = null }) {
    let res;
    if (registry.id === this.registry.id) {
      res = await this.call(`${registry.url}/v1/registrations`, {
        agent_jwk: publicOf(child.longTermKey.publicJwk), parent: { type: 'agent' }, records, provider, label, expires_in: expiresIn, lineage,
      });
    } else {
      // Cross-registry: prove our own registration to the other registry with a PPID addressed to it.
      const ctx = await this.contextFor(registry.id, { mode: 'pairwise' });
      res = await postSigned(
        `${registry.url}/v1/registrations`,
        { agent_jwk: publicOf(child.longTermKey.publicJwk), parent: { type: 'remote_agent', attestation: ctx.attestation }, records, provider, label, expires_in: expiresIn, lineage },
        ctx.key,
        { embedJwk: true },
      );
    }
    child.attach({ registry, registrationId: res.registration_id, receipt: res.receipt, records });
    return res;
  }

  /** Delegate part of this agent's authority to a sub-agent. The record keeper enforces that it only narrows. */
  async delegate(child, { permissions, prohibitions = [], delegation = { allowed: false, max_depth: 0 }, validForDays, purpose, grantId }) {
    const parentGrant = grantId ? this.grants.find((g) => g.grantId === grantId) : this.grants[0];
    if (!parentGrant) throw new Error(grantId ? `no grant ${grantId} to delegate from` : 'this agent holds no grant to delegate from');
    const now = nowSeconds();
    const exp = delegatedGrantExpiry({ now, parentExp: decodeJws(parentGrant.grant).payload.exp, validForDays });
    const grant = signJws(
      {
        iss: `agent:${this.registrationId}@${this.registry.id}`,
        sub: child.registrationId,
        registry: child.registry.id,
        agent_key: child.longTermKey.kid,
        iat: now,
        nbf: now,
        exp,
        jti: randomId('grt', 12),
        authorization_details: permissions.map(toRar),
        prohibitions: prohibitions.map(toRar),
        delegation,
        purpose,
        parent_grant: parentGrant.grantId,
      },
      this.longTermKey,
      { typ: RK_TYP.grant, embedJwk: true },
    );
    const res = await postJson(`${parentGrant.rk.url}/v1/grants`, { grant, registration_receipt: child.receipt });
    child.addGrant({ grantId: res.grant_id, rk: parentGrant.rk, grant });
    return res;
  }

  async revokeSubagent(child, reason = 'principal_request') {
    if (child.registry.id === this.registry.id) {
      return this.call(`${child.registry.url}/v1/registrations/${child.registrationId}/revoke`, { reason });
    }
    const ctx = await this.contextFor(child.registry.id, { mode: 'pairwise' });
    return postSigned(`${child.registry.url}/v1/registrations/${child.registrationId}/revoke`, { reason }, ctx.key, { embedJwk: true });
  }
}

/** How long a delegated grant lasts when no length is requested. */
export const DEFAULT_DELEGATION_DAYS = 7;

/**
 * The expiry (seconds) of a grant delegated under a parent grant that expires
 * at parentExp. With no requested length, the default is cut to the parent's
 * expiry, as a sub-agent's registration is cut to its parent's lifetime. A
 * requested length that would outlive the parent is refused here, naming the
 * parent's expiry; the record keeper refuses it as well (spec §11.3).
 */
export function delegatedGrantExpiry({ now, parentExp, validForDays }) {
  if (validForDays == null) {
    const exp = now + DEFAULT_DELEGATION_DAYS * 86400;
    return parentExp != null ? Math.min(exp, parentExp) : exp;
  }
  if (typeof validForDays !== 'number' || !(validForDays > 0) || !Number.isFinite(validForDays)) throw new Error('validForDays must be a positive number of days');
  const exp = now + validForDays * 86400;
  if (parentExp != null && exp > parentExp) {
    throw new Error(`a ${validForDays}-day grant would outlive its parent grant, which expires ${new Date(parentExp * 1000).toISOString()}`);
  }
  return exp;
}

/** Decode a presented SD-JWT's issuer-signed part without verifying (for display). */
export const peek = (sdJwt) => decodeJws(String(sdJwt).split('~')[0]).payload;
