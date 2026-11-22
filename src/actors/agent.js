// Agent SDK. An agent holds a long-term key known only to its directory and
// records services, and a separate presentation key per counterparty (a PPID)
// or per presentation (an unlinkable ID), so nothing it shows one counterparty
// can be matched against what it shows another.
import { generateSigningKey, signJws, nowSeconds, randomId, digestOf, publicOf, decodeJws } from '../lib/crypto.js';
import { postJson, getJson, postSigned, ServiceError } from '../lib/http.js';
import { present, unpackSdJwt } from '../lib/sd-jwt.js';
import { detailMatches, toRar } from '../lib/scope.js';
import { COUNTERPARTY_METADATA_PATH } from '../lib/protocol.js';
import { buildPresentationRequest } from '../lib/presentation.js';
import { TYP as RS_TYP, TOKEN_EXCHANGE } from '../records/records.js';
import { TYP as DIRECTORY_TYP, AGENT_PROOF_PURPOSE } from '../directory/directory.js';

const IDENTITY_CLAIMS = ['legal_name', 'jurisdiction', 'registration_number', 'lei'];
/** Optional claims about the principal and the chain; shown only on request. */
const SUMMARY_CLAIMS = ['principal_type', 'assurance', 'verification_source', 'chain_length', 'principal_directory'];

/**
 * What a counterparty asks for on one action: its standing requests, plus
 * the claims that action's policy tiers say they need.
 */
export function requestsFor(meta, action) {
  const req = { ...(meta.requests ?? {}) };
  for (const tier of meta.actions?.[action] ?? []) {
    const need = tier.require ?? {};
    if (need.principalType) req.principal_type = true;
    if (need.assurance || need.trustFramework) req.assurance = true;
    if (need.maxChainLength != null) req.chain_length = true;
  }
  return req;
}

const REFRESH_MARGIN_SECONDS = 30;

export class Agent {
  constructor({ name, trust }) {
    this.name = name;
    this.trust = trust;
    this.longTermKey = generateSigningKey();
    this.directory = null;
    this.registrationId = null;
    this.receipt = null;
    this.records = [];
    this.grants = [];
    this.contexts = new Map(); // audience -> pairwise context
    this.counterpartyMetadata = new Map();
  }

  attach({ directory, registrationId, receipt, records }) {
    this.directory = directory;
    this.registrationId = registrationId;
    this.receipt = receipt;
    this.records = records ?? [];
  }

  /** grant: the grant JWS, which the agent presents as the subject token in token exchange. */
  addGrant({ grantId, rs, grant }) {
    this.grants.unshift({ grantId, rs, grant });
  }

  /** New long-term key and receipt (after a transfer or key rotation): every per-counterparty credential starts over. */
  rekey(newKey, receipt) {
    this.longTermKey = newKey;
    this.receipt = receipt;
    this.contexts.clear();
    this.grants = [];
  }

  /** Fetch a current receipt, e.g. after an ancestor changed hands. Old grants no longer bind, so they are dropped. */
  async refreshReceipt() {
    const res = await this.call(`${this.directory.url}/v1/registrations/${this.registrationId}/receipt`, {});
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

  /**
   * Proof that this agent holds a key (AG-2): a statement signed with the key,
   * for one directory, one purpose, and one registrant, registration or offer.
   */
  keyProof(directoryId, purpose, binding, key = this.longTermKey) {
    return signJws({ aud: directoryId, purpose, binding, agent_key: key.kid, iat: nowSeconds() }, key, { typ: DIRECTORY_TYP.agentProof });
  }

  /** A request to the agent's directory, signed (RFC 9421) with its long-term key. */
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
      const res = await this.call(`${this.directory.url}/v1/attestations`, { audience, mode, cnf_jwk: publicOf(ctx.key.publicJwk) });
      ctx.attestation = res.attestation;
      ctx.aaf_id = res.aaf_id;
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
   * RFC 8693 Token Exchange at the authorization records service: the grant is the
   * subject token, the accountability credential the actor token; the agent
   * authenticates with an RFC 7523 JWT assertion signed by its long-term key.
   */
  async exchangeToken(grant, accountability, audience) {
    const now = nowSeconds();
    const clientId = `urn:aaf:registration:${this.registrationId}`;
    const assertion = signJws(
      { iss: clientId, sub: clientId, aud: `${grant.rs.id}/token`, iat: now, exp: now + 60, jti: randomId('ca', 12) },
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
      res = await fetch(`${grant.rs.url}/token`, { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body: form, signal: AbortSignal.timeout(5000) });
    } catch (err) {
      throw new ServiceError(0, 'unreachable', `could not reach ${grant.rs.url}: ${err.message}`);
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
  // Acting at a counterparty
  // -------------------------------------------------------------------------

  async metadataFor(counterpartyUrl) {
    if (!this.counterpartyMetadata.has(counterpartyUrl)) this.counterpartyMetadata.set(counterpartyUrl, await getJson(`${counterpartyUrl}${COUNTERPARTY_METADATA_PATH}`));
    return this.counterpartyMetadata.get(counterpartyUrl);
  }

  /**
   * Ask a counterparty to perform an action.
   * opts.disclose: { identity: bool, attributes: [names], provenance: bool, purpose: bool,
   *                  principal_type, assurance, verification_source, chain_length, principal_directory: bool,
   *                  activity_log: bool (default true: the pointer to the shared activity log) }
   *   (defaults: the ID alone, plus only what the counterparty asks for on this action and the principal allowed)
   * opts.approval: an approval credential to carry
   * opts.headers: extra headers, e.g. a service's passkey approval reference (aaf-approval-ref)
   */
  async act(counterpartyUrl, action, params = {}, opts = {}) {
    const meta = await this.metadataFor(counterpartyUrl);
    const ctx = await this.contextFor(meta.id, { mode: opts.mode ?? 'pairwise', grantId: opts.grantId });
    const requested = requestsFor(meta, action);
    const disclose = {
      identity: opts.disclose?.identity ?? Boolean(requested.identity),
      attributes: opts.disclose?.attributes ?? requested.attributes ?? [],
      provenance: opts.disclose?.provenance ?? Boolean(requested.provenance),
      purpose: opts.disclose?.purpose ?? false,
      activity_log: opts.disclose?.activity_log ?? true,
    };
    for (const c of SUMMARY_CLAIMS) disclose[c] = opts.disclose?.[c] ?? Boolean(requested[c]);

    const accountability = present(ctx.attestation, (d) => {
      if (d.name && IDENTITY_CLAIMS.includes(d.name)) return disclose.identity;
      if (d.name && SUMMARY_CLAIMS.includes(d.name)) return disclose[d.name];
      if (d.value && typeof d.value === 'object' && 'claims' in d.value && 'verification' in d.value) {
        return disclose.attributes.includes(Object.keys(d.value.claims)[0]);
      }
      if (d.value && typeof d.value === 'object' && 'role' in d.value && 'rs' in d.value) {
        // Record pointers: where the shared activity log is (so both sides can write to it), and the bill of materials on request.
        if (d.value.role === 'activity') return disclose.activity_log;
        return d.value.role === 'provenance' && disclose.provenance;
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

    const url = `${counterpartyUrl}/actions/${action}`;
    const { body, headers } = buildPresentationRequest({ url, counterpartyId: meta.id, params, accountability, authorization, approval: opts.approval, key: ctx.key });
    const presentation = { accountability, authorization, approval: opts.approval };
    const started = performance.now();
    const res = await fetch(url, { method: 'POST', headers: { ...headers, ...(opts.headers ?? {}) }, body });
    const response = await res.json();
    const latencyMs = Math.round((performance.now() - started) * 10) / 10;

    const agentLog = await this.logActivity(ctx, {
      txn: response.txn,
      event: 'action',
      details: { action, params_digest: digestOf(params), outcome: response.decision, at_counterparty: meta.id },
    });
    return { httpStatus: res.status, ...response, aaf_id: ctx.aaf_id, mode: ctx.mode, latencyMs, presentation, agentLog };
  }

  /** The agent's own account of what it did, written to the activity records service named in its registration. */
  async logActivity(ctx, { txn, event, details }) {
    const pointer = this.records.find((r) => r.role === 'activity');
    if (!pointer) return null;
    const rs = this.trust.recordsService(pointer.rs);
    const entry = signJws(
      { subject: ctx.aaf_id, txn: txn ?? null, writer_role: 'agent', event, details, at: new Date().toISOString() },
      ctx.key,
      { typ: RS_TYP.activity, embedJwk: true },
    );
    try {
      return (await postJson(`${rs.url}/v1/activity`, { entry })).receipt;
    } catch {
      return null;
    }
  }

  // -------------------------------------------------------------------------
  // Acting as a delegating agent: registering and authorizing sub-agents (AG-3)
  // -------------------------------------------------------------------------

  async registerSubagent(child, { directory = this.directory, label, records, provider = null, expiresIn = null, lineage = null }) {
    let res;
    const agentJwk = publicOf(child.longTermKey.publicJwk);
    if (directory.id === this.directory.id) {
      res = await this.call(`${directory.url}/v1/registrations`, {
        agent_jwk: agentJwk, agent_proof: child.keyProof(directory.id, AGENT_PROOF_PURPOSE.registration, `registration:${this.registrationId}`),
        parent: { type: 'agent' }, records, provider, label, expires_in: expiresIn, lineage,
      });
    } else {
      // Cross-directory: prove our own registration to the other directory with an ID addressed to it,
      // disclosing only what that directory needs to vouch for the sub-agent's chain.
      const ctx = await this.contextFor(directory.id, { mode: 'pairwise' });
      const attestation = present(ctx.attestation, (d) => SUMMARY_CLAIMS.includes(d.name));
      res = await postSigned(
        `${directory.url}/v1/registrations`,
        {
          agent_jwk: agentJwk, agent_proof: child.keyProof(directory.id, AGENT_PROOF_PURPOSE.registration, `jkt:${ctx.key.kid}`),
          parent: { type: 'remote_agent', attestation }, records, provider, label, expires_in: expiresIn, lineage,
        },
        ctx.key,
        { embedJwk: true },
      );
    }
    child.attach({ directory, registrationId: res.registration_id, receipt: res.receipt, records });
    return res;
  }

  /** Delegate part of this agent's authority to a sub-agent. The records service enforces that it only narrows. */
  async delegate(child, { permissions, prohibitions = [], delegation = { allowed: false, max_depth: 0 }, validForDays, purpose, grantId }) {
    const parentGrant = grantId ? this.grants.find((g) => g.grantId === grantId) : this.grants[0];
    if (!parentGrant) throw new Error(grantId ? `no grant ${grantId} to delegate from` : 'this agent holds no grant to delegate from');
    const now = nowSeconds();
    const exp = delegatedGrantExpiry({ now, parentExp: decodeJws(parentGrant.grant).payload.exp, validForDays });
    const grant = signJws(
      {
        iss: `agent:${this.registrationId}@${this.directory.id}`,
        sub: child.registrationId,
        directory: child.directory.id,
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
      { typ: RS_TYP.grant, embedJwk: true },
    );
    const res = await postJson(`${parentGrant.rs.url}/v1/grants`, { grant, registration_receipt: child.receipt });
    child.addGrant({ grantId: res.grant_id, rs: parentGrant.rs, grant });
    return res;
  }

  async revokeSubagent(child, reason = 'principal_request') {
    if (child.directory.id === this.directory.id) {
      return this.call(`${child.directory.url}/v1/registrations/${child.registrationId}/revoke`, { reason });
    }
    const ctx = await this.contextFor(child.directory.id, { mode: 'pairwise' });
    return postSigned(`${child.directory.url}/v1/registrations/${child.registrationId}/revoke`, { reason }, ctx.key, { embedJwk: true });
  }
}

/** How long a delegated grant lasts when no length is requested. */
export const DEFAULT_DELEGATION_DAYS = 7;

/**
 * The expiry (seconds) of a grant delegated under a parent grant that expires
 * at parentExp. With no requested length, the default is cut to the parent's
 * expiry, as a sub-agent's registration is cut to its parent's lifetime. A
 * requested length that would outlive the parent is refused here, naming the
 * parent's expiry; the records service refuses it as well (spec §11.3).
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
