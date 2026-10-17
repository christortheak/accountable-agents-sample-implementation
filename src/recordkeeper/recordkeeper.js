// Record keeper: holds authorization records (for principals), provenance
// records (from agent providers) and activity logs (from agents and relying
// parties). Every record is signed by its source, appended to a Merkle log, and
// acknowledged with a receipt the submitter can use to hold the keeper to it.
//
// The authorization role also runs an OAuth 2.0 Token Exchange endpoint
// (RFC 8693): the agent exchanges its grant (subject token) and its
// accountability credential (actor token) for an audience-specific,
// selectively disclosable authorization credential (SD-JWT VC) bound to its
// per-relying-party key, so relying parties never see the principal's own
// signature (which would identify the principal). Authority is expressed as
// RFC 9396 authorization_details; delegation chains as nested RFC 8693 `act`.
import path from 'node:path';
import {
  randomId, nowSeconds, signJws, verifyJws, verifySelfSignedJws, decodeJws, sha256b64u, randomBytes, b64u,
} from '../lib/crypto.js';
import { issueSdJwt, sd, verifySdJwt } from '../lib/sd-jwt.js';
import { MerkleLog } from '../lib/log.js';
import { jwksOf } from '../lib/openid-federation.js';
import { HttpError } from '../lib/http.js';
import { checkAttenuation } from '../lib/scope.js';
import { regBinding, TYP as REGISTRY_TYP } from '../registry/registry.js';
import { SD_JWT_VC_TYP, vct } from '../lib/credentials.js';
import { STATUS, allocateIndex, statusListToken } from '../lib/status-list.js';
import { hostOf } from '../lib/openid-federation.js';
import { bindingChallenge, creationOptions, requestOptions, verifyRegistration, verifyAssertion, WebAuthnError } from '../lib/webauthn.js';

export const TOKEN_EXCHANGE = {
  grantType: 'urn:ietf:params:oauth:grant-type:token-exchange',
  subjectTokenType: 'urn:ietf:params:oauth:token-type:jwt', // the grant (a JWS)
  actorTokenType: 'urn:aaf:params:oauth:token-type:accountability', // the registry's SD-JWT VC
  requestedTokenType: 'urn:aaf:params:oauth:token-type:authorization', // an SD-JWT VC
  clientAssertionType: 'urn:ietf:params:oauth:client-assertion-type:jwt-bearer', // RFC 7523
};

/** OAuth-style error (RFC 6749 §5.2) for the token endpoint. */
export class OAuthError extends Error {
  constructor(error, description, status = 400) {
    super(description);
    this.error = error;
    this.status = status;
  }
}

export const TYP = {
  grant: 'aaf-grant+jwt',
  authorization: SD_JWT_VC_TYP,
  approval: SD_JWT_VC_TYP,
  approvalRequest: 'aaf-approval-request+jwt',
  provenance: 'aaf-provenance+jwt',
  activity: 'aaf-activity+jwt',
  recordStatus: 'aaf-record-status+jwt',
};

export class RecordKeeper {
  constructor({ id, name, roles, keys, trustList, dataDir = null, allowTamperSimulation = false }) {
    this.id = id;
    this.name = name;
    this.roles = roles;
    this.keys = keys;
    this.trust = trustList;
    this.allowTamperSimulation = allowTamperSimulation;
    this.grants = new Map();
    this.attestations = new Map();
    this.approvals = new Map();
    this.provenance = new Map();
    this.activity = new Map(); // subject -> [log index]
    this.latestVersion = new Map(); // registration -> highest chain version seen in a receipt
    this.statusIndex = new Map(); // Token Status List idx -> { kind: 'authorization' | 'approval', ref }
    this.assertionIds = new Map(); // client assertion jti -> exp (replay protection)
    this.passkeys = new Map(); // WebAuthn credential id -> { public_jwk, alg, sign_count, display_name }
    this.pending = new Map(); // WebAuthn ceremony id -> { purpose, challenge, details, expires } (transient)
    this.log = new MerkleLog({ logId: id, signer: keys.signing, file: dataDir ? path.join(dataDir, 'records-log.jsonl') : null });
    this.log.entries.forEach((entry, index) => this.apply(entry, index));
  }

  commit(kind, data) {
    const entry = { kind, at: new Date().toISOString(), data };
    const { index } = this.log.append(entry);
    this.apply(entry, index);
    return this.log.receipt(index);
  }

  apply({ kind, at, data }, index) {
    switch (kind) {
      case 'grant.deposited':
        this.grants.set(data.id, { ...data, status: 'active', deposited_at: at, index });
        if (data.kind === 'agent') this.latestVersion.set(data.claims.sub, Math.max(this.latestVersion.get(data.claims.sub) ?? 0, data.version ?? 0));
        break;
      case 'grant.superseded':
        for (const gid of data.ids) {
          const g = this.grants.get(gid);
          if (g && g.status === 'active') Object.assign(g, { status: 'superseded', revoked_at: at, revocation_reason: data.reason });
        }
        break;
      case 'grant.revoked': {
        const g = this.grants.get(data.id);
        if (g) Object.assign(g, { status: 'revoked', revoked_at: at, revocation_reason: data.reason });
        break;
      }
      case 'authorization.attested':
        this.attestations.set(data.ref, { ...data, at });
        if (data.status_idx != null) this.statusIndex.set(data.status_idx, { kind: 'authorization', ref: data.ref });
        break;
      case 'passkey.registered':
        this.passkeys.set(data.credential_id, { public_jwk: data.public_jwk, alg: data.alg, sign_count: data.sign_count, display_name: data.display_name });
        break;
      case 'approval.attested':
        if (data.passkey && this.passkeys.has(data.passkey)) this.passkeys.get(data.passkey).sign_count = data.sign_count;
        this.approvals.set(data.ref, { ...data, at });
        if (data.status_idx != null) this.statusIndex.set(data.status_idx, { kind: 'approval', ref: data.ref });
        break;
      case 'provenance.deposited':
        this.provenance.set(data.id, { ...data, at, index });
        break;
      case 'activity.appended': {
        const list = this.activity.get(data.subject) ?? [];
        list.push(index);
        this.activity.set(data.subject, list);
        break;
      }
      default:
        // Unknown kinds (for example after tampering) are kept in the log but not indexed.
        break;
    }
  }

  requireRole(role) {
    if (!this.roles.includes(role)) throw new HttpError(404, 'role_not_offered', `${this.id} does not keep ${role} records`);
  }

  /** aaf_record_keeper metadata for this keeper's OpenID Federation Entity Configuration. */
  metadata(endpointBase) {
    return {
      organization_name: this.name,
      roles: this.roles,
      endpoint_base: endpointBase,
      jwks: jwksOf(this.keys.signing),
      endpoints: { token: '/token', status_lists: '/status-lists/1', provenance: '/v1/provenance', activity: '/v1/activity', log: '/v1/log/sth' },
    };
  }

  verifyRegistryToken(jws, typ) {
    const { header, payload: unverified } = decodeJws(String(jws).split('~')[0]);
    const registry = this.trust.registry(unverified.iss);
    if (!registry) throw new HttpError(403, 'untrusted_registry', `${unverified.iss} is not a trusted registry`);
    try {
      if (typ === REGISTRY_TYP.attestation) return verifySdJwt(jws, this.trust.signingKey(registry, header.kid), { typ }).payload;
      return verifyJws(jws, this.trust.signingKey(registry, header.kid), { typ }).payload;
    } catch (err) {
      throw new HttpError(403, 'invalid_registry_token', err.message);
    }
  }

  // -------------------------------------------------------------------------
  // Authorization records
  // -------------------------------------------------------------------------

  depositGrant({ grant, registration_receipt: receiptJws }) {
    this.requireRole('authorization');
    let verified;
    try {
      verified = verifySelfSignedJws(grant, { typ: TYP.grant });
    } catch (err) {
      throw new HttpError(400, 'invalid_grant', err.message);
    }
    const { payload: g, thumbprint: signer } = verified;
    if (this.grants.has(g.jti)) return { grant_id: g.jti, already: true };
    const receipt = this.verifyRegistryToken(receiptJws, REGISTRY_TYP.registration);
    const principalRefOf = (r) => `${r.iss}|${r.principal.id}`;

    if (g.grantee?.kind === 'person') {
      if (!this.passkeys.has(g.grantee.passkey)) throw new HttpError(400, 'unknown_passkey', 'the designee must first register a passkey with this keeper');
      // A role designation for a human (for example a designated officer).
      if (receipt.principal.type !== 'principal' || !receipt.principal.key_thumbprints.includes(signer)) {
        throw new HttpError(403, 'not_principal', 'role designations must be signed by the principal');
      }
      const data = {
        id: g.jti, kind: 'role', jws: grant, claims: g, grantor_key: signer, principal_ref: principalRefOf(receipt),
        effective_prohibitions: [], parent_grant: null, depth: 0,
      };
      return { grant_id: g.jti, receipt: this.commit('grant.deposited', data) };
    }

    if (g.sub !== receipt.sub || g.registry !== receipt.iss || g.agent_key !== receipt.agent_key) {
      throw new HttpError(400, 'grant_receipt_mismatch', 'grant does not name the agent in the registration receipt');
    }
    const version = receipt.version ?? 0;
    if (version < (this.latestVersion.get(receipt.sub) ?? 0)) {
      throw new HttpError(409, 'stale_receipt', 'the agent has changed hands since this receipt was issued');
    }
    let principalRef;
    let effectiveProhibitions = g.prohibitions ?? [];
    let depth = 1;
    if (receipt.principal.type === 'principal') {
      if (!receipt.principal.key_thumbprints.includes(signer)) throw new HttpError(403, 'not_principal', 'grant is not signed by the registered principal');
      if (g.parent_grant) throw new HttpError(400, 'unexpected_parent', 'a principal grant has no parent grant');
      principalRef = principalRefOf(receipt);
    } else {
      const parent = this.grants.get(g.parent_grant);
      if (!parent || parent.kind !== 'agent') throw new HttpError(400, 'unknown_parent_grant', 'delegated grants must name a parent grant held here');
      const parentStatus = this.grantStatus(parent);
      if (parentStatus.status !== 'active') throw new HttpError(403, 'parent_grant_inactive', `parent grant is ${parentStatus.status}`);
      if (signer !== parent.claims.agent_key) throw new HttpError(403, 'not_parent_agent', 'delegated grants must be signed by the parent agent');
      const linked =
        receipt.principal.type === 'agent'
          ? receipt.principal.registration === parent.claims.sub && receipt.iss === parent.claims.registry
          : receipt.principal.registry === parent.claims.registry && regBinding(parent.claims.sub, parent.version ?? 0, receipt.principal.ppid) === receipt.principal.reg_binding;
      if (!linked) throw new HttpError(403, 'chain_mismatch', 'the registration chain does not run through the parent grant\'s agent');
      const att = checkAttenuation(g, { ...parent.claims, prohibitions: parent.effective_prohibitions });
      if (!att.ok) throw new HttpError(403, 'exceeds_parent_authority', att.errors.join('; '), att.errors);
      principalRef = parent.principal_ref;
      effectiveProhibitions = att.effectiveProhibitions;
      depth = parent.depth + 1;
    }
    // A receipt from a newer chain version means the agent changed hands:
    // grants made for it under the earlier relationship end here.
    const superseded = [...this.grants.values()]
      .filter((x) => x.kind === 'agent' && x.claims.sub === g.sub && x.status === 'active' && (x.version ?? 0) < version)
      .map((x) => x.id);
    if (superseded.length) this.commit('grant.superseded', { ids: superseded, reason: 'custody_transferred' });
    const data = {
      id: g.jti, kind: 'agent', jws: grant, claims: g, grantor_key: signer, principal_ref: principalRef,
      effective_prohibitions: effectiveProhibitions, parent_grant: g.parent_grant ?? null, depth, version,
    };
    return { grant_id: g.jti, receipt: this.commit('grant.deposited', data), superseded };
  }

  revokeGrant(grantId, { thumbprint: signer, payload }) {
    this.requireRole('authorization');
    const g = this.grants.get(grantId);
    if (!g) throw new HttpError(404, 'unknown_grant', grantId);
    if (signer !== g.grantor_key) throw new HttpError(403, 'not_grantor', 'only the grantor may revoke a grant');
    if (g.status === 'revoked') return { grant_id: grantId, status: 'revoked', already: true };
    return { grant_id: grantId, status: 'revoked', receipt: this.commit('grant.revoked', { id: grantId, reason: payload.reason ?? 'grantor_request' }) };
  }

  grantStatus(g) {
    if (!g) return { status: 'unknown', reason: 'no_such_grant' };
    if (g.status === 'revoked' || g.status === 'superseded') return { status: g.status, reason: g.revocation_reason, at: g.revoked_at };
    if (g.claims.exp && g.claims.exp < nowSeconds()) return { status: 'expired', reason: 'grant_expired' };
    if (g.claims.nbf && g.claims.nbf > nowSeconds()) return { status: 'not_yet_valid', reason: 'grant_not_yet_valid' };
    if (g.parent_grant) {
      const up = this.grantStatus(this.grants.get(g.parent_grant));
      if (up.status !== 'active') return { status: up.status, reason: `parent_grant:${up.reason}` };
    }
    return { status: 'active' };
  }

  get statusListUri() {
    return `${this.id}/status-lists/1`;
  }

  /** Token Status List over every authorization credential and approval this keeper issued. */
  statusList() {
    const values = new Map();
    for (const [idx, e] of this.statusIndex) {
      const g = e.kind === 'authorization' ? this.grants.get(this.attestations.get(e.ref).grant_id) : this.grants.get(this.approvals.get(e.ref).designation_id);
      const s = this.grantStatus(g).status;
      values.set(idx, s === 'active' ? STATUS.VALID : s === 'not_yet_valid' ? STATUS.SUSPENDED : STATUS.INVALID);
    }
    return statusListToken({ issuer: this.id, key: this.keys.signing, uri: this.statusListUri, values, ttl: this.trust.policies.statusListTtlSeconds ?? 10 });
  }

  /**
   * RFC 8693 Token Exchange. subject_token: the grant (JWS); actor_token: the
   * agent's accountability SD-JWT VC for the audience; client authentication by
   * an RFC 7523 JWT assertion signed with the agent's long-term key.
   */
  tokenExchange(params) {
    this.requireRole('authorization');
    if (params.grant_type !== TOKEN_EXCHANGE.grantType) throw new OAuthError('unsupported_grant_type', 'only token exchange is supported');
    if (params.subject_token_type !== TOKEN_EXCHANGE.subjectTokenType || params.actor_token_type !== TOKEN_EXCHANGE.actorTokenType) {
      throw new OAuthError('invalid_request', 'unexpected subject_token_type or actor_token_type');
    }
    if (params.requested_token_type && params.requested_token_type !== TOKEN_EXCHANGE.requestedTokenType) throw new OAuthError('invalid_request', 'unsupported requested_token_type');
    const audience = params.audience;
    if (!audience) throw new OAuthError('invalid_target', 'audience is required');

    // The subject token is the grant itself; it must be one this keeper holds.
    let grantJti;
    try {
      grantJti = decodeJws(params.subject_token).payload.jti;
    } catch {
      throw new OAuthError('invalid_grant', 'subject_token is not a grant');
    }
    const g = this.grants.get(grantJti);
    if (!g || g.kind !== 'agent' || g.jws !== params.subject_token) throw new OAuthError('invalid_grant', 'no such grant is held here');

    // Client authentication (RFC 7523): signed by the grantee agent's long-term key.
    const clientId = `urn:aaf:registration:${g.claims.sub}`;
    if (params.client_assertion_type !== TOKEN_EXCHANGE.clientAssertionType || !params.client_assertion) throw new OAuthError('invalid_client', 'a JWT client assertion is required', 401);
    let assertion;
    try {
      assertion = verifySelfSignedJws(params.client_assertion);
    } catch {
      throw new OAuthError('invalid_client', 'client assertion signature invalid', 401);
    }
    const a = assertion.payload;
    const now = nowSeconds();
    if (assertion.thumbprint !== g.claims.agent_key) throw new OAuthError('invalid_client', 'client assertion not signed by the grantee agent', 401);
    if (a.iss !== clientId || a.sub !== clientId || a.aud !== `${this.id}/token` || !(a.exp > now) || this.assertionIds.has(a.jti)) {
      throw new OAuthError('invalid_client', 'client assertion claims invalid or replayed', 401);
    }
    this.assertionIds.set(a.jti, a.exp);

    const status = this.grantStatus(g);
    if (status.status !== 'active') throw new OAuthError('invalid_grant', `grant is ${status.status} (${status.reason})`);
    let att;
    try {
      att = this.verifyRegistryToken(params.actor_token, REGISTRY_TYP.attestation);
    } catch (err) {
      throw new OAuthError('invalid_grant', `actor_token: ${err.message}`);
    }
    if (att.vct !== vct(this.trust.trustAnchor.entity_id, 'accountability')) throw new OAuthError('invalid_grant', 'actor_token is not an accountability credential');
    if (att.iss !== g.claims.registry) throw new OAuthError('invalid_grant', 'actor_token issued by a different registry than the grant names');
    if (att.aud !== audience) throw new OAuthError('invalid_target', 'actor_token is for a different audience');
    if (att.exp < now) throw new OAuthError('invalid_grant', 'actor_token expired');
    if (att.reg_binding !== regBinding(g.claims.sub, g.version ?? 0, att.sub)) {
      throw new OAuthError('invalid_grant', "the actor's PPID does not belong to the grant's agent under the principal relationship the grant was made in");
    }

    const ref = randomId('azr', 12);
    const salt = b64u.encode(randomBytes(16));
    const commitment = sha256b64u(`${salt}.${g.jws}`);
    const claims = g.claims;
    const statusIdx = allocateIndex(this.statusIndex);
    // RFC 8693 act: the outermost actor is the acting agent (its PPID here);
    // nested actors are the agents that delegated to it, under per-token
    // pseudonyms. sub is the principal, likewise pseudonymous.
    const pseudonym = () => `urn:aaf:pseudonym:${randomId('p', 12).slice(2)}`;
    let act = null;
    for (let level = 1; level < g.depth; level++) act = act ? { sub: pseudonym(), act } : { sub: pseudonym() };
    const body = {
      vct: vct(this.trust.trustAnchor.entity_id, 'authorization'),
      iss: this.id,
      sub: pseudonym(),
      act: act ? { sub: att.sub, act } : { sub: att.sub },
      aud: audience,
      iat: now,
      exp: Math.min(now + this.trust.policies.attestationTtlSeconds, claims.exp ?? Infinity, att.exp),
      jti: randomId('az', 12),
      cnf: att.cnf,
      // Grants of authority are selectively disclosable: hiding one can only
      // understate what the agent may do. Limitations are never hidden.
      authorization_details: (claims.authorization_details ?? []).map((d) => sd(d)),
      prohibitions: g.effective_prohibitions,
      delegation: claims.delegation ?? { allowed: false, max_depth: 0 },
      // Calendar dates only: an exact timestamp repeated across relying
      // parties would link them. The keeper enforces the precise window.
      granted_on: new Date((claims.nbf ?? claims.iat) * 1000).toISOString().slice(0, 10),
      valid_until: claims.exp ? new Date(claims.exp * 1000).toISOString().slice(0, 10) : null,
      purpose: claims.purpose ? sd(claims.purpose) : undefined,
      context: claims.context ? sd(claims.context) : undefined,
      grant_commitment: commitment,
      status: { status_list: { idx: statusIdx, uri: this.statusListUri } },
    };
    const token = issueSdJwt(body, this.keys.signing, { typ: TYP.authorization });
    this.commit('authorization.attested', { ref, grant_id: g.id, ppid: att.sub, audience, salt, commitment, jti: body.jti, status_idx: statusIdx });
    return { access_token: token, issued_token_type: TOKEN_EXCHANGE.requestedTokenType, token_type: 'N_A', expires_in: body.exp - now };
  }

  // -------------------------------------------------------------------------
  // Passkeys (WebAuthn) for designated humans. This keeper is the WebAuthn
  // relying party: rpId = its host, origin = its entity identifier.
  // -------------------------------------------------------------------------

  get webauthnRp() {
    return { rpId: hostOf(this.id), origin: this.id };
  }

  ceremony(purpose, details, ttlSeconds = 300) {
    const { challenge } = bindingChallenge(purpose, details);
    const id = randomId('wa', 12);
    this.pending.set(id, { purpose, challenge, details, expires: Date.now() + ttlSeconds * 1000 });
    return { id, challenge };
  }

  takeCeremony(id, purpose) {
    const c = this.pending.get(id);
    this.pending.delete(id); // single use
    if (!c || c.purpose !== purpose || c.expires < Date.now()) throw new HttpError(400, 'unknown_ceremony', 'no such pending passkey request (or it expired)');
    return c;
  }

  passkeyRegistrationOptions({ display_name: displayName }) {
    this.requireRole('authorization');
    const { id, challenge } = this.ceremony('register', { display_name: displayName });
    return { request_id: id, publicKey: creationOptions({ rpId: this.webauthnRp.rpId, rpName: this.name, user: { id: randomId('u', 12), name: displayName }, challenge }) };
  }

  registerPasskey({ request_id: requestId, credential }) {
    const c = this.takeCeremony(requestId, 'register');
    let reg;
    try {
      reg = verifyRegistration({ response: credential, expectedChallenge: c.challenge, expectedOrigin: this.webauthnRp.origin, rpId: this.webauthnRp.rpId });
    } catch (err) {
      throw new HttpError(400, err.code ?? 'invalid_registration', err.message);
    }
    this.commit('passkey.registered', { credential_id: reg.credentialId, public_jwk: reg.publicJwk, alg: reg.alg, sign_count: reg.signCount, display_name: c.details.display_name });
    return { credential_id: reg.credentialId };
  }

  /**
   * Step 1 of an approval: check the request makes sense, then issue a passkey
   * challenge that commits to exactly what is being approved.
   */
  approvalOptions({ designation_id: designationId, ppid, action, subject_digest: subjectDigest, note }) {
    this.requireRole('authorization');
    const d = this.grants.get(designationId);
    if (!d || d.kind !== 'role') throw new HttpError(404, 'unknown_designation', 'no such role designation');
    const ds = this.grantStatus(d);
    if (ds.status !== 'active') throw new HttpError(403, 'designation_inactive', `designation is ${ds.status} (${ds.reason})`);
    const agentAttestation = [...this.attestations.values()].reverse().find((a) => a.ppid === ppid);
    if (!agentAttestation) throw new HttpError(404, 'unknown_agent', 'no authorization issued here for that PPID');
    const agentGrant = this.grants.get(agentAttestation.grant_id);
    if (agentGrant.principal_ref !== d.principal_ref) throw new HttpError(403, 'different_principal', 'designee and agent answer to different principals');
    const details = { designation_id: d.id, role: d.claims.grantee.role, ppid, action, subject_digest: subjectDigest, note: note ?? null };
    const { id, challenge } = this.ceremony('approve', details);
    return { request_id: id, details, publicKey: requestOptions({ rpId: this.webauthnRp.rpId, challenge, credentials: [d.claims.grantee.passkey] }) };
  }

  /** Step 2: the designee's passkey assertion over that challenge; the keeper countersigns an approval credential. */
  approve({ request_id: requestId, credential }) {
    this.requireRole('authorization');
    const c = this.takeCeremony(requestId, 'approve');
    const { designation_id: designationId, ppid, action, subject_digest: subjectDigest, note } = c.details;
    const d = this.grants.get(designationId);
    const ds = this.grantStatus(d);
    if (ds.status !== 'active') throw new HttpError(403, 'designation_inactive', `designation is ${ds.status} (${ds.reason})`);
    const passkeyId = d.claims.grantee.passkey;
    if (credential?.id !== passkeyId) throw new HttpError(403, 'not_designee', "approval not made with the designee's passkey");
    const stored = this.passkeys.get(passkeyId);
    let result;
    try {
      result = verifyAssertion({
        response: credential, expectedChallenge: c.challenge, expectedOrigin: this.webauthnRp.origin, rpId: this.webauthnRp.rpId,
        credential: { publicJwk: stored.public_jwk, alg: stored.alg, signCount: stored.sign_count },
      });
    } catch (err) {
      throw new HttpError(403, err instanceof WebAuthnError ? err.code : 'invalid_assertion', err.message);
    }
    const now = nowSeconds();
    const ref = randomId('apr', 12);
    const statusIdx = allocateIndex(this.statusIndex);
    const approval = issueSdJwt(
      {
        vct: vct(this.trust.trustAnchor.entity_id, 'approval'),
        iss: this.id, sub: ppid, iat: now, exp: now + 7 * 86400, jti: ref,
        role: d.claims.grantee.role, action, subject_digest: subjectDigest,
        approver_ref: sha256b64u(`${d.id}|${ref}`),
        // How the human approved: a WebAuthn assertion with user verification, made just now.
        approval_method: { type: 'webauthn', user_verified: result.userVerified },
        status: { status_list: { idx: statusIdx, uri: this.statusListUri } },
      },
      this.keys.signing,
      { typ: TYP.approval },
    );
    const receipt = this.commit('approval.attested', {
      ref, designation_id: d.id, ppid, action, subject_digest: subjectDigest, note, status_idx: statusIdx,
      passkey: passkeyId, sign_count: result.signCount, assertion: credential,
    });
    return { approval, ref, receipt };
  }

  /** Status of an authorization attestation or approval reference. */
  recordStatus(ref) {
    let s;
    if (this.attestations.has(ref)) s = this.grantStatus(this.grants.get(this.attestations.get(ref).grant_id));
    else if (this.approvals.has(ref)) s = this.grantStatus(this.grants.get(this.approvals.get(ref).designation_id));
    else throw new HttpError(404, 'unknown_ref', 'no record with that reference');
    const token = signJws(
      { iss: this.id, ref, status: s.status, reason: s.reason ?? null, checked_at: new Date().toISOString(), iat: nowSeconds() },
      this.keys.signing,
      { typ: TYP.recordStatus },
    );
    return { ref, status: s.status, reason: s.reason ?? null, status_token: token };
  }

  // -------------------------------------------------------------------------
  // Provenance records
  // -------------------------------------------------------------------------

  depositProvenance({ record }) {
    this.requireRole('provenance');
    let verified;
    try {
      verified = verifySelfSignedJws(record, { typ: TYP.provenance });
    } catch (err) {
      throw new HttpError(400, 'invalid_provenance', err.message);
    }
    const id = `prov_${sha256b64u(record).slice(0, 22)}`;
    if (this.provenance.has(id)) return { provenance_id: id, receipt: this.log.receipt(this.provenance.get(id).index), already: true };
    const receipt = this.commit('provenance.deposited', { id, jws: record, provider_key: verified.thumbprint, provider: verified.payload.provider });
    return { provenance_id: id, receipt };
  }

  getProvenance(id) {
    this.requireRole('provenance');
    const p = this.provenance.get(id);
    if (!p) throw new HttpError(404, 'unknown_provenance', id);
    return { provenance_id: id, record: p.jws, receipt: this.log.receipt(p.index) };
  }

  // -------------------------------------------------------------------------
  // Activity logs
  // -------------------------------------------------------------------------

  appendActivity({ entry }) {
    this.requireRole('activity');
    let verified;
    try {
      verified = verifySelfSignedJws(entry, { typ: TYP.activity });
    } catch (err) {
      throw new HttpError(400, 'invalid_activity', err.message);
    }
    const p = verified.payload;
    if (!p.subject || !p.writer_role || !p.event) throw new HttpError(400, 'invalid_activity', 'subject, writer_role and event are required');
    if (!['agent', 'relying_party'].includes(p.writer_role)) throw new HttpError(400, 'invalid_activity', 'writer_role must be agent or relying_party');
    const receipt = this.commit('activity.appended', {
      subject: p.subject, txn: p.txn ?? null, writer_role: p.writer_role, writer: p.writer ?? null,
      writer_key: verified.thumbprint, event: p.event, jws: entry,
    });
    return { receipt };
  }

  /**
   * Who may read an activity log: a party that wrote to it (its own
   * transaction history), or anyone holding a legal order that covers it.
   */
  queryActivity({ thumbprint: requester, payload }) {
    this.requireRole('activity');
    const subjects = payload.subjects ?? [payload.subject];
    let allowedByOrder = new Set();
    let orderCase = null;
    if (payload.order) {
      const { payload: unverified, header } = decodeJws(payload.order);
      const authority = this.trust.authority(unverified.iss, 'resolution-authority');
      if (!authority) throw new HttpError(403, 'untrusted_authority', 'order not issued by a recognized authority');
      const order = verifyJws(payload.order, this.trust.signingKey(authority, header.kid), { typ: REGISTRY_TYP.order }).payload;
      orderCase = order.case;
      allowedByOrder = new Set(order.ppids);
      if (payload.resolution) {
        const res = this.verifyRegistryToken(payload.resolution, REGISTRY_TYP.resolution);
        if (res.case === order.case) for (const p of res.related_ppids ?? []) allowedByOrder.add(p);
      }
    }
    const results = [];
    for (const subject of subjects) {
      const indices = this.activity.get(subject) ?? [];
      const wroteHere = indices.some((i) => this.log.get(i).data.writer_key === requester);
      if (!wroteHere && !allowedByOrder.has(subject)) throw new HttpError(403, 'not_authorized', `no access to the activity log for ${subject}`);
      for (const i of indices) results.push({ index: i, entry: this.log.get(i), receipt: this.log.receipt(i) });
    }
    return { case: orderCase, entries: results };
  }

  // -------------------------------------------------------------------------
  // Development only: behave like a compromised keeper
  // -------------------------------------------------------------------------

  tamper({ index, event, details }) {
    if (!this.allowTamperSimulation) throw new HttpError(403, 'disabled', 'tamper simulation is disabled for this keeper');
    const original = this.log.get(index);
    if (!original) throw new HttpError(404, 'no_entry', 'no such log entry');
    const forged = structuredClone(original);
    if (forged.data?.jws) {
      // Rewrite the signed payload but keep the old signature, as a keeper
      // without the writer's key would have to.
      const [h, p, s] = forged.data.jws.split('.');
      const payload = JSON.parse(Buffer.from(p, 'base64url').toString('utf8'));
      if (event) payload.event = event;
      payload.details = details ? { ...payload.details, ...details } : { note: 'redacted by record keeper' };
      forged.data.jws = `${h}.${b64u.encodeJson(payload)}.${s}`;
      forged.data.event = payload.event;
    }
    this.log.rewriteEntry(index, forged);
    return { index, rewritten: true };
  }

  stats() {
    return {
      roles: this.roles,
      grants: this.grants.size,
      active_grants: [...this.grants.values()].filter((g) => this.grantStatus(g).status === 'active').length,
      authorization_attestations: this.attestations.size,
      approvals: this.approvals.size,
      provenance_records: this.provenance.size,
      activity_subjects: this.activity.size,
      log_size: this.log.size,
    };
  }
}
