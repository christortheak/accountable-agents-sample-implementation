// Directory: verifies principals (via trusted
// identity verifiers), registers agents into chains that end at a verified
// principal, issues IDs (reusable PPIDs and unlinkable, single-use IDs) in
// accountability credentials, tracks status, points to records services,
// accredits the records services that keep records for it, and recovers the principal behind an ID only
// under consent or legal process (identity escrow).
//
// State is event-sourced from the directory's own Merkle log, so every change
// the directory makes is covered by its signed tree heads.
import path from 'node:path';
import {
  base32, hmac, randomId, randomBytes, nowSeconds, signJws, verifyJws, decodeJws, sealJwe, openJwe,
  thumbprint, sha256b64u, digestOf, publicOf,
} from '../lib/crypto.js';
import { issueSdJwt, sd, sdPad, verifySdJwt } from '../lib/sd-jwt.js';
import { MerkleLog } from '../lib/log.js';
import { attributeName, attributeSource } from '../lib/ida.js';
import { SD_JWT_VC_TYP, vct } from '../lib/credentials.js';
import { STATUS, allocateIndex, statusListToken } from '../lib/status-list.js';
import fs from 'node:fs';
import { hostOf, issueTrustMark, trustMarkType, jwksOf } from '../lib/openid-federation.js';
import { HttpError, postJson, postSigned, ServiceError } from '../lib/http.js';

/** A signed call from this directory to a federation peer. */
const peerCall = (directory, url, params) => postSigned(url, params, directory.keys.signing, { keyid: `directory:${directory.id}` });

export const TYP = {
  attestation: SD_JWT_VC_TYP, // SD-JWT VC; vct distinguishes credential kinds
  registration: 'aaf-registration+jwt',
  status: 'aaf-status+jwt',
  attribution: 'aaf-attribution+jwt',
  order: 'aaf-legal-order+jwt',
  forward: 'aaf-attribution-forward+jwt',
  agentProof: 'aaf-agent-proof+jwt',
};

/** What an agent's proof of possession is for (AG-2, AG-5). */
export const AGENT_PROOF_PURPOSE = { registration: 'aaf-agent-registration', rotation: 'aaf-agent-key-rotation', transfer: 'aaf-agent-transfer' };

/** Scope a legal order must carry before a directory revokes under it. */
export const ORDER_SCOPE_REVOKE = 'revoke_registration';

/** Decoy padding for the accountability credential, so digest counts do not distinguish principals. */
const PAD = { claims: 12, attributes: 4, records: 4 };

/**
 * The sample rule for "one verified identity, one principal record" (PV-3):
 * a legal entity is keyed by its LEI or registration number, a person by name,
 * jurisdiction and date of birth where known. A real directory would key on
 * the evidence its identity proofing produced.
 */
export function identityKey(type, identity = {}) {
  const norm = (v) => String(v ?? '').normalize('NFKC').trim().replace(/\s+/g, ' ').toLowerCase();
  let basis;
  if (type === 'legal_person' && identity.lei) basis = { lei: norm(identity.lei) };
  else if (type === 'legal_person' && identity.registration_number) basis = { jurisdiction: norm(identity.jurisdiction), registration_number: norm(identity.registration_number) };
  else basis = { name: norm(identity.legal_name), jurisdiction: norm(identity.jurisdiction), date_of_birth: norm(identity.date_of_birth) };
  return digestOf({ type, ...basis });
}

export const REVOCATION_REASONS = [
  'principal_request', 'compromised', 'authority_ended', 'fraud', 'legal_order', 'superseded', 'parent_transferred',
];

const DISCLOSABLE_IDENTITY_CLAIMS = ['legal_name', 'jurisdiction', 'registration_number', 'lei'];

/**
 * Binding between a registration (at a given chain version) and one of its
 * IDs; lets records services check that an ID belongs to a grant's agent under
 * the same principal relationship. A transfer bumps the version, so grants made
 * under the previous principal no longer bind.
 */
export const regBinding = (registrationId, version, aaf_id) => sha256b64u(`aaf-binding|${registrationId}|${version}|${aaf_id}`);

/**
 * IDs are written aaf:<directory host>:p_… (a PPID: reusable, one per agent and
 * counterparty) or aaf:<directory host>:u_… (unlinkable: used once). The host
 * names the issuing directory.
 */
export const ID_PREFIX = 'aaf';
export const directoryOfId = (aaf_id) => {
  const m = /^aaf:([^:]+):[pu]_[0-9a-z]+$/.exec(aaf_id ?? '');
  return m ? m[1] : null;
};

export class Directory {
  constructor({ id, name, jurisdiction, url, keys, trustList, dataDir = null }) {
    this.id = id;
    this.host = hostOf(id); // embedded in every ID this directory issues
    this.name = name;
    this.jurisdiction = jurisdiction;
    this.url = url;
    this.keys = keys;
    this.trust = trustList;
    this.policies = trustList.policies;
    this.principals = new Map();
    this.identityKeys = new Map(); // verified identity -> principal id (PV-3)
    this.registrations = new Map();
    this.agentKeys = new Map(); // thumbprint -> registration id
    this.aaf_ids = new Map(); // pairwise aaf_id -> { registration, audience }
    this.accreditations = new Map();
    this.incidents = new Map();
    this.notifications = new Map(); // principal id -> []
    this.remoteStatusCache = new Map();
    this.transferOffers = new Map();
    // Token Status List entries: idx -> pairwise PPID, or an unlinkable attestation's located registration.
    this.statusIndex = new Map();
    this.unlinkableFile = dataDir ? path.join(dataDir, 'unlinkable-status.json') : null;
    this.log = new MerkleLog({ logId: id, signer: keys.signing, file: dataDir ? path.join(dataDir, 'directory-log.jsonl') : null });
    for (const entry of this.log.entries) this.apply(entry);
    // Unlinkable attestations keep a status entry only until they expire; the
    // directory keeps no lasting record linking unlinkable IDs to registrations.
    if (this.unlinkableFile && fs.existsSync(this.unlinkableFile)) {
      for (const e of JSON.parse(fs.readFileSync(this.unlinkableFile, 'utf8'))) if (e.exp > nowSeconds()) this.statusIndex.set(e.idx, e);
    }
  }

  get statusListUri() {
    return `${this.id}/status-lists/1`;
  }

  rememberUnlinkable(entry) {
    const now = nowSeconds();
    for (const [idx, e] of this.statusIndex) if (e.unlinkable && e.exp < now) this.statusIndex.delete(idx);
    this.statusIndex.set(entry.idx, entry);
    if (this.unlinkableFile) {
      fs.mkdirSync(path.dirname(this.unlinkableFile), { recursive: true });
      fs.writeFileSync(this.unlinkableFile, JSON.stringify([...this.statusIndex.values()].filter((e) => e.unlinkable)));
    }
  }

  /** The directory's Token Status List: one entry per pairwise PPID and per live unlinkable attestation. */
  async statusList() {
    const values = new Map();
    const code = { active: STATUS.VALID, revoked: STATUS.INVALID, expired: STATUS.INVALID, suspended: STATUS.SUSPENDED, unknown: STATUS.SUSPENDED, transferred: STATUS.TRANSFERRED };
    for (const [idx, e] of this.statusIndex) {
      const located = e.unlinkable
        ? { registration: this.registrations.get(e.registration), version: e.version }
        : (() => {
            const rec = this.aaf_ids.get(e.aaf_id);
            return { registration: this.registrations.get(rec.registration), version: rec.version ?? 0 };
          })();
      values.set(idx, code[(await this.idStatus(located)).status] ?? STATUS.INVALID);
    }
    return statusListToken({ issuer: this.id, key: this.keys.signing, uri: this.statusListUri, values, ttl: this.policies.statusListTtlSeconds ?? 10 });
  }

  // -------------------------------------------------------------------------
  // Event sourcing
  // -------------------------------------------------------------------------

  commit(type, data) {
    const entry = { type, at: new Date().toISOString(), data };
    const { index } = this.log.append(entry);
    this.apply(entry);
    return index;
  }

  apply({ type, at, data }) {
    switch (type) {
      case 'principal.enrolled':
        this.principals.set(data.id, {
          id: data.id, type: data.type, identity: data.identity, contact: data.contact,
          keys: [data.jwk], verification: null, attributes: [], disclosure: { identity: { audiences: [], claims: [] }, attributes: [] },
          enrolled_at: at,
        });
        break;
      case 'principal.verified': {
        const p = this.principals.get(data.id);
        p.verification = { ...data, status: 'verified' };
        if (data.identity_key) {
          p.identity_key = data.identity_key;
          this.identityKeys.set(data.identity_key, p.id);
        }
        break;
      }
      case 'principal.closed': {
        const p = this.principals.get(data.id);
        p.closed = { reason: data.reason, at };
        if (p.identity_key && this.identityKeys.get(p.identity_key) === p.id) this.identityKeys.delete(p.identity_key);
        break;
      }
      case 'principal.attributes_set': {
        const p = this.principals.get(data.id);
        const byName = new Map(p.attributes.map((a) => [a.name, a]));
        for (const a of data.attributes) byName.set(a.name, a);
        p.attributes = [...byName.values()];
        break;
      }
      case 'principal.disclosure_set':
        this.principals.get(data.id).disclosure = data.policy;
        break;
      case 'registration.created':
        this.registrations.set(data.id, {
          ...data, epoch: 0, status: 'active', created_at: at,
          custody: data.parent.type === 'principal' ? [{ epoch: 0, principal: data.parent.id, from: at, to: null }] : [],
        });
        this.agentKeys.set(thumbprint(data.agent_jwk), data.id);
        break;
      case 'registration.transferred': {
        const r = this.registrations.get(data.id);
        const to = this.principals.get(data.to);
        r.custody.at(-1).to = at;
        r.custody.push({ epoch: data.epoch, principal: data.to, from: at, to: null, offer: data.offer });
        r.epoch = data.epoch;
        r.parent = { type: 'principal', id: to.id, key_thumbprints: to.keys.map(thumbprint) };
        r.principal = to.id;
        this.agentKeys.delete(thumbprint(r.agent_jwk));
        r.agent_jwk = data.agent_jwk;
        this.agentKeys.set(thumbprint(data.agent_jwk), r.id);
        for (const d of this.descendants(r)) if (d.principal) d.principal = to.id;
        this.transferOffers.get(data.offer).status = 'accepted';
        break;
      }
      case 'registration.key_rotated': {
        const r = this.registrations.get(data.id);
        this.agentKeys.delete(thumbprint(r.agent_jwk));
        r.agent_jwk = data.agent_jwk;
        this.agentKeys.set(thumbprint(data.agent_jwk), r.id);
        break;
      }
      case 'transfer.offered':
        this.transferOffers.set(data.id, { ...data, status: 'pending', offered_at: at });
        break;
      case 'transfer.cancelled':
        this.transferOffers.get(data.id).status = 'cancelled';
        break;
      case 'registration.revoked': {
        const r = this.registrations.get(data.id);
        r.status = 'revoked';
        r.revocation = { reason: data.reason, by: data.by, at };
        break;
      }
      case 'aaf_id.issued':
        this.aaf_ids.set(data.aaf_id, { registration: data.registration, audience: data.audience, version: data.version, root: data.root, status_idx: data.status_idx, issued_at: at });
        if (data.status_idx != null) this.statusIndex.set(data.status_idx, { idx: data.status_idx, aaf_id: data.aaf_id });
        break;
      case 'accreditation.granted':
        this.accreditations.set(data.rs, { ...data, status: 'active' });
        break;
      case 'accreditation.withdrawn':
        if (this.accreditations.has(data.rs)) this.accreditations.get(data.rs).status = 'withdrawn';
        break;
      case 'incident.reported':
        this.incidents.set(data.id, { ...data, at });
        break;
      case 'notification.sent': {
        const list = this.notifications.get(data.principal) ?? [];
        list.push({ ...data.notification, at });
        this.notifications.set(data.principal, list);
        break;
      }
      case 'attribution.performed':
        break;
      default:
        throw new Error(`unknown directory event ${type}`);
    }
  }

  // -------------------------------------------------------------------------
  // Metadata
  // -------------------------------------------------------------------------

  /** aaf_directory metadata for this directory's OpenID Federation Entity Configuration. */
  metadata() {
    return {
      organization_name: this.name,
      jurisdiction: this.jurisdiction,
      endpoint_base: this.url,
      jwks: jwksOf(this.keys.signing, this.keys.encryption),
      id_modes: ['pairwise', 'unlinkable'],
      practices: this.practices(),
      policies: {
        revocation_interval_seconds: this.policies.revocationIntervalSeconds,
        attestation_ttl_seconds: this.policies.attestationTtlSeconds,
        max_chain_depth: this.policies.maxChainDepth,
        record_retention_years: this.policies.recordRetentionYears,
      },
      endpoints: {
        principals: '/v1/principals',
        registrations: '/v1/registrations',
        attestations: '/v1/attestations',
        status: '/v1/status',
        attributions: '/v1/attributions',
        revocations: '/v1/revocations',
        practices: '/v1/practices',
        incidents: '/v1/incidents',
        trust_marks: '/federation/trust-mark',
        transparency: '/v1/transparency/sth',
      },
    };
  }

  /**
   * Published practices (paper Appendix A, DR-1): what a counterparty or
   * principal needs to know to decide whether to rely on this directory. Every
   * statement here describes what this code does.
   */
  practices() {
    const pol = this.policies;
    const ids = (list) => (list ?? []).map((e) => e.id);
    return {
      identity_proofing: {
        verified_identities: ['natural_person', 'legal_person'],
        method: 'OpenID Connect for Identity Assurance verified_claims, recorded by a recognized identity verifier; each ID can show the trust framework and assurance level',
        identity_verifiers: ids(this.trust.doc?.verifiers),
        sybil_resistance: 'one principal record per verified identity: a legal entity by LEI or registration number, a person by name, jurisdiction and date of birth',
        reverification: 'a verification expires; while it is lapsed the principal cannot register agents and its agents are suspended',
      },
      authentication: {
        principals: 'an Ed25519 key enrolled with the principal record; every request is signed (RFC 9421)',
        agents: 'an Ed25519 key whose possession the agent proves at registration; a separate key per counterparty or per presentation is bound into each ID',
      },
      ids: {
        modes: { pairwise: 'reusable: at most one per agent and counterparty (a PPID)', unlinkable: 'used once, so presentations cannot be linked by their IDs' },
        validity_seconds: pol.attestationTtlSeconds,
        claims: 'every claim except the ID is selectively disclosable by the agent',
      },
      revocation: {
        by: ['the principal', 'a delegating agent, for its sub-agents', 'this directory, for fraud or under its operating rules', 'a designated authority, by legal order'],
        cascades_to_sub_agents: true,
        latency_seconds: { bound: pol.revocationIntervalSeconds, status_list_refresh: pol.statusListTtlSeconds ?? 10, without_status_check: pol.attestationTtlSeconds },
        status: 'a published Token Status List, fetched whole: this directory does not learn which ID a counterparty checks',
      },
      records: {
        held: ['principal records with verified identity', 'agent records and their chains', 'custody history', 'pairwise IDs issued and their counterparties', 'incident reports', 'disclosures made'],
        not_held: ['authorizations', 'bills of materials', 'activity (accredited records services hold these)', 'a lasting link from a single-use ID to its agent (the ID carries a sealed reference only this directory can open)'],
        retention_years: pol.recordRetentionYears,
        kept_after_revocation: true,
        log: 'every change is an entry in an append-only Merkle log with signed tree heads',
      },
      disclosure: {
        to_counterparties: 'identity claims only where the principal\'s disclosure policy names the claim and the counterparty',
        attribution: {
          process: 'a legal order from a designated authority that names the ID; single-use IDs also need the sealed reference the counterparty kept',
          authorities: ids(this.trust.doc?.designated_authorities),
          logged: true,
          principal_notified: 'yes, unless the order forbids it',
        },
        incidents: 'reports are relayed to the principal without telling the reporter who the principal is',
      },
      signing_keys: 'held in files on the operator\'s server; no hardware protection and no rotation (sample implementation)',
      security: 'a sample implementation for discussion and pilots; not operated to a production standard',
    };
  }

  // -------------------------------------------------------------------------
  // Signer attribution for signed requests
  //   kid "principal:<id>"     -> the principal's enrolled key
  //   kid "registration:<id>"  -> the agent's long-term key
  //   kid "verifier:<id>"      -> a trusted identity verifier (trust list)
  //   (self-presented "jkt:" keys are checked by the signature layer itself)
  // -------------------------------------------------------------------------

  resolveSigner(header) {
    const kid = header.kid ?? '';
    if (kid.startsWith('principal:')) {
      const p = this.principals.get(kid.slice('principal:'.length));
      return p ? p.keys[0] : null;
    }
    if (kid.startsWith('registration:')) {
      const r = this.registrations.get(kid.slice('registration:'.length));
      return r ? r.agent_jwk : null;
    }
    if (kid.startsWith('directory:')) {
      const peer = this.trust.directory(kid.slice('directory:'.length));
      return peer && peer.id !== this.id ? this.trust.signingKey(peer) : null;
    }
    if (kid.startsWith('verifier:')) {
      const v = this.trust.authority(kid.slice('verifier:'.length), 'verifier');
      return v ? this.trust.signingKey(v) : null;
    }
    return null;
  }

  // -------------------------------------------------------------------------
  // Principals
  // -------------------------------------------------------------------------

  enrollPrincipal({ payload, jwk }) {
    const { type, identity, contact } = payload;
    if (!['natural_person', 'legal_person'].includes(type)) throw new HttpError(400, 'invalid_type', 'type must be natural_person or legal_person');
    if (!identity?.legal_name || !identity?.jurisdiction) throw new HttpError(400, 'invalid_identity', 'identity.legal_name and identity.jurisdiction are required');
    const id = randomId('prn');
    this.commit('principal.enrolled', { id, type, identity, contact: contact ?? null, jwk: publicOf(jwk) });
    return { principal_id: id, verification: 'pending', identity_digest: digestOf(identity) };
  }

  /**
   * Recorded on the word of a trusted identity verifier: the slow, out-of-band
   * step. The verifier submits OpenID Connect for Identity Assurance
   * verified_claims, whose claims must be exactly the enrolled identity.
   */
  recordVerification(principalId, { payload, header }) {
    const verifierId = header.kid.slice('verifier:'.length);
    const p = this.mustPrincipal(principalId);
    if (payload.principal_id !== principalId) throw new HttpError(400, 'mismatch', 'principal id mismatch');
    const vc = payload.verified_claims;
    if (!vc?.verification?.trust_framework || !vc.claims) throw new HttpError(400, 'invalid_verified_claims', 'verified_claims with verification and claims required');
    if (digestOf(vc.claims) !== digestOf(p.identity)) {
      throw new HttpError(409, 'identity_mismatch', 'verified claims do not match the enrolled identity claims');
    }
    if (p.closed) throw new HttpError(409, 'principal_closed', 'this principal record has been closed');
    // One verified identity has one principal record (PV-3).
    const key = identityKey(p.type, vc.claims);
    const existing = this.identityKeys.get(key);
    if (existing && existing !== principalId) {
      throw new HttpError(409, 'duplicate_identity', `this verified identity already has a principal record here (${existing})`, { existing_principal: existing });
    }
    const data = { id: principalId, verifier: verifierId, ...vc.verification, expires_at: payload.expires_at, identity_key: key };
    this.commit('principal.verified', data);
    if (payload.attributes?.length) this.recordAttributes(principalId, verifierId, payload.attributes);
    return { principal_id: principalId, verification: 'verified', trust_framework: data.trust_framework, assurance_level: data.assurance_level };
  }

  /** Attributes arrive as verified_claims elements, each from a named source. */
  recordAttributes(principalId, verifierId, attributes) {
    this.mustPrincipal(principalId);
    const stamped = attributes.map((a) => ({
      name: attributeName(a.verified_claims), verified_claims: a.verified_claims, attested_by: verifierId, expires_at: a.expires_at ?? null,
    }));
    this.commit('principal.attributes_set', { id: principalId, attributes: stamped });
    return { principal_id: principalId, attributes: stamped.map((a) => a.name) };
  }

  setDisclosurePolicy(principalId, policy) {
    this.mustPrincipal(principalId);
    const claims = policy?.identity?.claims ?? [];
    const bad = claims.filter((c) => !DISCLOSABLE_IDENTITY_CLAIMS.includes(c));
    if (bad.length) throw new HttpError(400, 'invalid_policy', `claims not disclosable by consent: ${bad.join(', ')}`);
    const normalized = {
      identity: { audiences: policy?.identity?.audiences ?? [], claims },
      attributes: policy?.attributes ?? [],
    };
    this.commit('principal.disclosure_set', { id: principalId, policy: normalized });
    return { principal_id: principalId, policy: normalized };
  }

  mustPrincipal(id) {
    const p = this.principals.get(id);
    if (!p) throw new HttpError(404, 'unknown_principal', `no principal ${id}`);
    return p;
  }

  /**
   * Close a principal record (operator): the identity may then enroll again,
   * for example after losing its key. The record and its agents' history are
   * kept, so IDs issued under it can still be attributed; its agents stop working.
   */
  async closePrincipal(principalId, reason = 'operator') {
    const p = this.mustPrincipal(principalId);
    if (p.closed) return { principal_id: p.id, status: 'closed', already: true };
    this.commit('principal.closed', { id: p.id, reason });
    const regs = [...this.registrations.values()].filter((r) => r.principal === p.id);
    const peersNotified = await this.pushStatusChange(regs);
    return { principal_id: p.id, status: 'closed', registrations_suspended: regs.filter((r) => r.status === 'active').length, peers_notified: peersNotified };
  }

  principalVerificationValid(p) {
    if (p.closed) return false;
    if (p.verification?.status !== 'verified') return false;
    return !p.verification.expires_at || new Date(p.verification.expires_at) > new Date();
  }

  notificationsFor(principalId) {
    return this.notifications.get(principalId) ?? [];
  }

  // -------------------------------------------------------------------------
  // Registrations
  // -------------------------------------------------------------------------

  async register({ header, payload, jwk }) {
    const started = process.hrtime.bigint();
    const { agent_jwk: agentJwk, parent = {}, provider = null, records = [], label = null, expires_in: expiresIn = null, lineage = null } = payload;
    if (!agentJwk || agentJwk.kty !== 'OKP' || agentJwk.crv !== 'Ed25519') throw new HttpError(400, 'invalid_agent_key', 'agent_jwk must be an Ed25519 public JWK');
    const agentKey = thumbprint(agentJwk);
    if (this.agentKeys.has(agentKey)) throw new HttpError(409, 'agent_key_in_use', 'agent key already registered');
    // The agent itself proves it holds the key, for this registrant (AG-2).
    const registrant = parent.type === 'remote_agent' ? `jkt:${jwk ? thumbprint(jwk) : ''}` : header.kid ?? '';
    this.checkAgentProof(payload.agent_proof, agentJwk, { purpose: AGENT_PROOF_PURPOSE.registration, binding: registrant });

    let parentLink;
    let principal = null;
    let principalSummary = null;
    let depth;
    const kid = header.kid ?? '';

    if (parent.type === 'principal') {
      if (!kid.startsWith('principal:')) throw new HttpError(401, 'wrong_signer', 'principal registrations must be signed by the principal');
      const p = this.mustPrincipal(kid.slice('principal:'.length));
      if (!this.principalVerificationValid(p)) {
        throw new HttpError(403, 'principal_not_verified', 'the principal must be verified before registering agents');
      }
      parentLink = { type: 'principal', id: p.id, key_thumbprints: p.keys.map(thumbprint) };
      principal = p.id;
      depth = 1;
    } else if (parent.type === 'agent') {
      if (!kid.startsWith('registration:')) throw new HttpError(401, 'wrong_signer', 'sub-agent registrations must be signed by the delegating agent');
      const parentReg = this.registrations.get(kid.slice('registration:'.length));
      const status = await this.registrationStatus(parentReg);
      if (status.status !== 'active') throw new HttpError(403, 'parent_inactive', `parent registration is ${status.status}`);
      parentLink = { type: 'agent', registration: parentReg.id, agent_key: thumbprint(parentReg.agent_jwk) };
      principal = parentReg.principal;
      principalSummary = parentReg.principal_summary ?? null;
      depth = parentReg.depth + 1;
      // A lineage budget set on any ancestor limits how deep its sub-agents may go.
      for (const a of [parentReg, ...this.ancestors(parentReg)]) {
        if (a.lineage_max_depth != null && depth - a.depth > a.lineage_max_depth) {
          throw new HttpError(403, 'lineage_depth_exceeded', `${a.label ?? a.id} allows sub-agents at most ${a.lineage_max_depth} level(s) below it`);
        }
      }
    } else if (parent.type === 'remote_agent') {
      const remote = await this.verifyRemoteParent(parent.attestation, jwk);
      parentLink = remote.link;
      principalSummary = remote.principalSummary;
      depth = remote.depth;
    } else {
      throw new HttpError(400, 'invalid_parent', 'parent.type must be principal, agent or remote_agent');
    }
    if (depth > this.policies.maxChainDepth) throw new HttpError(403, 'chain_too_deep', `chains are limited to ${this.policies.maxChainDepth} links`);

    // Expiry: an ephemeral sub-agent lapses on its own. No agent outlives its parent.
    let expiresAt = expiresIn != null ? Date.now() + Number(expiresIn) * 1000 : null;
    if (parent.type === 'agent') {
      const parentExpiry = this.effectiveExpiry(this.registrations.get(parentLink.registration));
      if (parentExpiry != null && (expiresAt == null || expiresAt > parentExpiry)) expiresAt = parentExpiry;
    }
    const lineageMaxDepth = lineage?.max_depth ?? null;
    if (lineageMaxDepth != null && !(Number.isInteger(lineageMaxDepth) && lineageMaxDepth >= 0)) {
      throw new HttpError(400, 'invalid_lineage', 'lineage.max_depth must be a non-negative integer');
    }

    for (const rec of records) {
      const acc = this.accreditations.get(rec.rs);
      if (!acc || acc.status !== 'active' || !acc.roles.includes(rec.role)) {
        throw new HttpError(400, 'records_service_not_accredited', `${rec.rs} is not accredited by ${this.id} for ${rec.role} records`);
      }
    }

    const id = randomId('reg');
    this.commit('registration.created', {
      id, agent_jwk: publicOf(agentJwk), parent: parentLink, principal: principal, principal_summary: principalSummary,
      depth, provider, records, label,
      expires_at: expiresAt ? new Date(expiresAt).toISOString() : null, lineage_max_depth: lineageMaxDepth,
    });
    const reg = this.registrations.get(id);
    const elapsedMs = Number(process.hrtime.bigint() - started) / 1e6;
    return { registration_id: id, receipt: this.receiptFor(reg), depth, expires_at: reg.expires_at, issuance_ms: Math.round(elapsedMs * 100) / 100 };
  }

  /**
   * Proof of possession of an agent key: a JWS signed with that key, naming
   * this directory, what the proof is for, and what it is bound to (the
   * registrant, the registration or the transfer offer).
   */
  checkAgentProof(proof, agentJwk, { purpose, binding }) {
    if (!proof) throw new HttpError(400, 'agent_proof_required', 'the agent must prove it holds the key being bound to its record (agent_proof)');
    let claims;
    try {
      claims = verifyJws(proof, agentJwk, { typ: TYP.agentProof }).payload;
    } catch (err) {
      throw new HttpError(401, 'invalid_agent_proof', `agent proof not signed by the agent key: ${err.message}`);
    }
    const fresh = typeof claims.iat === 'number' && Math.abs(nowSeconds() - claims.iat) <= 120;
    if (claims.aud !== this.id || claims.purpose !== purpose || claims.binding !== binding || claims.agent_key !== thumbprint(agentJwk) || !fresh) {
      throw new HttpError(401, 'invalid_agent_proof', 'agent proof is stale or was made for a different directory, purpose or registrant');
    }
  }

  /** Current registration receipt: who the agent answers to now, at which chain version. */
  receiptFor(reg) {
    let parent = reg.parent;
    if (reg.parent.type === 'principal') {
      const p = this.principals.get(reg.parent.id);
      parent = { type: 'principal', id: p.id, key_thumbprints: p.keys.map(thumbprint) };
    } else if (reg.parent.type === 'agent') {
      const parentReg = this.registrations.get(reg.parent.registration);
      parent = { type: 'agent', registration: parentReg.id, agent_key: thumbprint(parentReg.agent_jwk) };
    }
    return signJws(
      {
        iss: this.id, sub: reg.id, iat: nowSeconds(), agent_key: thumbprint(reg.agent_jwk), parent,
        depth: reg.depth, version: this.chainVersion(reg), records: reg.records, expires_at: reg.expires_at ?? null,
      },
      this.keys.signing,
      { typ: TYP.registration },
    );
  }

  /** Changes whenever this registration or any local ancestor changes hands. */
  chainVersion(reg) {
    let v = 0;
    for (let cur = reg; cur; cur = cur.parent.type === 'agent' ? this.registrations.get(cur.parent.registration) : null) v += cur.epoch ?? 0;
    return v;
  }

  /** Earliest expiry along the local chain (ms since epoch), or null. */
  effectiveExpiry(reg) {
    let min = null;
    for (let cur = reg; cur; cur = cur.parent.type === 'agent' ? this.registrations.get(cur.parent.registration) : null) {
      if (cur.expires_at) {
        const t = Date.parse(cur.expires_at);
        if (min == null || t < min) min = t;
      }
    }
    return min;
  }

  descendants(reg) {
    return [...this.registrations.values()].filter((r) => this.ancestors(r).some((a) => a.id === reg.id));
  }

  /** Re-issue the receipt, e.g. for a sub-agent whose lineage changed hands. Signed by the agent or anyone above it. */
  refreshReceipt(registrationId, { header }) {
    const reg = this.mustRegistration(registrationId);
    const kid = header.kid ?? '';
    const allowed =
      kid === `registration:${reg.id}` ||
      (kid.startsWith('principal:') && kid.slice('principal:'.length) === reg.principal) ||
      (kid.startsWith('registration:') && this.ancestors(reg).some((a) => a.id === kid.slice('registration:'.length)));
    if (!allowed) throw new HttpError(403, 'not_authorized', 'only the agent or its chain may fetch its receipt');
    return { registration_id: reg.id, receipt: this.receiptFor(reg), version: this.chainVersion(reg) };
  }

  /** Replace an agent's long-term key (for example after a transfer, or suspected key exposure). */
  rotateKey(registrationId, { header, payload }) {
    const reg = this.mustRegistration(registrationId);
    const kid = header.kid ?? '';
    const allowed =
      (kid.startsWith('principal:') && kid.slice('principal:'.length) === reg.principal) ||
      (kid.startsWith('registration:') && this.ancestors(reg).some((a) => a.id === kid.slice('registration:'.length)));
    if (!allowed) throw new HttpError(403, 'not_authorized', 'only the principal chain above this agent may rotate its key');
    const jwk = payload.agent_jwk;
    if (!jwk || jwk.crv !== 'Ed25519') throw new HttpError(400, 'invalid_agent_key', 'agent_jwk must be an Ed25519 public JWK');
    if (this.agentKeys.has(thumbprint(jwk))) throw new HttpError(409, 'agent_key_in_use', 'agent key already registered');
    this.checkAgentProof(payload.agent_proof, jwk, { purpose: AGENT_PROOF_PURPOSE.rotation, binding: reg.id });
    this.commit('registration.key_rotated', { id: reg.id, agent_jwk: publicOf(jwk), by: kid });
    return { registration_id: reg.id, receipt: this.receiptFor(reg) };
  }

  // -------------------------------------------------------------------------
  // Transfer between principals: both sign; the relationship (and so every
  // ID) is new; the old principal stays answerable for what came before.
  // -------------------------------------------------------------------------

  async activeDescendants(reg) {
    const out = [];
    for (const d of this.descendants(reg)) if ((await this.registrationStatus(d)).status === 'active') out.push(d);
    return out;
  }

  async offerTransfer(registrationId, { header, payload }) {
    const reg = this.mustRegistration(registrationId);
    const from = (header.kid ?? '').startsWith('principal:') ? header.kid.slice('principal:'.length) : null;
    if (reg.parent.type !== 'principal' || reg.parent.id !== from) {
      throw new HttpError(403, 'not_authorized', 'only the principal an agent is directly registered under may offer it');
    }
    if (reg.status !== 'active') throw new HttpError(403, 'registration_inactive', 'only active agents can be transferred');
    const to = this.mustPrincipal(payload.to_principal);
    if (to.id === from) throw new HttpError(400, 'same_principal', 'cannot transfer an agent to its current principal');
    const subtree = payload.subtree ?? 'move';
    if (!['move', 'end'].includes(subtree)) throw new HttpError(400, 'invalid_subtree', "subtree must be 'move' or 'end'");
    const id = randomId('xfr', 12);
    const expiresAt = new Date(Date.now() + (payload.expires_in ?? 7 * 86400) * 1000).toISOString();
    const live = await this.activeDescendants(reg);
    this.commit('transfer.offered', { id, registration: reg.id, from, to: to.id, subtree, epoch: reg.epoch, expires_at: expiresAt });
    this.commit('notification.sent', {
      principal: to.id,
      notification: { kind: 'transfer_offer', offer_id: id, agent_label: reg.label, subtree, descendants: live.length, expires_at: expiresAt },
    });
    return { offer_id: id, registration_id: reg.id, to_principal: to.id, subtree, expires_at: expiresAt };
  }

  cancelTransfer(offerId, { header }) {
    const offer = this.transferOffers.get(offerId);
    if (!offer) throw new HttpError(404, 'unknown_offer', offerId);
    if (header.kid !== `principal:${offer.from}`) throw new HttpError(403, 'not_authorized', 'only the offering principal may cancel');
    if (offer.status !== 'pending') throw new HttpError(409, 'offer_closed', `offer is ${offer.status}`);
    this.commit('transfer.cancelled', { id: offerId });
    return { offer_id: offerId, status: 'cancelled' };
  }

  async acceptTransfer(offerId, { header, payload }) {
    const offer = this.transferOffers.get(offerId);
    if (!offer) throw new HttpError(404, 'unknown_offer', offerId);
    if (header.kid !== `principal:${offer.to}`) throw new HttpError(403, 'not_authorized', 'only the named recipient may accept');
    if (offer.status !== 'pending') throw new HttpError(409, 'offer_closed', `offer is ${offer.status}`);
    if (Date.parse(offer.expires_at) < Date.now()) throw new HttpError(410, 'offer_expired', 'transfer offer expired');
    const to = this.mustPrincipal(offer.to);
    if (!this.principalVerificationValid(to)) throw new HttpError(403, 'principal_not_verified', 'the receiving principal must be verified');
    const reg = this.mustRegistration(offer.registration);
    if (reg.parent.type !== 'principal' || reg.parent.id !== offer.from || reg.epoch !== offer.epoch) {
      throw new HttpError(409, 'offer_stale', 'the agent changed hands since the offer was made');
    }
    const status = await this.registrationStatus(reg);
    if (status.status !== 'active') throw new HttpError(403, 'registration_inactive', `agent is ${status.status}`);
    const jwk = payload.agent_jwk;
    if (!jwk || jwk.crv !== 'Ed25519') throw new HttpError(400, 'invalid_agent_key', 'the new owner must supply a fresh Ed25519 agent key');
    if (this.agentKeys.has(thumbprint(jwk))) throw new HttpError(409, 'agent_key_in_use', 'the new agent key must be fresh');
    this.checkAgentProof(payload.agent_proof, jwk, { purpose: AGENT_PROOF_PURPOSE.transfer, binding: offerId });

    const descendants = this.descendants(reg);
    const live = await this.activeDescendants(reg);
    this.commit('registration.transferred', { id: reg.id, offer: offerId, from: offer.from, to: to.id, epoch: reg.epoch + 1, agent_jwk: publicOf(jwk), subtree: offer.subtree });
    if (offer.subtree === 'end') {
      for (const d of descendants) if (d.status !== 'revoked') this.commit('registration.revoked', { id: d.id, reason: 'parent_transferred', by: `transfer:${offerId}` });
    }
    // Old IDs (this agent's and every descendant's) are now "transferred"; tell peers holding sub-agents.
    const peersNotified = await this.pushStatusChange([reg, ...descendants]);
    for (const principal of [offer.from, to.id]) {
      this.commit('notification.sent', {
        principal,
        notification: { kind: principal === to.id ? 'transfer_received' : 'transfer_completed', offer_id: offerId, registration_id: reg.id, agent_label: reg.label, subtree: offer.subtree, descendants: live.length },
      });
    }
    return {
      registration_id: reg.id, receipt: this.receiptFor(reg), version: this.chainVersion(reg), subtree: offer.subtree,
      descendants_moved: offer.subtree === 'move' ? live.length : 0,
      descendants_ended: offer.subtree === 'end' ? live.length : 0,
      peers_notified: peersNotified,
    };
  }

  /** A delegating agent registered at a peer directory proves itself with an ID attestation addressed to us. */
  async verifyRemoteParent(attestation, signerJwk) {
    if (!signerJwk) throw new HttpError(401, 'missing_key', 'remote parent must sign with its attested key');
    const { header, payload: unverified } = decodeJws(String(attestation).split('~')[0]);
    const iss = unverified.iss;
    const peer = this.trust.directory(iss);
    if (!peer || iss === this.id) throw new HttpError(403, 'untrusted_directory', `directory ${iss} is not a federation peer`);
    let att;
    try {
      att = verifySdJwt(attestation, this.trust.signingKey(peer, header.kid), { typ: TYP.attestation }).payload;
      if (att.vct !== vct(this.trust.trustAnchor.entity_id, 'accountability')) throw new Error('not an accountability credential');
    } catch (err) {
      throw new HttpError(403, 'invalid_attestation', err.message);
    }
    if (att.aud !== this.id) throw new HttpError(403, 'wrong_audience', 'attestation is not addressed to this directory');
    if (att.exp < nowSeconds()) throw new HttpError(403, 'expired_attestation', 'parent attestation expired');
    if (thumbprint(att.cnf.jwk) !== thumbprint(signerJwk)) throw new HttpError(401, 'key_mismatch', 'request not signed by the attested key');
    const status = await this.remoteStatus(iss, att.sub);
    if (status.status !== 'active') throw new HttpError(403, 'parent_inactive', `parent at ${iss} is ${status.status}`);
    // To vouch for a sub-agent we need what the parent's directory says about the chain, so the parent must disclose it to us.
    const a = att.accountability ?? {};
    if (!a.principal_type || !a.assurance || !a.verification_source || !Number.isInteger(a.chain_length)) {
      throw new HttpError(400, 'chain_summary_required', 'the parent must disclose principal_type, assurance, verification_source and chain_length to this directory');
    }
    return {
      link: { type: 'remote_agent', directory: iss, aaf_id: att.sub, reg_binding: att.reg_binding, cnf_thumbprint: thumbprint(signerJwk) },
      principalSummary: { type: a.principal_type, assurance: a.assurance, verification_source: a.verification_source, directory: a.principal_directory ?? iss },
      depth: a.chain_length + 1,
    };
  }

  mustRegistration(id) {
    const r = this.registrations.get(id);
    if (!r) throw new HttpError(404, 'unknown_registration', `no registration ${id}`);
    return r;
  }

  /** Who may revoke: the principal, any ancestor agent, the direct (remote) parent, or the operator. */
  async revoke(registrationId, { header, jwk, payload }) {
    const reg = this.mustRegistration(registrationId);
    const reason = payload.reason ?? 'principal_request';
    if (!REVOCATION_REASONS.includes(reason)) throw new HttpError(400, 'invalid_reason', `reason must be one of ${REVOCATION_REASONS.join(', ')}`);
    const kid = header.kid ?? '';
    let by = null;
    if (kid.startsWith('principal:') && kid.slice('principal:'.length) === reg.principal) by = kid;
    if (kid.startsWith('registration:') && this.ancestors(reg).some((a) => a.id === kid.slice('registration:'.length))) by = kid;
    if (!by && reg.parent.type === 'remote_agent' && jwk && thumbprint(jwk) === reg.parent.cnf_thumbprint) by = `remote:${reg.parent.aaf_id}`;
    if (!by) throw new HttpError(403, 'not_authorized', 'only the principal chain above this agent may revoke it');
    return this.applyRevocation(reg, reason, by);
  }

  async applyRevocation(reg, reason, by) {
    if (reg.status === 'revoked') return { registration_id: reg.id, status: 'revoked', already: true };
    this.commit('registration.revoked', { id: reg.id, reason, by });
    const descendants = this.descendants(reg);
    const peersNotified = await this.pushStatusChange([reg, ...descendants]);
    return { registration_id: reg.id, status: 'revoked', reason, cascades_to: descendants.length, peers_notified: peersNotified };
  }

  /**
   * Push: tell peer directories that hold sub-agents under these registrations
   * to drop cached status at once. Pull (bounded cache) remains the backstop if
   * a peer is unreachable, so propagation never exceeds statusCacheSeconds.
   */
  async pushStatusChange(regs) {
    const ids = new Set(regs.map((r) => r.id));
    const byPeer = new Map();
    for (const [aaf_id, rec] of this.aaf_ids) {
      if (!ids.has(rec.registration)) continue;
      const peer = this.trust.directory(rec.audience);
      if (!peer || peer.id === this.id) continue;
      byPeer.set(peer, [...(byPeer.get(peer) ?? []), aaf_id]);
    }
    const notified = [];
    for (const [peer, aaf_ids] of byPeer) {
      try {
        await peerCall(this, `${peer.url}/v1/federation/status-changed`, { aaf_ids });
        notified.push(peer.id);
      } catch {
        // Peer unreachable: its cache expires within statusCacheSeconds.
      }
    }
    return notified;
  }

  statusChangedUpstream(peerId, aaf_ids) {
    let invalidated = 0;
    for (const aaf_id of aaf_ids) if (this.remoteStatusCache.delete(`${peerId}|${aaf_id}`)) invalidated++;
    return { invalidated };
  }

  ancestors(reg) {
    const out = [];
    let cur = reg;
    while (cur?.parent?.type === 'agent') {
      cur = this.registrations.get(cur.parent.registration);
      if (cur) out.push(cur);
    }
    return out;
  }

  /** Status of a registration, including everything above it in the chain. */
  async registrationStatus(reg) {
    if (!reg) return { status: 'unknown', reason: 'no_such_registration' };
    if (reg.status === 'revoked') return { status: 'revoked', reason: reg.revocation.reason, at: reg.revocation.at };
    if (reg.expires_at && Date.parse(reg.expires_at) <= Date.now()) return { status: 'expired', reason: 'registration_expired', at: reg.expires_at };
    const parent = reg.parent;
    if (parent.type === 'principal') {
      const p = this.principals.get(parent.id);
      if (!this.principalVerificationValid(p)) return { status: 'suspended', reason: p.closed ? 'principal_record_closed' : 'principal_verification_lapsed' };
    } else if (parent.type === 'agent') {
      const up = await this.registrationStatus(this.registrations.get(parent.registration));
      if (up.status !== 'active') return { status: up.status, reason: `upstream:${up.reason}` };
    } else if (parent.type === 'remote_agent') {
      const up = await this.remoteStatus(parent.directory, parent.aaf_id);
      // A remote parent that changed hands ends this link; the new owner re-attaches sub-agents.
      if (up.status === 'transferred') return { status: 'revoked', reason: `upstream(${parent.directory}):parent_transferred` };
      if (up.status !== 'active') return { status: up.status, reason: `upstream(${parent.directory}):${up.reason}` };
    }
    return { status: 'active' };
  }

  /** Ask a federation peer for the status of an ID it issued (cached briefly). */
  async remoteStatus(directoryId, aaf_id) {
    const key = `${directoryId}|${aaf_id}`;
    const cached = this.remoteStatusCache.get(key);
    if (cached && cached.until > Date.now()) return cached.value;
    const peer = this.trust.directory(directoryId);
    let value;
    try {
      const res = await postJson(`${peer.url}/v1/status`, { aaf_id });
      const { payload } = verifyJws(res.status_token, this.trust.signingKey(peer), { typ: TYP.status });
      if (payload.sub !== aaf_id) throw new Error('status token for wrong aaf_id');
      value = { status: payload.status, reason: payload.reason };
    } catch (err) {
      return { status: 'unknown', reason: err instanceof ServiceError ? err.code : 'invalid_status_token' };
    }
    this.remoteStatusCache.set(key, { value, until: Date.now() + this.policies.statusCacheSeconds * 1000 });
    return value;
  }

  // -------------------------------------------------------------------------
  // IDs and accountability attestations
  // -------------------------------------------------------------------------

  /** One value per (registration, chain version, audience): a new principal relationship means new PPIDs. */
  pairwisePpid(registrationId, version, audience) {
    const mac = hmac(Buffer.from(this.keys.pairwiseSecret, 'base64url'), `${registrationId}|${version}|${audience}`);
    return `${ID_PREFIX}:${this.host}:p_${base32(mac).slice(0, 26)}`;
  }

  rootOf(reg) {
    if (reg.principal) {
      const p = this.principals.get(reg.principal);
      return { local: true, principal: p };
    }
    return { local: false, summary: reg.principal_summary };
  }

  async issueAttestation(registrationId, { audience, mode = 'pairwise', cnf_jwk: cnfJwk }) {
    const reg = this.mustRegistration(registrationId);
    if (!audience) throw new HttpError(400, 'missing_audience', 'audience is required');
    if (!['pairwise', 'unlinkable'].includes(mode)) throw new HttpError(400, 'invalid_mode', 'mode must be pairwise or unlinkable');
    if (!cnfJwk || cnfJwk.crv !== 'Ed25519') throw new HttpError(400, 'invalid_cnf', 'cnf_jwk must be an Ed25519 public JWK');
    if (thumbprint(cnfJwk) === thumbprint(reg.agent_jwk)) {
      throw new HttpError(400, 'correlatable_key', 'presentation key must differ from the long-term agent key');
    }
    const status = await this.registrationStatus(reg);
    if (status.status === 'unknown') throw new HttpError(503, 'status_unavailable', `cannot establish status: ${status.reason}`);
    if (status.status !== 'active') throw new HttpError(403, 'registration_inactive', `registration is ${status.status} (${status.reason})`);

    const now = nowSeconds();
    const version = this.chainVersion(reg);
    // Whoever is accountable for conduct under this ID, fixed at issuance.
    const rootSnapshot = reg.principal ? { principal: reg.principal } : { remote: reg.parent.type === 'remote_agent' ? reg.parent.directory : null };
    const expiry = this.effectiveExpiry(reg);
    const exp = Math.min(now + this.policies.attestationTtlSeconds, expiry != null ? Math.floor(expiry / 1000) : Infinity);
    let aaf_id;
    let sealedRef;
    let statusIdx;
    if (mode === 'pairwise') {
      aaf_id = this.pairwisePpid(reg.id, version, audience);
      if (!this.aaf_ids.has(aaf_id)) this.commit('aaf_id.issued', { aaf_id, registration: reg.id, audience, version, root: rootSnapshot, status_idx: allocateIndex(this.statusIndex) });
      statusIdx = this.aaf_ids.get(aaf_id).status_idx;
    } else {
      aaf_id = `${ID_PREFIX}:${this.host}:u_${base32(randomBytes(16)).slice(0, 26)}`;
      sealedRef = sealJwe({ aaf_id, registration: reg.id, audience, version, root: rootSnapshot, iat: now }, this.keys.encryption.publicJwk);
      statusIdx = allocateIndex(this.statusIndex);
      this.rememberUnlinkable({ idx: statusIdx, unlinkable: true, registration: reg.id, version, exp });
    }

    // Everything about the principal and the chain is selectively disclosable:
    // the ID alone is a valid presentation (PR-1), and the agent adds what the
    // counterparty asks for and the principal allows (PR-5, PR-10). Long-lived
    // facts are coarsened: an exact time repeated across counterparties would
    // be a correlation handle.
    const root = this.rootOf(reg);
    const claims = {};
    let attributes = [];
    if (root.local) {
      const p = root.principal;
      claims.principal_type = sd(p.type);
      claims.assurance = sd({ trust_framework: p.verification.trust_framework, assurance_level: p.verification.assurance_level });
      claims.verification_source = sd({ verifier: p.verification.verifier, time: p.verification.time.slice(0, 7) });
      claims.principal_directory = sd(this.id);
      const disclose = p.disclosure.identity;
      if (disclose.audiences.includes(audience) || disclose.audiences.includes('*')) {
        for (const c of disclose.claims) if (p.identity[c] !== undefined) claims[c] = sd(p.identity[c]);
      }
      attributes = p.attributes
        .filter((a) => p.disclosure.attributes.includes(a.name))
        .filter((a) => !a.expires_at || new Date(a.expires_at) > new Date())
        .map((a) =>
          sd({
            verification: {
              trust_framework: a.verified_claims.verification.trust_framework,
              time: a.verified_claims.verification.time.slice(0, 7),
              evidence: [{ type: 'electronic_record', record: { type: a.name, source: { name: attributeSource(a.verified_claims) } } }],
              verifier: a.attested_by,
            },
            claims: a.verified_claims.claims,
            valid_until: a.expires_at?.slice(0, 7) ?? null,
          }),
        );
    } else {
      // The principal is registered with another directory: pass on what that directory attested.
      const sum = root.summary ?? {};
      if (sum.type) claims.principal_type = sd(sum.type);
      if (sum.assurance) claims.assurance = sd(sum.assurance);
      if (sum.verification_source) claims.verification_source = sd(sum.verification_source);
      if (sum.directory) claims.principal_directory = sd(sum.directory);
    }

    const payload = {
      vct: vct(this.trust.trustAnchor.entity_id, 'accountability'),
      iss: this.id,
      sub: aaf_id,
      aud: audience,
      iat: now,
      exp,
      jti: randomId('att', 12),
      cnf: { jwk: publicOf(cnfJwk) },
      // pairwise: a PPID, at most one per agent and counterparty; unlinkable: single-use.
      id_mode: mode,
      reg_binding: regBinding(reg.id, version, aaf_id),
      // The directory's statement: this ID resolves to a principal it verified under its published practices.
      accountability: sdPad({ status: 'accountable', ...claims, chain_length: sd(reg.depth), attributes: sdPad(attributes, PAD.attributes) }, PAD.claims),
      records: sdPad(reg.records.map((r) => sd(r)), PAD.records),
      status: { status_list: { idx: statusIdx, uri: this.statusListUri } },
      ...(sealedRef ? { sealed_ref: sealedRef } : {}),
    };
    const attestation = issueSdJwt(payload, this.keys.signing, { typ: TYP.attestation });
    return { aaf_id, mode, attestation, expires_at: payload.exp };
  }

  /** Map an ID (plus sealed reference for unlinkable IDs) to a registration, the chain version and the root at issuance. */
  locate(aaf_id, sealedRef) {
    if (directoryOfId(aaf_id) !== this.host) throw new HttpError(400, 'foreign_id', `this ID was not issued by ${this.id}`);
    if (aaf_id.includes(':p_')) {
      const rec = this.aaf_ids.get(aaf_id);
      if (!rec) throw new HttpError(404, 'unknown_id', 'ID not recognized');
      return { registration: this.registrations.get(rec.registration), audience: rec.audience, version: rec.version ?? 0, root: rec.root, issuedAt: rec.issued_at };
    }
    if (!sealedRef) throw new HttpError(400, 'sealed_ref_required', 'unlinkable IDs can be traced only with the sealed reference the counterparty kept');
    let opened;
    try {
      opened = openJwe(sealedRef, this.keys.encryption.privateJwk).payload;
    } catch {
      throw new HttpError(400, 'invalid_sealed_ref', 'sealed reference could not be opened');
    }
    if (opened.aaf_id !== aaf_id) throw new HttpError(400, 'sealed_ref_mismatch', 'sealed reference belongs to a different ID');
    return { registration: this.registrations.get(opened.registration), audience: opened.audience, version: opened.version ?? 0, root: opened.root, issuedAt: new Date(opened.iat * 1000).toISOString() };
  }

  /** Status of one ID: an ID from before a change of hands is "transferred", whatever the agent's status now. */
  async idStatus(located) {
    const s = await this.registrationStatus(located.registration);
    if (s.status === 'active' && located.version !== this.chainVersion(located.registration)) return { status: 'transferred', reason: 'custody_transferred' };
    return s;
  }

  async status({ aaf_id, sealed_ref: sealedRef }) {
    const s = await this.idStatus(this.locate(aaf_id, sealedRef));
    const token = signJws(
      { iss: this.id, sub: aaf_id, status: s.status, reason: s.reason ?? null, revoked_at: s.at ?? null, checked_at: new Date().toISOString(), iat: nowSeconds() },
      this.keys.signing,
      { typ: TYP.status },
    );
    return { aaf_id, status: s.status, reason: s.reason ?? null, status_token: token };
  }

  // -------------------------------------------------------------------------
  // Incidents: the directory relays to the principal without revealing it
  // -------------------------------------------------------------------------

  async incident({ header, payload, thumbprint: reporterKey }) {
    const { aaf_id, sealed_ref: sealedRef, reporter, summary, evidence = [] } = payload;
    const located = this.locate(aaf_id, sealedRef);
    const { registration } = located;
    const forwardedBy = (header.kid ?? '').startsWith('directory:') ? header.kid.slice('directory:'.length) : null;
    const id = randomId('inc', 10);
    this.commit('incident.reported', { id, aaf_id, registration: registration.id, reporter, reporter_key: reporterKey, forwarded_by: forwardedBy, summary, evidence });
    let principalNotified = false;
    let top = registration;
    while (top.parent.type === 'agent') top = this.registrations.get(top.parent.registration);
    if (located.root?.principal) {
      // The principal accountable when the ID was issued, and the current one if the agent has since changed hands.
      for (const principal of new Set([located.root.principal, registration.principal].filter(Boolean))) {
        this.commit('notification.sent', {
          principal,
          notification: {
            kind: 'incident', incident_id: id, registration_id: registration.id, agent_label: registration.label,
            reporter, forwarded_by: forwardedBy, summary, aaf_id, about_prior_custody: principal !== located.root.principal,
          },
        });
      }
      principalNotified = true;
    } else if (top.parent.type === 'remote_agent') {
      // The principal is registered with a peer: relay through it, naming
      // the delegating agent's ID there. The reporter learns nothing new.
      const peer = this.trust.directory(top.parent.directory);
      try {
        const res = await peerCall(this, `${peer.url}/v1/incidents`, {
          aaf_id: top.parent.aaf_id,
          reporter,
          summary: `[relayed by ${this.id} about sub-agent ${registration.label ?? registration.id}] ${summary}`,
          evidence,
        });
        principalNotified = res.principal_notified;
      } catch {
        principalNotified = false;
      }
    }
    return { incident_id: id, principal_notified: principalNotified, incident_response: registration.provider ?? null };
  }

  // -------------------------------------------------------------------------
  // Attribution under legal process
  // -------------------------------------------------------------------------

  verifyOrder(order) {
    const { payload: unverified, header } = decodeJws(order);
    const authority = this.trust.authority(unverified.iss, 'designated-authority');
    if (!authority) throw new HttpError(403, 'untrusted_authority', `${unverified.iss} is not a recognized designated authority`);
    let payload;
    try {
      payload = verifyJws(order, this.trust.signingKey(authority, header.kid), { typ: TYP.order }).payload;
    } catch (err) {
      throw new HttpError(403, 'invalid_order', err.message);
    }
    if (payload.exp && payload.exp < nowSeconds()) throw new HttpError(403, 'order_expired', 'legal order expired');
    return { payload, authority };
  }

  async trace({ order, aaf_id, sealed_ref: sealedRef, forward }) {
    const { payload: ord, authority } = this.verifyOrder(order);
    let subjectId = aaf_id;
    let forwardedBy = null;
    if (forward) {
      const { payload: unverified } = decodeJws(forward);
      const peer = this.trust.directory(unverified.iss);
      if (!peer) throw new HttpError(403, 'untrusted_directory', 'forwarding directory is not a federation peer');
      const { payload: fwd } = verifyJws(forward, this.trust.signingKey(peer), { typ: TYP.forward });
      if (fwd.order_digest !== sha256b64u(order) || fwd.aaf_id !== aaf_id) throw new HttpError(403, 'invalid_forward', 'forwarding statement does not match');
      subjectId = fwd.subject_id;
      forwardedBy = peer.id;
    }
    if (!ord.aaf_ids.includes(subjectId)) throw new HttpError(403, 'not_covered', 'the order does not cover this ID');

    const located = this.locate(aaf_id, sealedRef);
    const { registration } = located;
    const idStatus = await this.idStatus(located);
    const chain = [];
    let cur = registration;
    while (cur) {
      const s = await this.registrationStatus(cur);
      chain.push({
        directory: this.id, registration_id: cur.id, label: cur.label, status: s.status, reason: s.reason ?? null,
        created_at: cur.created_at, revoked_at: cur.revocation?.at ?? null, expires_at: cur.expires_at ?? null, provider: cur.provider,
        ...(cur.custody?.length > 1 ? { custody: cur.custody.map((c) => ({ principal: this.principals.get(c.principal)?.identity.legal_name, from: c.from, to: c.to })) } : {}),
      });
      cur = cur.parent.type === 'agent' ? this.registrations.get(cur.parent.registration) : null;
    }
    const top = chain.length ? this.registrations.get(chain[chain.length - 1].registration_id) : registration;

    let principal = null;
    let upstream = null;
    if (located.root?.principal) {
      // The principal accountable for conduct under this ID: the one in place when it was issued.
      const p = this.principals.get(located.root.principal);
      principal = {
        principal_id: p.id, type: p.type, identity: p.identity, contact: p.contact,
        verification: { verifier: p.verification.verifier, trust_framework: p.verification.trust_framework, assurance_level: p.verification.assurance_level, time: p.verification.time, verification_process: p.verification.verification_process, evidence: p.verification.evidence },
        directory: this.id,
      };
    } else if (top.parent.type === 'remote_agent') {
      const peer = this.trust.directory(top.parent.directory);
      const fwd = signJws(
        { iss: this.id, aud: peer.id, order_digest: sha256b64u(order), aaf_id: top.parent.aaf_id, subject_id: subjectId, iat: nowSeconds() },
        this.keys.signing,
        { typ: TYP.forward },
      );
      upstream = await postJson(`${peer.url}/v1/attributions`, { order, aaf_id: top.parent.aaf_id, forward: fwd });
      chain.push(...upstream.result.chain);
      principal = upstream.result.principal;
    }

    let related = [];
    if (ord.scope?.includes('related_ids') && ord.counterparty && principal?.directory === this.id) {
      related = [...this.aaf_ids.entries()]
        .filter(([, v]) => v.audience === ord.counterparty && v.root?.principal === principal.principal_id)
        .map(([k]) => k);
    }

    const id = randomId('res', 10);
    this.commit('attribution.performed', {
      id, authority: authority.id, case: ord.case, aaf_id, forwarded_by: forwardedBy, scope: ord.scope ?? [], requester: ord.requester ?? null,
    });
    if (ord.notify_principal !== false && principal?.directory === this.id) {
      this.commit('notification.sent', {
        principal: principal.principal_id,
        notification: { kind: 'attribution', attribution_id: id, authority: authority.id, case: ord.case, registration_id: registration.id, agent_label: registration.label },
      });
    }

    const result = {
      attribution_id: id, aaf_id, id_status: idStatus.status, id_issued_at: located.issuedAt ?? null, authority: authority.id, case: ord.case,
      principal: principal, current_principal: registration.principal && registration.principal !== principal?.principal_id
        ? { principal_id: registration.principal, legal_name: this.principals.get(registration.principal).identity.legal_name } : undefined,
      chain, related_ids: related,
    };
    return { result, token: signJws({ iss: this.id, iat: nowSeconds(), ...result }, this.keys.signing, { typ: TYP.attribution }) };
  }

  /**
   * Revocation under a legal order (RV-1): a designated authority may require
   * this directory to revoke the registration behind an ID. The order must name
   * the ID and carry the revoke_registration scope. An ID from before a change
   * of hands names a relationship that has already ended, so there is nothing
   * to revoke under it.
   */
  async revokeUnderOrder({ order, aaf_id, sealed_ref: sealedRef }) {
    const { payload: ord, authority } = this.verifyOrder(order);
    if (!ord.aaf_ids?.includes(aaf_id)) throw new HttpError(403, 'not_covered', 'the order does not cover this ID');
    if (!ord.scope?.includes(ORDER_SCOPE_REVOKE)) throw new HttpError(403, 'not_in_scope', `the order does not include the ${ORDER_SCOPE_REVOKE} scope`);
    const located = this.locate(aaf_id, sealedRef);
    const { registration } = located;
    if (located.version !== this.chainVersion(registration)) {
      throw new HttpError(409, 'custody_changed', 'this ID belongs to a principal–agent relationship that has already ended; the agent now answers to a different principal');
    }
    let res = { registration_id: registration.id, status: 'revoked', already: true };
    if (registration.status !== 'revoked') {
      this.commit('registration.revoked', { id: registration.id, reason: 'legal_order', by: `authority:${authority.id}`, case: ord.case });
      const descendants = this.descendants(registration);
      const peersNotified = await this.pushStatusChange([registration, ...descendants]);
      res = { registration_id: registration.id, status: 'revoked', reason: 'legal_order', cascades_to: descendants.length, peers_notified: peersNotified };
    }
    if (!res.already && ord.notify_principal !== false && registration.principal) {
      this.commit('notification.sent', {
        principal: registration.principal,
        notification: { kind: 'revocation_order', authority: authority.id, case: ord.case, registration_id: registration.id, agent_label: registration.label },
      });
    }
    return { ...res, aaf_id, authority: authority.id, case: ord.case };
  }

  // -------------------------------------------------------------------------
  // Accreditation of records services: OpenID Federation Trust Marks, one per
  // role, issued only for types the Trust Anchor lets this directory issue.
  // -------------------------------------------------------------------------

  accredit(rsId) {
    const rs = this.trust.recordsService(rsId);
    if (!rs) throw new HttpError(404, 'unknown_records_service', `${rsId} is not a member of the federation`);
    const existing = this.accreditations.get(rsId);
    if (existing?.status === 'active') return { trust_marks: Object.entries(existing.marks).map(([t, m]) => ({ trust_mark_type: t, trust_mark: m })), already: true };
    const marks = {};
    for (const role of rs.roles) {
      const type = trustMarkType(this.trust.trustAnchor.entity_id, role);
      if (!this.trust.trustMarkIssuers(type).includes(this.id)) continue;
      marks[type] = issueTrustMark({ issuer: this.id, key: this.keys.signing, sub: rsId, type });
    }
    if (!Object.keys(marks).length) throw new HttpError(403, 'not_a_trust_mark_issuer', `${this.id} may not accredit ${rsId}`);
    const roles = rs.roles.filter((r) => marks[trustMarkType(this.trust.trustAnchor.entity_id, r)]);
    this.commit('accreditation.granted', { rs: rsId, roles, marks });
    return { trust_marks: Object.entries(marks).map(([t, m]) => ({ trust_mark_type: t, trust_mark: m })) };
  }

  withdrawAccreditation(rsId) {
    this.commit('accreditation.withdrawn', { rs: rsId });
    return { rs: rsId, status: 'withdrawn' };
  }

  /** The current Trust Mark of a type for a subject, or null if none or withdrawn. */
  trustMark(type, sub) {
    const a = this.accreditations.get(sub);
    if (!a || a.status !== 'active') return null;
    return a.marks?.[type] ?? null;
  }

  // -------------------------------------------------------------------------
  // Transparency: public, redacted view of the directory's own log
  // -------------------------------------------------------------------------

  transparencyEntries(start = 0, end = this.log.size) {
    const out = [];
    for (let i = start; i < Math.min(end, this.log.size); i++) {
      const e = this.log.get(i);
      out.push({ index: i, type: e.type, at: e.at, leaf_hash: this.log.leafHashAt(i) });
    }
    return out;
  }

  stats() {
    const regs = [...this.registrations.values()];
    return {
      principals: this.principals.size,
      verified_principals: [...this.principals.values()].filter((p) => this.principalVerificationValid(p)).length,
      registrations: regs.length,
      active_registrations: regs.filter((r) => r.status === 'active').length,
      revoked_registrations: regs.filter((r) => r.status === 'revoked').length,
      pairwise_ppids: this.aaf_ids.size,
      transfers: [...this.transferOffers.values()].filter((o) => o.status === 'accepted').length,
      incidents: this.incidents.size,
      accreditations: [...this.accreditations.values()].filter((a) => a.status === 'active').map((a) => a.rs),
      log_size: this.log.size,
    };
  }
}
