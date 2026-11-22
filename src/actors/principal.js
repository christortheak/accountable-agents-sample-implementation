// Principal SDK: a natural or legal person that enrolls with a directory,
// registers agents, grants them authority, designates human approvers, and
// revokes registrations.
import { generateSigningKey, signJws, nowSeconds, randomId, publicOf } from '../lib/crypto.js';
import { postJson, sendSigned, postSigned } from '../lib/http.js';
import { TYP as RS_TYP } from '../records/records.js';
import { TYP as DIRECTORY_TYP, AGENT_PROOF_PURPOSE } from '../directory/directory.js';
import { toRar } from '../lib/scope.js';
import { SoftwareAuthenticator } from '../lib/webauthn.js';

export class Principal {
  /**
   * @param {object} opts
   * @param {'natural_person'|'legal_person'} opts.type
   * @param {object} opts.identity  { legal_name, jurisdiction, registration_number?, date_of_birth?, ... }
   * @param {object} opts.directory  trust-list entry of the directory to enroll with
   */
  constructor({ type, identity, contact = null, directory, trust }) {
    this.type = type;
    this.identity = identity;
    this.contact = contact;
    this.directory = directory;
    this.trust = trust;
    this.key = generateSigningKey();
    this.id = null;
    this.receipts = [];
  }

  get name() {
    return this.identity.legal_name;
  }

  /** A request to a directory, signed (RFC 9421) with the principal's enrolled key. */
  call(url, params, method = 'POST') {
    return sendSigned(method, url, params, this.key, { keyid: `principal:${this.id}` });
  }

  async enroll() {
    const res = await postSigned(`${this.directory.url}/v1/principals`, { type: this.type, identity: this.identity, contact: this.contact }, this.key, { embedJwk: true });
    this.id = res.principal_id;
    return res;
  }

  async setDisclosurePolicy(policy) {
    return this.call(`${this.directory.url}/v1/principals/${this.id}/disclosure-policy`, { policy }, 'PUT');
  }

  /** Register an agent under this principal. The agent keeps its own long-term key and proves it holds it. */
  async registerAgent(agent, { label, records, provider = null, expiresIn = null, lineage = null }) {
    const res = await this.call(`${this.directory.url}/v1/registrations`, {
      agent_jwk: publicOf(agent.longTermKey.publicJwk),
      agent_proof: agent.keyProof(this.directory.id, AGENT_PROOF_PURPOSE.registration, `principal:${this.id}`),
      parent: { type: 'principal' }, records, provider, label, expires_in: expiresIn, lineage,
    });
    agent.attach({ directory: this.directory, registrationId: res.registration_id, receipt: res.receipt, records });
    this.receipts.push(res.receipt);
    return res;
  }

  /** Grant authority to an agent and deposit the grant with an authorization records service. */
  async grant(agent, { rs, permissions, prohibitions = [], delegation = { allowed: false, max_depth: 0 }, purpose, context, validForDays = 30 }) {
    const now = nowSeconds();
    const grant = signJws(
      {
        iss: `principal:${this.id}@${this.directory.id}`,
        sub: agent.registrationId,
        directory: agent.directory.id,
        agent_key: agent.longTermKey.kid,
        iat: now,
        nbf: now,
        exp: now + validForDays * 86400,
        jti: randomId('grt', 12),
        authorization_details: permissions.map(toRar), // RFC 9396
        prohibitions: prohibitions.map(toRar),
        delegation,
        purpose,
        context,
      },
      this.key,
      { typ: RS_TYP.grant, embedJwk: true },
    );
    const res = await postJson(`${rs.url}/v1/grants`, { grant, registration_receipt: agent.receipt });
    agent.addGrant({ grantId: res.grant_id, rs, grant });
    return { ...res, grant };
  }

  /** Designate a human (by key) to a role, e.g. the officer who must approve filings. */
  async designate(person, { rs, role, validForDays = 365 }) {
    const now = nowSeconds();
    const grant = signJws(
      {
        iss: `principal:${this.id}@${this.directory.id}`,
        // The designee is identified by the passkey they registered with the records service.
        grantee: { kind: 'person', passkey: person.passkeys.get(rs.id), role, display_name: person.name },
        iat: now,
        exp: now + validForDays * 86400,
        jti: randomId('dsg', 12),
      },
      this.key,
      { typ: RS_TYP.grant, embedJwk: true },
    );
    const res = await postJson(`${rs.url}/v1/grants`, { grant, registration_receipt: this.receipts[0] });
    person.designations.push({ designationId: res.grant_id, role, rs });
    return res;
  }

  async revokeGrant(rs, grantId, reason = 'grantor_request') {
    return postSigned(`${rs.url}/v1/grants/${grantId}/revoke`, { reason }, this.key, { embedJwk: true });
  }

  /** Offer one of our agents (and, by default, its sub-agents) to another verified principal. */
  async offerTransfer(agent, recipient, { subtree = 'move', expiresIn } = {}) {
    return this.call(`${this.directory.url}/v1/registrations/${agent.registrationId}/transfer-offers`, { to_principal: recipient.id, subtree, expires_in: expiresIn });
  }

  async cancelTransfer(offerId) {
    return this.call(`${this.directory.url}/v1/transfer-offers/${offerId}/cancel`, {});
  }

  /**
   * Accept an offered agent. The agent gets a fresh long-term key (the previous
   * owner may still hold the old one) and starts over with no grants.
   */
  async acceptTransfer(offerId, agent) {
    const newKey = generateSigningKey();
    const res = await this.call(`${this.directory.url}/v1/transfer-offers/${offerId}/accept`, {
      agent_jwk: publicOf(newKey.publicJwk), agent_proof: keyProof(newKey, this.directory.id, AGENT_PROOF_PURPOSE.transfer, offerId),
    });
    agent.rekey(newKey, res.receipt);
    this.receipts.push(res.receipt);
    return res;
  }

  async rotateAgentKey(agent) {
    const newKey = generateSigningKey();
    const res = await this.call(`${agent.directory.url}/v1/registrations/${agent.registrationId}/rotate-key`, {
      agent_jwk: publicOf(newKey.publicJwk), agent_proof: keyProof(newKey, agent.directory.id, AGENT_PROOF_PURPOSE.rotation, agent.registrationId),
    });
    agent.rekey(newKey, res.receipt);
    return res;
  }

  async revokeAgent(agent, reason = 'principal_request') {
    return this.call(`${this.directory.url}/v1/registrations/${agent.registrationId}/revoke`, { reason });
  }

  async notifications() {
    const res = await this.call(`${this.directory.url}/v1/principals/${this.id}/notifications`, {});
    return res.notifications;
  }
}

/** Proof of possession of a fresh agent key (the principal holds it until the agent adopts it). */
const keyProof = (key, directoryId, purpose, binding) =>
  signJws({ aud: directoryId, purpose, binding, agent_key: key.kid, iat: nowSeconds() }, key, { typ: DIRECTORY_TYP.agentProof });

/**
 * A human acting in a designated role (for example a compliance officer). They
 * approve with a passkey; in the simulator the passkey lives in a software
 * authenticator standing in for Face ID / Touch ID on their own device.
 */
export class Person {
  constructor({ name }) {
    this.name = name;
    this.authenticator = new SoftwareAuthenticator();
    this.passkeys = new Map(); // records service id -> credential id
    this.designations = [];
  }

  /** Register a passkey with a records service (the records service is the WebAuthn relying party). */
  async registerPasskey(rs) {
    const opts = await postJson(`${rs.url}/v1/webauthn/registration-options`, { display_name: this.name });
    const credential = this.authenticator.create(opts.publicKey, rs.id);
    const res = await postJson(`${rs.url}/v1/webauthn/register`, { request_id: opts.request_id, credential });
    this.passkeys.set(rs.id, res.credential_id);
    return res;
  }

  /** Approve one specific action: the records service's challenge commits to it; the passkey signs it after user verification. */
  async approve({ rs, designationId, aaf_id, action, subjectDigest, note }) {
    const opts = await postJson(`${rs.url}/v1/approvals/options`, { designation_id: designationId, aaf_id, action, subject_digest: subjectDigest, note });
    const credential = this.authenticator.get(opts.publicKey, rs.id);
    return postJson(`${rs.url}/v1/approvals`, { request_id: opts.request_id, credential });
  }
}
