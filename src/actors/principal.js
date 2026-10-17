// Principal SDK: a natural or legal person that enrolls with a registry,
// registers agents, grants them authority, designates human approvers, and
// revokes registrations.
import { generateSigningKey, signJws, nowSeconds, randomId, publicOf } from '../lib/crypto.js';
import { postJson, sendSigned, postSigned } from '../lib/http.js';
import { TYP as RK_TYP } from '../recordkeeper/recordkeeper.js';
import { toRar } from '../lib/scope.js';
import { SoftwareAuthenticator } from '../lib/webauthn.js';

export class Principal {
  /**
   * @param {object} opts
   * @param {'natural_person'|'legal_person'} opts.type
   * @param {object} opts.identity  { legal_name, jurisdiction, registration_number?, date_of_birth?, ... }
   * @param {object} opts.registry  trust-list entry of the registry to enroll with
   */
  constructor({ type, identity, contact = null, registry, trust }) {
    this.type = type;
    this.identity = identity;
    this.contact = contact;
    this.registry = registry;
    this.trust = trust;
    this.key = generateSigningKey();
    this.id = null;
    this.receipts = [];
  }

  get name() {
    return this.identity.legal_name;
  }

  /** A request to a registry, signed (RFC 9421) with the principal's enrolled key. */
  call(url, params, method = 'POST') {
    return sendSigned(method, url, params, this.key, { keyid: `principal:${this.id}` });
  }

  async enroll() {
    const res = await postSigned(`${this.registry.url}/v1/principals`, { type: this.type, identity: this.identity, contact: this.contact }, this.key, { embedJwk: true });
    this.id = res.principal_id;
    return res;
  }

  async setDisclosurePolicy(policy) {
    return this.call(`${this.registry.url}/v1/principals/${this.id}/disclosure-policy`, { policy }, 'PUT');
  }

  /** Register an agent under this principal. The agent keeps its own long-term key. */
  async registerAgent(agent, { label, records, provider = null, expiresIn = null, lineage = null }) {
    const res = await this.call(`${this.registry.url}/v1/registrations`, {
      agent_jwk: publicOf(agent.longTermKey.publicJwk), parent: { type: 'principal' }, records, provider, label, expires_in: expiresIn, lineage,
    });
    agent.attach({ registry: this.registry, registrationId: res.registration_id, receipt: res.receipt, records });
    this.receipts.push(res.receipt);
    return res;
  }

  /** Grant authority to an agent and deposit the grant with an authorization record keeper. */
  async grant(agent, { rk, permissions, prohibitions = [], delegation = { allowed: false, max_depth: 0 }, purpose, context, validForDays = 30 }) {
    const now = nowSeconds();
    const grant = signJws(
      {
        iss: `principal:${this.id}@${this.registry.id}`,
        sub: agent.registrationId,
        registry: agent.registry.id,
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
      { typ: RK_TYP.grant, embedJwk: true },
    );
    const res = await postJson(`${rk.url}/v1/grants`, { grant, registration_receipt: agent.receipt });
    agent.addGrant({ grantId: res.grant_id, rk, grant });
    return { ...res, grant };
  }

  /** Designate a human (by key) to a role, e.g. the officer who must approve filings. */
  async designate(person, { rk, role, validForDays = 365 }) {
    const now = nowSeconds();
    const grant = signJws(
      {
        iss: `principal:${this.id}@${this.registry.id}`,
        // The designee is identified by the passkey they registered with the keeper.
        grantee: { kind: 'person', passkey: person.passkeys.get(rk.id), role, display_name: person.name },
        iat: now,
        exp: now + validForDays * 86400,
        jti: randomId('dsg', 12),
      },
      this.key,
      { typ: RK_TYP.grant, embedJwk: true },
    );
    const res = await postJson(`${rk.url}/v1/grants`, { grant, registration_receipt: this.receipts[0] });
    person.designations.push({ designationId: res.grant_id, role, rk });
    return res;
  }

  async revokeGrant(rk, grantId, reason = 'grantor_request') {
    return postSigned(`${rk.url}/v1/grants/${grantId}/revoke`, { reason }, this.key, { embedJwk: true });
  }

  /** Offer one of our agents (and, by default, its sub-agents) to another verified principal. */
  async offerTransfer(agent, recipient, { subtree = 'move', expiresIn } = {}) {
    return this.call(`${this.registry.url}/v1/registrations/${agent.registrationId}/transfer-offers`, { to_principal: recipient.id, subtree, expires_in: expiresIn });
  }

  async cancelTransfer(offerId) {
    return this.call(`${this.registry.url}/v1/transfer-offers/${offerId}/cancel`, {});
  }

  /**
   * Accept an offered agent. The agent gets a fresh long-term key (the previous
   * owner may still hold the old one) and starts over with no grants.
   */
  async acceptTransfer(offerId, agent) {
    const newKey = generateSigningKey();
    const res = await this.call(`${this.registry.url}/v1/transfer-offers/${offerId}/accept`, { agent_jwk: publicOf(newKey.publicJwk) });
    agent.rekey(newKey, res.receipt);
    this.receipts.push(res.receipt);
    return res;
  }

  async rotateAgentKey(agent) {
    const newKey = generateSigningKey();
    const res = await this.call(`${agent.registry.url}/v1/registrations/${agent.registrationId}/rotate-key`, { agent_jwk: publicOf(newKey.publicJwk) });
    agent.rekey(newKey, res.receipt);
    return res;
  }

  async revokeAgent(agent, reason = 'principal_request') {
    return this.call(`${this.registry.url}/v1/registrations/${agent.registrationId}/revoke`, { reason });
  }

  async notifications() {
    const res = await this.call(`${this.registry.url}/v1/principals/${this.id}/notifications`, {});
    return res.notifications;
  }
}

/**
 * A human acting in a designated role (for example a compliance officer). They
 * approve with a passkey; in the simulator the passkey lives in a software
 * authenticator standing in for Face ID / Touch ID on their own device.
 */
export class Person {
  constructor({ name }) {
    this.name = name;
    this.authenticator = new SoftwareAuthenticator();
    this.passkeys = new Map(); // record keeper id -> credential id
    this.designations = [];
  }

  /** Register a passkey with a record keeper (the keeper is the WebAuthn relying party). */
  async registerPasskey(rk) {
    const opts = await postJson(`${rk.url}/v1/webauthn/registration-options`, { display_name: this.name });
    const credential = this.authenticator.create(opts.publicKey, rk.id);
    const res = await postJson(`${rk.url}/v1/webauthn/register`, { request_id: opts.request_id, credential });
    this.passkeys.set(rk.id, res.credential_id);
    return res;
  }

  /** Approve one specific action: the keeper's challenge commits to it; the passkey signs it after user verification. */
  async approve({ rk, designationId, ppid, action, subjectDigest, note }) {
    const opts = await postJson(`${rk.url}/v1/approvals/options`, { designation_id: designationId, ppid, action, subject_digest: subjectDigest, note });
    const credential = this.authenticator.get(opts.publicKey, rk.id);
    return postJson(`${rk.url}/v1/approvals`, { request_id: opts.request_id, credential });
  }
}
