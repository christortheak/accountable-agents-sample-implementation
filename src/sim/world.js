// The simulated world shared by scenarios: the federation's services, the
// authorities, and helpers for creating principals, agents and counterparties.
import { loadKeys } from '../lib/trust.js';
import { getJson, postJson } from '../lib/http.js';
import { decodeJws, verifyJws } from '../lib/crypto.js';
import { buildPresentationRequest } from '../lib/presentation.js';
import { verifyReceipt } from '../lib/log.js';
import { Principal, Person } from '../actors/principal.js';
import { Agent } from '../actors/agent.js';
import { AgentProvider, IdentityVerifier, DesignatedAuthority } from '../actors/authorities.js';
import { startCounterparty } from '../counterparty/server.js';

export function createWorld({ trust, keysDir }) {
  const regA = trust.directory('https://directory-a.aaf.test');
  const regB = trust.directory('https://directory-b.aaf.test');
  const ledgerline = trust.recordsService('https://records-1.aaf.test'); // authorization + provenance
  const tessera = trust.recordsService('https://records-2.aaf.test'); // activity
  const authorityEntry = (id) => trust.authority(id, 'designated-authority');
  const counterparties = [];

  const world = {
    trust,
    keysDir,
    regA,
    regB,
    ledgerline,
    tessera,
    kyc: new IdentityVerifier({ id: 'https://kyc.verifier.test', keys: loadKeys('https://kyc.verifier.test', keysDir) }),
    court: new DesignatedAuthority({ id: 'https://court.sdny.test', name: authorityEntry('https://court.sdny.test').name, keys: loadKeys('https://court.sdny.test', keysDir) }),
    regulator: new DesignatedAuthority({ id: 'https://fincen.test', name: authorityEntry('https://fincen.test').name, keys: loadKeys('https://fincen.test', keysDir) }),

    /** Standard record pointers: authorization + provenance at Ledgerline, activity at Tessera. */
    records(provenanceId) {
      return [
        { role: 'authorization', rs: ledgerline.id },
        ...(provenanceId ? [{ role: 'provenance', rs: ledgerline.id, ref: provenanceId }] : []),
        { role: 'activity', rs: tessera.id },
      ];
    },

    /** Enroll a principal and have the identity verifier verify it. */
    async verifiedPrincipal({ type, identity, directory = regA, assurance, method, attributes = [], contact }) {
      const p = new Principal({ type, identity, directory, trust, contact });
      await p.enroll();
      let v;
      try {
        v = await world.kyc.verify(p, { assurance, method, attributes });
      } catch (err) {
        // A directory keeps one principal record per verified identity. When the
        // simulator is run again against services that are still running, its
        // characters already have records whose keys are gone, so the operator
        // closes the old record (the lost-key procedure) and verifies the new one.
        if (err.code !== 'duplicate_identity') throw err;
        await postJson(`${directory.url}/admin/principals/${err.details.existing_principal}/close`, { reason: 'simulation rerun' }, { authorization: `Bearer ${loadKeys(directory.id, keysDir).adminToken}` });
        v = await world.kyc.verify(p, { assurance, method, attributes });
      }
      p.verification = v;
      return p;
    },

    agent(name) {
      return new Agent({ name, trust });
    },

    person(name) {
      return new Person({ name });
    },

    provider(name, contact) {
      return new AgentProvider({ name, contact });
    },

    async counterparty(opts) {
      const counterparty = await startCounterparty({ trust, ...opts });
      counterparties.push(counterparty);
      return counterparty;
    },

    async close() {
      await Promise.all(counterparties.map((counterparty) => counterparty.close()));
    },

    /** Verify a log receipt against the records service's published key (and optionally the entry). */
    verifyReceipt(receipt, entry) {
      const rs = trust.recordsService(receipt.log_id) ?? trust.directory(receipt.log_id);
      return verifyReceipt(receipt, trust.signingKey(rs), entry ? { entry } : {});
    },

    /** A request made without the agent SDK: no presentation, or a hand-built one. */
    async rawRequest(counterpartyUrl, action, params = {}, headers = {}) {
      const res = await fetch(`${counterpartyUrl}/actions/${action}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify(params),
      });
      return { httpStatus: res.status, ...(await res.json()) };
    },

    /** Send a presentation built by hand (forged, replayed or intercepted), signed with signingKey. */
    async handBuiltRequest({ counterparty, action, params = {}, accountability, authorization, proofKey }) {
      const url = `${counterparty.url}/actions/${action}`;
      const { body, headers } = buildPresentationRequest({ url, counterpartyId: counterparty.id, params, accountability, authorization, key: proofKey });
      const res = await fetch(url, { method: 'POST', headers, body });
      return { httpStatus: res.status, ...(await res.json()) };
    },

    async directorySth(directory) {
      const { sth } = await getJson(`${directory.url}/v1/transparency/sth`);
      return verifyJws(sth, trust.signingKey(directory), { typ: 'aaf-sth+jwt' }).payload;
    },
  };
  return world;
}

export const payloadOf = (jws) => decodeJws(String(jws).split('~')[0]).payload;
export const money = (value, currency = 'USD') => ({ value, currency });
export const short = (s, n = 18) => (s && s.length > n ? `${s.slice(0, n)}…` : s);
