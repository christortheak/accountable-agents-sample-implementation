// The simulated world shared by scenarios: the federation's services, the
// authorities, and helpers for creating principals, agents and relying parties.
import { loadKeys } from '../lib/trust.js';
import { getJson } from '../lib/http.js';
import { decodeJws, verifyJws } from '../lib/crypto.js';
import { buildPresentationRequest } from '../lib/presentation.js';
import { verifyReceipt } from '../lib/log.js';
import { Principal, Person } from '../actors/principal.js';
import { Agent } from '../actors/agent.js';
import { AgentProvider, IdentityVerifier, ResolutionAuthority } from '../actors/authorities.js';
import { startRelyingParty } from '../rp/server.js';

export function createWorld({ trust, keysDir }) {
  const regA = trust.registry('https://registry-a.aaf.test');
  const regB = trust.registry('https://registry-b.aaf.test');
  const ledgerline = trust.recordKeeper('https://records-1.aaf.test'); // authorization + provenance
  const tessera = trust.recordKeeper('https://records-2.aaf.test'); // activity
  const authorityEntry = (id) => trust.authority(id, 'resolution-authority');
  const relyingParties = [];

  const world = {
    trust,
    keysDir,
    regA,
    regB,
    ledgerline,
    tessera,
    kyc: new IdentityVerifier({ id: 'https://kyc.verifier.test', keys: loadKeys('https://kyc.verifier.test', keysDir) }),
    court: new ResolutionAuthority({ id: 'https://court.sdny.test', name: authorityEntry('https://court.sdny.test').name, keys: loadKeys('https://court.sdny.test', keysDir) }),
    regulator: new ResolutionAuthority({ id: 'https://fincen.test', name: authorityEntry('https://fincen.test').name, keys: loadKeys('https://fincen.test', keysDir) }),

    /** Standard record pointers: authorization + provenance at Ledgerline, activity at Tessera. */
    records(provenanceId) {
      return [
        { role: 'authorization', rk: ledgerline.id },
        ...(provenanceId ? [{ role: 'provenance', rk: ledgerline.id, ref: provenanceId }] : []),
        { role: 'activity', rk: tessera.id },
      ];
    },

    /** Enroll a principal and have the identity verifier verify it. */
    async verifiedPrincipal({ type, identity, registry = regA, assurance, method, attributes = [], contact }) {
      const p = new Principal({ type, identity, registry, trust, contact });
      await p.enroll();
      const v = await world.kyc.verify(p, { assurance, method, attributes });
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

    async relyingParty(opts) {
      const rp = await startRelyingParty({ trust, ...opts });
      relyingParties.push(rp);
      return rp;
    },

    async close() {
      await Promise.all(relyingParties.map((rp) => rp.close()));
    },

    /** Verify a log receipt against the record keeper's published key (and optionally the entry). */
    verifyReceipt(receipt, entry) {
      const rk = trust.recordKeeper(receipt.log_id) ?? trust.registry(receipt.log_id);
      return verifyReceipt(receipt, trust.signingKey(rk), entry ? { entry } : {});
    },

    /** A request made without the agent SDK: no presentation, or a hand-built one. */
    async rawRequest(rpUrl, action, params = {}, headers = {}) {
      const res = await fetch(`${rpUrl}/actions/${action}`, {
        method: 'POST',
        headers: { 'content-type': 'application/json', ...headers },
        body: JSON.stringify(params),
      });
      return { httpStatus: res.status, ...(await res.json()) };
    },

    /** Send a presentation built by hand (forged, replayed or intercepted), signed with signingKey. */
    async handBuiltRequest({ rp, action, params = {}, accountability, authorization, proofKey }) {
      const url = `${rp.url}/actions/${action}`;
      const { body, headers } = buildPresentationRequest({ url, rpId: rp.id, params, accountability, authorization, key: proofKey });
      const res = await fetch(url, { method: 'POST', headers, body });
      return { httpStatus: res.status, ...(await res.json()) };
    },

    async registrySth(registry) {
      const { sth } = await getJson(`${registry.url}/v1/transparency/sth`);
      return verifyJws(sth, trust.signingKey(registry), { typ: 'aaf-sth+jwt' }).payload;
    },
  };
  return world;
}

export const payloadOf = (jws) => decodeJws(String(jws).split('~')[0]).payload;
export const money = (value, currency = 'USD') => ({ value, currency });
export const short = (s, n = 18) => (s && s.length > n ? `${s.slice(0, n)}…` : s);
