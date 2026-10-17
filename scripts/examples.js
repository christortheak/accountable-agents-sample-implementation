// Generate decoded example artifacts for the specification (spec/examples/)
// from a real run against a throwaway federation.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startFederationInProcess } from '../src/lib/federation.js';
import { PROJECT_ROOT, loadKeys } from '../src/lib/trust.js';
import { b64u, decodeJws, signJws, nowSeconds, randomId } from '../src/lib/crypto.js';
import { unpackSdJwt } from '../src/lib/sd-jwt.js';
import { identityVerifiedClaims } from '../src/lib/ida.js';
import { WELL_KNOWN } from '../src/lib/openid-federation.js';
import { Principal } from '../src/actors/principal.js';
import { Agent } from '../src/actors/agent.js';
import { IdentityVerifier, ResolutionAuthority, AgentProvider } from '../src/actors/authorities.js';
import { startRelyingParty } from '../src/rp/server.js';
import { TOKEN_EXCHANGE } from '../src/recordkeeper/recordkeeper.js';

const out = path.join(PROJECT_ROOT, 'spec', 'examples');
fs.rmSync(out, { recursive: true, force: true });
fs.mkdirSync(out, { recursive: true });
const write = (name, value) => fs.writeFileSync(path.join(out, `${name}.json`), JSON.stringify(value, null, 2) + '\n');
const jws = (token) => {
  const { header, payload } = decodeJws(token);
  return { header, payload };
};
const truncate = (s, n = 40) => (s.length > n ? `${s.slice(0, n)}…` : s);
const sdView = (combined) => {
  const parts = combined.split('~');
  const kb = parts.at(-1).includes('.') ? parts.at(-1) : null;
  return {
    issuer_signed: jws(parts[0]),
    disclosures: parts.slice(1, kb ? -1 : undefined).filter(Boolean).map((d) => ({ encoded: truncate(d, 24), decoded: b64u.decodeJson(d) })),
    ...(kb ? { key_binding_jwt: jws(kb) } : {}),
  };
};
const statusListView = (token) => {
  const v = jws(token);
  v.payload.status_list.lst = truncate(v.payload.status_list.lst);
  return v;
};
const fetchText = async (url) => (await fetch(url)).text();

const fed = await startFederationInProcess({ dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'aaf-ex-')), portOffset: 4000 });
try {
  const t = fed.trustList;
  const regA = t.registry('https://registry-a.aaf.test');
  const rk1 = t.recordKeeper('https://records-1.aaf.test');
  const kyc = new IdentityVerifier({ id: 'https://kyc.verifier.test', keys: loadKeys('https://kyc.verifier.test', fed.paths.keysDir) });
  const court = new ResolutionAuthority({ id: 'https://court.sdny.test', name: 'court', keys: loadKeys('https://court.sdny.test', fed.paths.keysDir) });

  // OpenID Federation
  write('openid-federation.trust-anchor-entity-configuration', jws(await fetchText(`${t.trustAnchor.url}${WELL_KNOWN}`)));
  write('openid-federation.subordinate-statement', jws(await fetchText(`${t.trustAnchor.url}/fetch?sub=${encodeURIComponent(regA.id)}`)));
  write('openid-federation.registry-entity-configuration', jws(await fetchText(`${regA.url}${WELL_KNOWN}`)));
  const rkConfig = jws(await fetchText(`${rk1.url}${WELL_KNOWN}`));
  write('openid-federation.record-keeper-entity-configuration', { ...rkConfig, payload: { ...rkConfig.payload, trust_marks: rkConfig.payload.trust_marks.map((m) => ({ ...m, trust_mark: truncate(m.trust_mark) })) } });
  write('openid-federation.trust-mark', jws(rkConfig.payload.trust_marks[0].trust_mark));

  // Principal, verification (OIDC Identity Assurance), agent, grant (RAR)
  const org = new Principal({ type: 'legal_person', identity: { legal_name: 'Example Corp', jurisdiction: 'US-DE', registration_number: 'DE-1234567' }, registry: regA, trust: t });
  await org.enroll();
  write('oidc-ida.verified-claims', identityVerifiedClaims({ principalType: org.type, identity: org.identity, assurance: 'high', method: 'KYB: registry extract + beneficial ownership', evidenceRef: 'kyc_example' }));
  await kyc.verify(org, { assurance: 'high', method: 'KYB: registry extract + beneficial ownership', attributes: [{ name: 'insured', value: 'cyber liability ≥ $5M', source: 'Insurer (simulated)' }] });
  await org.setDisclosurePolicy({ identity: { audiences: ['shop.example'], claims: ['legal_name', 'registration_number'] }, attributes: ['insured'] });
  const { provenanceId } = await new AgentProvider({ name: 'Example Agents Inc.', contact: 'sec@agents.example' }).publishProvenance(rk1, {
    build: 'Example Agent 1.0', components: [{ type: 'model', name: 'example-model', supplier: 'Example Lab', version: '2026-09' }, { type: 'tool', name: 'browser', version: '3.1' }],
    incidentResponse: { contact: 'sec@agents.example', constrain_endpoint: 'https://agents.example/constrain' },
  });
  const agent = new Agent({ name: 'Agent', trust: t });
  const reg = await org.registerAgent(agent, { label: 'purchasing agent', records: [{ role: 'authorization', rk: rk1.id }, { role: 'provenance', rk: rk1.id, ref: provenanceId }, { role: 'activity', rk: 'https://records-2.aaf.test' }] });
  write('registration-receipt', jws(reg.receipt));
  const g = await org.grant(agent, {
    rk: rk1,
    permissions: [{ action: 'commerce.purchase', constraints: { max_amount: { value: 500, currency: 'USD' }, categories: ['office'] } }, { action: 'travel.book' }],
    prohibitions: [{ action: 'commerce.subscribe' }],
    purpose: 'Office supplies',
  });
  write('grant', jws(g.grant));

  // Presentation to a relying party
  const rp = await startRelyingParty({
    id: 'shop.example', name: 'Shop', trust: t, requests: { identity: true },
    rules: { 'commerce.purchase': [{ label: 'standard', require: { accountability: 'established', authorization: true } }] },
    handlers: { 'commerce.purchase': async () => ({ order: 'o-1' }) },
  });
  const res = await agent.act(rp.url, 'commerce.purchase', { amount: { value: 42, currency: 'USD' }, category: 'office' });
  const ctx = agent.contexts.get('shop.example');
  write('accountability-credential.issued', sdView(ctx.attestation));
  write('accountability-credential.as-seen-by-agent', unpackSdJwt(ctx.attestation).payload);
  write('authorization-credential.issued', sdView(ctx.authorization));
  const now = nowSeconds();
  const clientId = `urn:aaf:registration:${agent.registrationId}`;
  write('token-exchange.request', {
    method: 'POST', url: `${rk1.id}/token`, content_type: 'application/x-www-form-urlencoded',
    form: {
      grant_type: TOKEN_EXCHANGE.grantType,
      subject_token: truncate(g.grant), subject_token_type: TOKEN_EXCHANGE.subjectTokenType,
      actor_token: truncate(ctx.attestation), actor_token_type: TOKEN_EXCHANGE.actorTokenType,
      requested_token_type: TOKEN_EXCHANGE.requestedTokenType, audience: 'shop.example',
      client_assertion_type: TOKEN_EXCHANGE.clientAssertionType, client_assertion: '<JWT below>',
    },
    client_assertion: jws(signJws({ iss: clientId, sub: clientId, aud: `${rk1.id}/token`, iat: now, exp: now + 60, jti: randomId('ca', 12) }, agent.longTermKey, { typ: 'JWT', embedJwk: true })),
    response: { access_token: '<authorization-credential.issued>', issued_token_type: TOKEN_EXCHANGE.requestedTokenType, token_type: 'N_A', expires_in: 300 },
  });
  const received = rp.received.at(-1);
  const pres = b64u.decodeJson(received.presentation);
  write('presentation.as-received-by-relying-party', {
    http_headers: {
      'content-type': 'application/json',
      'content-digest': 'sha-256=:<base64 of SHA-256(body)>:',
      'aaf-presentation': '<base64url JSON below>',
      'signature-input': received.signatureInput,
      signature: truncate(received.signature, 30),
    },
    presentation: { v: pres.v, accountability: sdView(pres.accountability), authorization: sdView(pres.authorization) },
  });
  const ev = rp.evidence.at(-1);
  write('status-list-token.registry', statusListView(ev.status_tokens[0]));
  write('status-list-token.record-keeper', statusListView(ev.status_tokens[1]));
  write('activity-receipt', { ...ev.activity_receipt, sth: jws(ev.activity_receipt.sth) });
  write('relying-party-evidence-record', { ...ev, status_tokens: ev.status_tokens.map((s) => truncate(s, 32)) });
  write('relying-party-response', res);

  // Legal process, provenance
  const order = court.order({ caseId: 'Example v. Doe', ppids: [res.ppid], relyingParty: rp.id, requester: 'Shop', scope: ['root_principal_identity', 'chain'] });
  write('legal-order', jws(order));
  write('resolution-result', (await court.resolve(regA, { order, ppid: res.ppid })).result);
  write('provenance-record.cyclonedx', jws((await (await fetch(`${rk1.url}/v1/provenance/${provenanceId}`)).json()).record));

  // A designated officer approves with a passkey (WebAuthn at the record keeper)
  const { Person } = await import('../src/actors/principal.js');
  const officer = new Person({ name: 'Officer' });
  await officer.registerPasskey(rk1);
  const designation = await org.designate(officer, { rk: rk1, role: 'designated-officer' });
  const opts = await (await fetch(`${rk1.url}/v1/approvals/options`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ designation_id: designation.grant_id, ppid: res.ppid, action: 'commerce.purchase', subject_digest: 'example-digest' }) })).json();
  const assertion = officer.authenticator.get(opts.publicKey, rk1.id);
  const authData = b64u.decode(assertion.response.authenticatorData);
  write('webauthn.approval-ceremony', {
    options: { request_id: opts.request_id, details: opts.details, publicKey: opts.publicKey },
    assertion: {
      id: assertion.id,
      clientDataJSON: JSON.parse(b64u.decode(assertion.response.clientDataJSON).toString('utf8')),
      authenticatorData: { rpIdHash: authData.subarray(0, 32).toString('hex'), flags: { user_present: !!(authData[32] & 1), user_verified: !!(authData[32] & 4) }, signCount: authData.readUInt32BE(33) },
      signature: truncate(assertion.response.signature, 30),
    },
  });
  const approved = await (await fetch(`${rk1.url}/v1/approvals`, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify({ request_id: opts.request_id, credential: assertion }) })).json();
  write('approval-credential.issued', sdView(approved.approval));

  // Transfer between principals
  const buyer = new Principal({ type: 'legal_person', identity: { legal_name: 'Buyer Inc.', jurisdiction: 'US-NY' }, registry: regA, trust: t });
  await buyer.enroll();
  await kyc.verify(buyer, { assurance: 'high', method: 'KYB: registry extract' });
  const offer = await org.offerTransfer(agent, buyer);
  const accepted = await buyer.acceptTransfer(offer.offer_id, agent);
  write('transfer', { offer, accepted: { ...accepted, receipt: jws(accepted.receipt) } });
  await rp.close();
  console.log(`Examples written to ${path.relative(process.cwd(), out)}/`);
} finally {
  await fed.close();
}
