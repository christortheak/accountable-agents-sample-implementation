// Requirements from the paper's Appendix A that have their own behavior here:
// PV-3 (one record per verified identity), AG-2 (the agent proves it holds its
// key), PR-1/PR-5/PR-10 (the ID alone is a valid presentation; more on request),
// RV-1 (revocation under a legal order), DR-1 (published practices), and a
// counterparty's choice of which directories to accept.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startFederationInProcess } from '../src/lib/federation.js';
import { loadKeys } from '../src/lib/trust.js';
import { decodeJws, generateSigningKey, publicOf, signJws, nowSeconds } from '../src/lib/crypto.js';
import { postJson, getJson, ServiceError } from '../src/lib/http.js';
import { issueSdJwt, sd, sdPad, splitSdJwt, verifySdJwt } from '../src/lib/sd-jwt.js';
import { Principal } from '../src/actors/principal.js';
import { Agent } from '../src/actors/agent.js';
import { IdentityVerifier, DesignatedAuthority } from '../src/actors/authorities.js';
import { TYP, AGENT_PROOF_PURPOSE, ORDER_SCOPE_REVOKE, identityKey } from '../src/directory/directory.js';
import { startCounterparty } from '../src/counterparty/server.js';

const REG_A = 'https://directory-a.aaf.test';
const REG_B = 'https://directory-b.aaf.test';
const KYC = 'https://kyc.verifier.test';
const COURT = 'https://court.sdny.test';

let fed; let trust; let regA; let rs; let kyc; let court; let adminToken;
const counterparties = [];
const records = () => [{ role: 'authorization', rs: rs.id }];

before(async () => {
  fed = await startFederationInProcess({ dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'aaf-test-')), portOffset: 9000 });
  trust = fed.trustList;
  regA = trust.directory(REG_A);
  rs = trust.recordsService('https://records-1.aaf.test');
  kyc = new IdentityVerifier({ id: KYC, keys: loadKeys(KYC, fed.paths.keysDir) });
  court = new DesignatedAuthority({ id: COURT, name: 'court', keys: loadKeys(COURT, fed.paths.keysDir) });
  adminToken = loadKeys(REG_A, fed.paths.keysDir).adminToken;
});
after(async () => {
  await Promise.all(counterparties.map((counterparty) => counterparty.close()));
  await fed.close();
});

const code = (c) => (e) => e instanceof ServiceError && e.code === c;

async function principal(identity, { type = 'legal_person', directory = regA, verify = true } = {}) {
  const p = new Principal({ type, identity, directory, trust });
  await p.enroll();
  if (verify) await kyc.verify(p, { assurance: type === 'natural_person' ? 'IAL2' : 'high', method: 'test' });
  return p;
}

async function agentOf(p, name, grant = { permissions: [{ action: 'commerce.purchase' }] }) {
  const a = new Agent({ name, trust });
  await p.registerAgent(a, { label: name, records: records() });
  if (grant) await p.grant(a, { rs, ...grant });
  return a;
}

async function shop(opts) {
  const counterparty = await startCounterparty({ trust, handlers: { 'commerce.purchase': async () => ({ ok: true }) }, ...opts });
  counterparties.push(counterparty);
  return counterparty;
}

test('PV-3: one verified identity has one principal record; a closed record frees the identity and keeps its history', { timeout: 30000 }, async () => {
  const identity = { legal_name: 'Acme Robotics Ltd', jurisdiction: 'US-DE', registration_number: 'DE-4471' };
  const first = await principal(identity);
  const agent = await agentOf(first, 'acme-agent');
  const before = await agent.contextFor('counterparty.example');

  // The same company, spelled differently, enrolling again: refused when its identity is verified.
  const second = await principal({ ...identity, legal_name: 'ACME Robotics, Limited' }, { verify: false });
  await assert.rejects(kyc.verify(second, { assurance: 'high', method: 'test' }), (e) => code('duplicate_identity')(e) && e.details.existing_principal === first.id);
  // A different company is unaffected, and re-verifying the same record is not a duplicate.
  await principal({ legal_name: 'Other Robotics Ltd', jurisdiction: 'US-DE', registration_number: 'DE-9000' });
  await kyc.verify(first, { assurance: 'high', method: 'renewal' });

  // Only the operator may close a record.
  await assert.rejects(postJson(`${regA.url}/admin/principals/${first.id}/close`, {}), code('admin_only'));
  const closed = await postJson(`${regA.url}/admin/principals/${first.id}/close`, { reason: 'lost key' }, { authorization: `Bearer ${adminToken}` });
  assert.equal(closed.status, 'closed');
  assert.equal(closed.registrations_suspended, 1);
  await kyc.verify(second, { assurance: 'high', method: 'test' });

  // The closed record's agent stops working, but an ID it used can still be attributed (ES-1).
  await assert.rejects(agent.contextFor('other-counterparty.example'), code('registration_inactive'));
  const order = court.order({ caseId: 'test', aaf_ids: [before.aaf_id], requester: 'test' });
  const res = await court.trace(regA, { order, aaf_id: before.aaf_id });
  assert.equal(res.result.principal.principal_id, first.id);
  assert.equal(res.result.id_status, 'suspended');

  // The sample key: entities by registration number, people by name, jurisdiction and date of birth.
  assert.equal(identityKey('legal_person', identity), identityKey('legal_person', { ...identity, legal_name: 'anything' }));
  assert.notEqual(identityKey('natural_person', { legal_name: 'Ann Lee', jurisdiction: 'US', date_of_birth: '1990-01-01' }), identityKey('natural_person', { legal_name: 'Ann Lee', jurisdiction: 'US', date_of_birth: '1991-01-01' }));
  assert.equal(identityKey('natural_person', { legal_name: ' ann  LEE ', jurisdiction: 'us' }), identityKey('natural_person', { legal_name: 'Ann Lee', jurisdiction: 'US' }));
});

test('AG-2: an agent is registered only with proof that it holds its key, made for this registrant', { timeout: 30000 }, async () => {
  const p = await principal({ legal_name: 'Proof Co', jurisdiction: 'US', registration_number: 'P-1' });
  const other = await principal({ legal_name: 'Other Proof Co', jurisdiction: 'US', registration_number: 'P-2' });
  const key = generateSigningKey();
  const register = (extra) => p.call(`${regA.url}/v1/registrations`, { agent_jwk: publicOf(key.publicJwk), parent: { type: 'principal' }, records: records(), label: 'x', ...extra });
  const proof = (claims, signer = key) => signJws({ aud: REG_A, purpose: AGENT_PROOF_PURPOSE.registration, binding: `principal:${p.id}`, agent_key: key.kid, iat: nowSeconds(), ...claims }, signer, { typ: TYP.agentProof });

  await assert.rejects(register({}), code('agent_proof_required'));
  // Signed by some other key (the principal names a key it does not hold).
  await assert.rejects(register({ agent_proof: proof({}, generateSigningKey()) }), code('invalid_agent_proof'));
  // Made for another registrant, another directory, another purpose, or long ago.
  await assert.rejects(register({ agent_proof: proof({ binding: `principal:${other.id}` }) }), code('invalid_agent_proof'));
  await assert.rejects(register({ agent_proof: proof({ aud: REG_B }) }), code('invalid_agent_proof'));
  await assert.rejects(register({ agent_proof: proof({ purpose: AGENT_PROOF_PURPOSE.rotation }) }), code('invalid_agent_proof'));
  await assert.rejects(register({ agent_proof: proof({ iat: nowSeconds() - 3600 }) }), code('invalid_agent_proof'));
  const ok = await register({ agent_proof: proof({}) });
  assert.match(ok.registration_id, /^reg_/);

  // Replacing a key needs the same proof from the new key.
  await assert.rejects(p.call(`${regA.url}/v1/registrations/${ok.registration_id}/rotate-key`, { agent_jwk: publicOf(generateSigningKey().publicJwk) }), code('agent_proof_required'));
  const a = await agentOf(p, 'rotating', null);
  await p.rotateAgentKey(a);
  await a.contextFor('counterparty.example');
});

test('PR-1, PR-5, PR-10: the ID alone is a valid presentation; a counterparty asks for more, and sets its own criteria', { timeout: 30000 }, async () => {
  const org = await principal({ legal_name: 'Quiet Org', jurisdiction: 'US', registration_number: 'Q-1' });
  const person = await principal({ legal_name: 'Pat Quiet', jurisdiction: 'US', date_of_birth: '1980-02-02' }, { type: 'natural_person' });
  const orgAgent = await agentOf(org, 'org-agent');
  const personAgent = await agentOf(person, 'person-agent');

  const open = await shop({ id: 'open-shop.example', name: 'Open shop', rules: { 'commerce.purchase': [{ label: 'any accountable agent', require: { accountability: 'established', authorization: true } }] } });
  const r1 = await orgAgent.act(open.url, 'commerce.purchase', {});
  assert.equal(r1.decision, 'allow');
  const ev = open.evidence.at(-1);
  // The shop asked for nothing, so it learned the ID and the directory, and nothing about the principal or the chain.
  assert.match(ev.aaf_id, /^aaf:directory-a\.aaf\.test:p_/);
  assert.equal(ev.id_mode, 'pairwise');
  assert.deepEqual(ev.principal, { type: null, trust_framework: null, assurance: null, verifier: null, directory: null, identity: null });
  assert.equal(ev.chain_length, null);
  assert.equal(splitSdJwt(r1.presentation.accountability).disclosures.length, 0);

  // Two different principals' credentials carry the same number of digests (decoy padding).
  const shape = (agentResult) => {
    const body = decodeJws(splitSdJwt(agentResult.presentation.accountability).jwt).payload;
    return [body.accountability._sd.length, body.accountability.attributes.length, body.records.length];
  };
  await org.setDisclosurePolicy({ identity: { audiences: ['open-shop.example'], claims: ['legal_name', 'registration_number'] }, attributes: [] });
  orgAgent.contexts.clear();
  const r1b = await orgAgent.act(open.url, 'commerce.purchase', {});
  const r2 = await personAgent.act(open.url, 'commerce.purchase', {});
  assert.deepEqual(shape(r1b), shape(r2));
  assert.equal(open.evidence.at(-2).principal.identity, null, 'identity is not volunteered when the shop does not ask for it');

  // A stricter counterparty: organizations only, proofed to "high", at most one link. Its tier's needs are asked for and shown.
  const strict = await shop({
    id: 'strict-shop.example', name: 'Strict shop',
    rules: { 'commerce.purchase': [{ label: 'organizations only', require: { accountability: 'established', authorization: true, principalType: 'legal_person', assurance: ['high'], maxChainLength: 1 } }] },
  });
  const s1 = await orgAgent.act(strict.url, 'commerce.purchase', {});
  assert.equal(s1.decision, 'allow');
  const sev = strict.evidence.at(-1);
  assert.equal(sev.principal.type, 'legal_person');
  assert.equal(sev.principal.assurance, 'high');
  assert.equal(sev.chain_length, 1);
  assert.equal(sev.principal.verifier, null, 'not asked for, so not shown');
  // An agent that withholds what the tier needs is asked for it; it is not refused outright.
  const s2 = await orgAgent.act(strict.url, 'commerce.purchase', {}, { disclose: { principal_type: false } });
  assert.equal(s2.decision, 'step_up');
  assert.deepEqual(s2.missing_claims, ['principal_type']);
  // A natural person does not meet this shop's criteria.
  const s3 = await personAgent.act(strict.url, 'commerce.purchase', {});
  assert.equal(s3.decision, 'deny');
  assert.match(s3.reasons.join(' '), /only legal person principals/);
  // A sub-agent is one link too many here.
  await org.grant(orgAgent, { rs, permissions: [{ action: 'commerce.purchase' }], delegation: { allowed: true, max_depth: 1 } });
  const sub = new Agent({ name: 'sub', trust });
  await orgAgent.registerSubagent(sub, { label: 'sub', records: records() });
  await orgAgent.delegate(sub, { permissions: [{ action: 'commerce.purchase' }] });
  const s4 = await sub.act(strict.url, 'commerce.purchase', {});
  assert.equal(s4.decision, 'deny');
  assert.match(s4.reasons.join(' '), /chains longer than 1/);

  // A counterparty chooses which directories it accepts.
  const euOnly = await shop({ id: 'eu-shop.example', name: 'EU shop', acceptedDirectories: [REG_B], rules: { 'commerce.purchase': [{ label: 'standard', require: { accountability: 'established', authorization: true } }] } });
  assert.deepEqual((await getJson(`${euOnly.url}/.well-known/aaf-counterparty`)).accepted_directories, [REG_B]);
  const e1 = await orgAgent.act(euOnly.url, 'commerce.purchase', {});
  assert.equal(e1.decision, 'deny');
  assert.equal(e1.classification, 'UNSUPPORTED');
  assert.match(e1.reasons.join(' '), /does not accept IDs from https:\/\/directory-a/);
});

test('SD-JWT decoy digests hide how many claims are disclosable and are ignored on verification', () => {
  const key = generateSigningKey();
  const issue = (claims) => issueSdJwt({ box: sdPad({ fixed: 1, ...claims }, 6), list: sdPad([], 3) }, key, { typ: 'x' });
  const few = issue({ a: sd('1') });
  const many = issue({ a: sd('1'), b: sd('2'), c: sd('3') });
  const body = (t) => decodeJws(splitSdJwt(t).jwt).payload;
  assert.equal(body(few).box._sd.length, 6);
  assert.equal(body(many).box._sd.length, 6);
  assert.equal(body(few).list.length, 3);
  assert.deepEqual(verifySdJwt(many, publicOf(key.publicJwk), { typ: 'x' }).payload, { box: { fixed: 1, a: '1', b: '2', c: '3' }, list: [] });
  assert.deepEqual(verifySdJwt(`${splitSdJwt(few).jwt}~`, publicOf(key.publicJwk), { typ: 'x' }).payload, { box: { fixed: 1 }, list: [] });
});

test('RV-1: a legal order with the revoke scope revokes the agent behind an ID, and its sub-agents', { timeout: 30000 }, async () => {
  const p = await principal({ legal_name: 'Ordered Co', jurisdiction: 'US', registration_number: 'O-1' });
  const a = await agentOf(p, 'ordered', { permissions: [{ action: 'commerce.purchase' }], delegation: { allowed: true, max_depth: 1 } });
  const child = new Agent({ name: 'ordered-child', trust });
  await a.registerSubagent(child, { label: 'child', records: records() });
  const ctx = await a.contextFor('counterparty.example');
  const single = await a.contextFor('counterparty.example', { mode: 'unlinkable' });

  // An order to identify does not authorize revocation, and an order must name the ID.
  const identifyOnly = court.order({ caseId: 'c-1', aaf_ids: [ctx.aaf_id], requester: 'test' });
  await assert.rejects(court.revoke(regA, { order: identifyOnly, aaf_id: ctx.aaf_id }), code('not_in_scope'));
  const elsewhere = court.order({ caseId: 'c-1', aaf_ids: ['aaf:directory-a.aaf.test:p_other'], requester: 'test', scope: [ORDER_SCOPE_REVOKE] });
  await assert.rejects(court.revoke(regA, { order: elsewhere, aaf_id: ctx.aaf_id }), code('not_covered'));
  // An order from someone who is not a designated authority is refused.
  const impostor = new DesignatedAuthority({ id: COURT, name: 'impostor', keys: { signing: generateSigningKey() } });
  await assert.rejects(impostor.revoke(regA, { order: impostor.order({ caseId: 'c-1', aaf_ids: [ctx.aaf_id], requester: 'x', scope: [ORDER_SCOPE_REVOKE] }), aaf_id: ctx.aaf_id }), code('invalid_order'));

  // A single-use ID needs the sealed reference the counterparty kept.
  const order = court.order({ caseId: 'State v. Ordered Co', aaf_ids: [single.aaf_id], requester: 'test', scope: [ORDER_SCOPE_REVOKE] });
  await assert.rejects(court.revoke(regA, { order, aaf_id: single.aaf_id }), code('sealed_ref_required'));
  const sealedRef = decodeJws(splitSdJwt(single.attestation).jwt).payload.sealed_ref;
  const res = await court.revoke(regA, { order, aaf_id: single.aaf_id, sealedRef });
  assert.equal(res.status, 'revoked');
  assert.equal(res.reason, 'legal_order');
  assert.equal(res.cascades_to, 1);
  assert.equal(res.authority, COURT);

  await assert.rejects(a.contextFor('another.example'), code('registration_inactive'));
  await assert.rejects(child.contextFor('another.example'), code('registration_inactive'));
  const note = (await p.notifications()).find((n) => n.kind === 'revocation_order');
  assert.equal(note.case, 'State v. Ordered Co');
  assert.equal((await court.revoke(regA, { order, aaf_id: single.aaf_id, sealedRef })).already, true);

  // After an agent changes hands, an ID from the earlier relationship cannot be used to revoke it from its new principal.
  const seller = await principal({ legal_name: 'Seller Co', jurisdiction: 'US', registration_number: 'S-1' });
  const buyer = await principal({ legal_name: 'Buyer Co', jurisdiction: 'US', registration_number: 'B-1' });
  const sold = await agentOf(seller, 'sold', null);
  const old = await sold.contextFor('counterparty.example');
  const offer = await seller.offerTransfer(sold, buyer);
  await buyer.acceptTransfer(offer.offer_id, sold);
  const stale = court.order({ caseId: 'c-2', aaf_ids: [old.aaf_id], requester: 'test', scope: [ORDER_SCOPE_REVOKE] });
  await assert.rejects(court.revoke(regA, { order: stale, aaf_id: old.aaf_id }), code('custody_changed'));
  await sold.contextFor('counterparty.example');
});

test('DR-1: each directory publishes its practices, in its entity configuration and at /v1/practices', async () => {
  const practices = await getJson(`${regA.url}/v1/practices`);
  assert.deepEqual(practices.identity_proofing.verified_identities, ['natural_person', 'legal_person']);
  assert.deepEqual(practices.identity_proofing.identity_verifiers, [KYC]);
  assert.ok(practices.disclosure.attribution.authorities.includes(COURT));
  assert.equal(practices.ids.validity_seconds, trust.policies.attestationTtlSeconds);
  assert.equal(practices.revocation.latency_seconds.bound, trust.policies.revocationIntervalSeconds);
  assert.equal(practices.records.retention_years, trust.policies.recordRetentionYears);
  assert.equal(practices.records.kept_after_revocation, true);
  for (const section of ['authentication', 'revocation', 'records', 'disclosure', 'signing_keys', 'security']) assert.ok(practices[section], section);
  const ec = decodeJws(await (await fetch(`${regA.url}/.well-known/openid-federation`)).text()).payload;
  assert.deepEqual(ec.metadata.aaf_directory.practices, practices);
  assert.deepEqual(ec.metadata.aaf_directory.id_modes, ['pairwise', 'unlinkable']);
});
