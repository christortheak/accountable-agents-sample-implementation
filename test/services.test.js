// Service-level tests: persistence across restarts, and refusals that the
// scenarios do not exercise directly.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startFederationInProcess } from '../src/lib/federation.js';
import { loadKeys } from '../src/lib/trust.js';
import { postJson, getJson, postSigned, buildSignedRequest, ServiceError } from '../src/lib/http.js';
import { Principal } from '../src/actors/principal.js';
import { Agent } from '../src/actors/agent.js';
import { IdentityVerifier } from '../src/actors/authorities.js';

const tmp = () => fs.mkdtempSync(path.join(os.tmpdir(), 'aaf-test-'));

async function withFederation(dataDir, fn) {
  const fed = await startFederationInProcess({ dataDir, portOffset: 3000 });
  try {
    return await fn(fed);
  } finally {
    await fed.close();
  }
}

test('registry and record keeper state survive a restart (event-sourced from their logs)', { timeout: 30000 }, async () => {
  const dataDir = tmp();
  const saved = await withFederation(dataDir, async ({ trustList, paths }) => {
    const regA = trustList.registry('https://registry-a.aaf.test');
    const rk = trustList.recordKeeper('https://records-1.aaf.test');
    const p = new Principal({ type: 'natural_person', identity: { legal_name: 'Test Person', jurisdiction: 'US' }, registry: regA, trust: trustList });
    await p.enroll();
    await new IdentityVerifier({ id: 'https://kyc.verifier.test', keys: loadKeys('https://kyc.verifier.test', paths.keysDir) }).verify(p, { assurance: 'IAL2', method: 'test' });
    const a = new Agent({ name: 'A', trust: trustList });
    await p.registerAgent(a, { label: 'a', records: [{ role: 'authorization', rk: rk.id }] });
    const g = await p.grant(a, { rk, permissions: [{ action: 'x.read' }] });
    const ctx = await a.contextFor('rp.test');
    const sth = (await getJson(`${regA.url}/v1/transparency/sth`)).sth;
    return { ppid: ctx.ppid, grantId: g.grant_id, sth, regA };
  });
  await withFederation(dataDir, async ({ trustList }) => {
    const regA = trustList.registry('https://registry-a.aaf.test');
    const status = await postJson(`${regA.url}/v1/status`, { ppid: saved.ppid });
    assert.equal(status.status, 'active');
    const stats = await getJson(`${trustList.recordKeeper('https://records-1.aaf.test').url}/v1/stats`);
    assert.equal(stats.grants, 1);
    const sth = (await getJson(`${regA.url}/v1/transparency/sth`)).sth;
    assert.equal(JSON.parse(Buffer.from(sth.split('.')[1], 'base64url')).root_hash, JSON.parse(Buffer.from(saved.sth.split('.')[1], 'base64url')).root_hash);
  });
});

test('registries refuse unverified principals, replayed requests and foreign verifiers', { timeout: 30000 }, async () => {
  await withFederation(tmp(), async ({ trustList }) => {
    const regA = trustList.registry('https://registry-a.aaf.test');
    const p = new Principal({ type: 'legal_person', identity: { legal_name: 'Unverified LLC', jurisdiction: 'US' }, registry: regA, trust: trustList });
    await p.enroll();
    const a = new Agent({ name: 'A', trust: trustList });
    await assert.rejects(p.registerAgent(a, { label: 'a', records: [] }), (e) => e instanceof ServiceError && e.code === 'principal_not_verified');

    const url = `${regA.url}/v1/principals/${p.id}/disclosure-policy`;
    const signed = buildSignedRequest('PUT', url, { policy: { identity: { audiences: [], claims: [] } } }, p.key, { keyid: `principal:${p.id}` });
    const first = await fetch(url, { method: 'PUT', ...signed });
    assert.equal(first.status, 200);
    const replay = await fetch(url, { method: 'PUT', ...signed });
    assert.equal((await replay.json()).error, 'replayed_request');
    // A signature over one URL cannot be replayed against another.
    const elsewhere = await fetch(`${regA.url}/v1/principals/${p.id}/notifications`, { method: 'POST', ...signed });
    assert.equal(elsewhere.status, 401);

    // The principal's own key cannot pose as an identity verifier.
    await assert.rejects(
      postSigned(`${regA.url}/v1/principals/${p.id}/verification`, { principal_id: p.id }, p.key, { keyid: 'verifier:https://kyc.verifier.test' }),
      (e) => e.code === 'bad_signature',
    );
  });
});
