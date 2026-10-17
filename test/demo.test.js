// The browser demo's server, driven with a software authenticator that sends
// exactly what a browser sends from http://localhost:4300.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startFederationInProcess } from '../src/lib/federation.js';
import { startDemo } from '../src/demo/server.js';
import { SoftwareAuthenticator } from '../src/lib/webauthn.js';

test('passkey demo: register, approve the agent, replay the attack, step-up', { timeout: 60000 }, async () => {
  const federation = await startFederationInProcess({ dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'aaf-demo-test-')), portOffset: 6000 });
  const demo = await startDemo({ port: 4399, quiet: true, federation });
  const base = demo.rp.url;
  const origin = demo.origin; // http://localhost:4399, as the browser would report it
  const post = async (p, body = {}) => (await fetch(base + p, { method: 'POST', headers: { 'content-type': 'application/json' }, body: JSON.stringify(body) })).json();
  try {
    const page = await (await fetch(base + '/')).text();
    assert.match(page, /navigator\.credentials\.create/);
    const you = new SoftwareAuthenticator();
    const regOpts = await post('/accounts/victim-org/passkeys/options');
    const reg = await post('/accounts/victim-org/passkeys', { credential: you.create(regOpts.publicKey, origin) });
    assert.ok(reg.credential_id);
    const approve = async (rid) => {
      const o = await post(`/approval-requests/${rid}/options`);
      return post(`/approval-requests/${rid}/approve`, { credential: you.get(o.publicKey, origin) });
    };
    const ask = await post('/demo/agent/access');
    assert.equal(ask.decision, 'step_up');
    assert.equal((await approve(ask.approval_request.request_id)).status, 'approved');
    assert.equal((await post('/demo/agent/access')).decision, 'allow');
    const attack = await post('/demo/attack');
    assert.equal(attack.rows_read_by_attackers, 0);
    assert.equal(attack.results[0].decision, 'allow');
    assert.ok(attack.results.slice(1).every((r) => r.decision === 'deny'));
    assert.match(attack.frontier_notified, /eval-runner-1/);
    const del = await post('/demo/agent/delete', { repo: 'victim-org/old-evals' });
    assert.equal(del.decision, 'step_up');
    await approve(del.approval_request.request_id);
    assert.equal((await post('/demo/agent/delete', { repo: 'victim-org/old-evals', approval_ref: del.approval_request.request_id })).decision, 'allow');
    assert.notEqual((await post('/demo/agent/delete', { repo: 'victim-org/held-out-evals', approval_ref: del.approval_request.request_id })).decision, 'allow');
  } finally {
    await demo.close();
  }
});
