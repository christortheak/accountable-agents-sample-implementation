// The pilot kit: the HTTPS fix, the aaf command-line tool and the standalone relying party.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { execFile } from 'node:child_process';
import { promisify } from 'node:util';
import { fileURLToPath } from 'node:url';
import { buildSignedRequest, createSignatureVerifier } from '../src/lib/http.js';
import { generateSigningKey } from '../src/lib/crypto.js';

const ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '..');
const run = promisify(execFile);

test('behind a TLS proxy, services verify signatures against their public URL', async () => {
  const key = generateSigningKey();
  const signed = buildSignedRequest('POST', 'https://registry.example.org/v1/things', { a: 1 }, key, { embedJwk: true });
  const ctx = (headers) => ({ req: { method: 'POST', url: '/v1/things' }, headers: { ...headers, host: '127.0.0.1:4101' }, rawBody: signed.body, body: JSON.parse(signed.body) });
  const behindProxy = createSignatureVerifier({ publicBaseUrl: 'https://registry.example.org' });
  assert.ok((await behindProxy(ctx(signed.headers), () => null)).thumbprint);
  const naive = createSignatureVerifier();
  await assert.rejects(naive(ctx(signed.headers), () => null), /verification failed/);
});

test('aaf CLI and standalone relying party, end to end', { timeout: 90000 }, async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aaf-pilot-'));
  const home = fs.mkdtempSync(path.join(os.tmpdir(), 'aaf-home-'));
  process.env.AAF_DATA_DIR = dataDir;
  const { startFederationInProcess } = await import('../src/lib/federation.js');
  const { startStandaloneRp } = await import('../src/rp/standalone.js');
  const fed = await startFederationInProcess({ dataDir, portOffset: 7000 });
  const shopConfig = JSON.parse(fs.readFileSync(path.join(ROOT, 'config/rp.local.json'), 'utf8'));
  const shop = await startStandaloneRp({ ...shopConfig, port: 0, trustAnchor: { url: fed.trustAnchor.url } }, { quiet: true });
  const env = { ...process.env, AAF_HOME: home, AAF_DATA_DIR: dataDir };
  const aaf = async (...args) => (await run(process.execPath, [path.join(ROOT, 'src/cli/aaf.js'), ...args], { env })).stdout;
  try {
    assert.match(await aaf('init', '--local'), /Joined/);
    assert.match(await aaf('enroll', '--name', 'Test Author'), /verification pending/);
    assert.match(await aaf('operator', 'verify', path.join(home, 'verification-request.json')), /Verified Test Author/);
    await aaf('agent', 'register', 'helper');
    await aaf('grant', 'helper', 'commerce.purchase', '--max-amount', '50:USD');
    const small = JSON.parse(await aaf('act', 'helper', shop.url, 'commerce.purchase', '--params', '{"amount":{"value":12,"currency":"USD"}}', '--json'));
    assert.equal(small.decision, 'allow');
    assert.equal(small.classification, 'ACCOUNTABLE_PROTECTED');
    const large = JSON.parse(await aaf('act', 'helper', shop.url, 'commerce.purchase', '--params', '{"amount":{"value":30,"currency":"USD"}}', '--json'));
    assert.equal(large.decision, 'step_up');
    await aaf('disclose', '--to', shopConfig.id, '--claims', 'legal_name');
    const disclosed = JSON.parse(await aaf('act', 'helper', shop.url, 'commerce.purchase', '--params', '{"amount":{"value":30,"currency":"USD"}}', '--json'));
    assert.equal(disclosed.classification, 'ACCOUNTABLE_DISCLOSED');
    const resolved = JSON.parse(await aaf('operator', 'resolve', small.ppid, '--case', 'test', '--rp', shopConfig.id));
    assert.equal(resolved.root_principal.identity.legal_name, 'Test Author');
    assert.match(await aaf('revoke', 'helper', '--reason', 'compromised'), /revoked/);
    await assert.rejects(aaf('act', 'helper', shop.url, 'commerce.purchase', '--params', '{"amount":{"value":5,"currency":"USD"}}'), /revoked/);
    const page = await (await fetch(shop.url)).text();
    assert.match(page, /ACCOUNTABLE_DISCLOSED/);
  } finally {
    await shop.close();
    await fed.close();
  }
});
