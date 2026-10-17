import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateSigningKey, generateEncryptionKey, signJws, verifyJws, sealJwe, openJwe, canonicalize } from '../src/lib/crypto.js';
import { issueSdJwt, present, verifySdJwt, sd } from '../src/lib/sd-jwt.js';
import { leafHash, treeHash, inclusionProof, verifyInclusion, consistencyProof, verifyConsistency } from '../src/lib/merkle.js';
import { MerkleLog, verifyReceipt } from '../src/lib/log.js';
import { evaluate, checkAttenuation, toRar } from '../src/lib/scope.js';
import { signRequest, verifyRequest } from '../src/lib/httpsig.js';
import { addKeyBinding } from '../src/lib/sd-jwt.js';
import { encodeStatusList, statusAt, statusListToken, verifyStatusListToken, STATUS } from '../src/lib/status-list.js';
import { b64u } from '../src/lib/crypto.js';

test('JWS sign/verify and tamper detection', () => {
  const key = generateSigningKey();
  const jws = signJws({ hello: 'world' }, key, { typ: 'test+jwt' });
  assert.deepEqual(verifyJws(jws, key.publicJwk, { typ: 'test+jwt' }).payload, { hello: 'world' });
  const [h, , s] = jws.split('.');
  const forged = `${h}.${b64u.encodeJson({ hello: 'mars' })}.${s}`;
  assert.throws(() => verifyJws(forged, key.publicJwk), /signature/);
  assert.throws(() => verifyJws(jws, generateSigningKey().publicJwk), /signature/);
});

test('JWE ECDH-ES round trip; wrong key fails', () => {
  const enc = generateEncryptionKey();
  const jwe = sealJwe({ registration: 'reg_123' }, enc.publicJwk);
  assert.deepEqual(openJwe(jwe, enc.privateJwk).payload, { registration: 'reg_123' });
  assert.throws(() => openJwe(jwe, generateEncryptionKey().privateJwk));
});

test('SD-JWT selective disclosure', () => {
  const key = generateSigningKey();
  const full = issueSdJwt(
    { iss: 'x', name: sd('Dana'), perms: [sd({ action: 'a' }), sd({ action: 'b' }), { action: 'c' }] },
    key,
  );
  const all = verifySdJwt(full, key.publicJwk).payload;
  assert.equal(all.name, 'Dana');
  assert.equal(all.perms.length, 3);
  const partial = present(full, (d) => d.value?.action === 'b');
  const shown = verifySdJwt(partial, key.publicJwk).payload;
  assert.equal(shown.name, undefined);
  assert.deepEqual(shown.perms, [{ action: 'b' }, { action: 'c' }]);
  // A disclosure from a different credential is rejected.
  const other = issueSdJwt({ name: sd('Eve') }, key);
  const foreign = other.split('~')[1];
  assert.throws(() => verifySdJwt(partial + foreign + '~', key.publicJwk), /does not match/);
});

test('Merkle inclusion and consistency proofs for many sizes', () => {
  const leaves = Array.from({ length: 33 }, (_, i) => leafHash(`entry-${i}`));
  for (let n = 1; n <= leaves.length; n++) {
    const root = b64u.encode(treeHash(leaves, 0, n));
    for (let m = 0; m < n; m++) {
      const proof = inclusionProof(leaves, m, n);
      assert.ok(verifyInclusion({ leafIndex: m, treeSize: n, leafHash: leaves[m], proof, rootHash: root }), `incl ${m}/${n}`);
    }
    for (let m = 1; m <= n; m++) {
      const proof = consistencyProof(leaves, m, n);
      const firstRoot = b64u.encode(treeHash(leaves, 0, m));
      assert.ok(verifyConsistency({ firstSize: m, secondSize: n, firstRoot, secondRoot: root, proof }), `cons ${m}->${n}`);
    }
  }
  const root = b64u.encode(treeHash(leaves, 0, 20));
  const proof = inclusionProof(leaves, 3, 20);
  assert.equal(verifyInclusion({ leafIndex: 3, treeSize: 20, leafHash: leaves[4], proof, rootHash: root }), false);
});

test('MerkleLog receipts detect rewritten history', () => {
  const key = generateSigningKey();
  const log = new MerkleLog({ logId: 'test', signer: key });
  for (let i = 0; i < 10; i++) log.append({ i });
  const receipt = log.receipt(4);
  assert.ok(verifyReceipt(receipt, key.publicJwk, { entry: { i: 4 } }).ok);
  assert.equal(verifyReceipt(receipt, key.publicJwk, { entry: { i: 5 } }).ok, false);
  log.rewriteEntry(4, { i: 'tampered' });
  assert.notEqual(log.rootHash(receipt.tree_size), JSON.parse(Buffer.from(receipt.sth.split('.')[1], 'base64url')).root_hash);
});

test('canonical JSON follows RFC 8785 (JCS)', () => {
  assert.equal(canonicalize({ b: 1, a: [{ d: 2, c: 3 }] }), canonicalize({ a: [{ c: 3, d: 2 }], b: 1 }));
  // RFC 8785 §3.2.2: numbers and string escaping.
  const input = {
    numbers: [333333333.33333329, 1e30, 4.5, 2e-3, 0.000000000000000000000000001],
    // "€$", U+000F, newline, "A'B", quote, two backslashes, quote, "/"
    string: ['€$', String.fromCharCode(0x0f), '\n', "A'B", '"', String.fromCharCode(0x5c, 0x5c), '"', '/'].join(''),
    literals: [null, true, false],
  };
  assert.equal(
    canonicalize(input),
    String.raw`{"literals":[null,true,false],"numbers":[333333333.3333333,1e+30,4.5,0.002,1e-27],"string":"€$\u000f\nA'B\"\\\\\"/"}`,
  );
  // RFC 8785 §3.2.3: members sorted by UTF-16 code units.
  const sorted = canonicalize({ '€': 'Euro Sign', '\r': 'Carriage Return', 'דּ': 'Hebrew Letter Dalet With Dagesh', '1': 'One', '😀': 'Emoji: Grinning Face', '\u0080': 'Control', 'ö': 'Latin Small Letter O With Diaeresis' });
  assert.deepEqual(
    [...sorted.matchAll(/:"([^"]+)"/g)].map((m) => m[1]),
    ['Carriage Return', 'One', 'Control', 'Latin Small Letter O With Diaeresis', 'Euro Sign', 'Emoji: Grinning Face', 'Hebrew Letter Dalet With Dagesh'],
  );
  assert.throws(() => canonicalize({ x: NaN }));
});

test('RAR authorization_details: evaluation and attenuation', () => {
  const grant = {
    authorization_details: [toRar({ action: 'commerce.purchase', constraints: { max_amount: { value: 500, currency: 'USD' }, categories: ['books'] } })],
    prohibitions: [toRar({ action: 'commerce.subscribe' })],
    delegation: { allowed: true, max_depth: 1 },
    exp: 2000,
  };
  assert.deepEqual(grant.authorization_details[0].type, 'commerce');
  assert.deepEqual(grant.authorization_details[0].actions, ['purchase']);
  const evalGrant = { permissions: grant.authorization_details, prohibitions: grant.prohibitions };
  assert.ok(evaluate(evalGrant, { action: 'commerce.purchase', params: { amount: { value: 20, currency: 'USD' }, category: 'books' } }).permitted);
  const over = evaluate(evalGrant, { action: 'commerce.purchase', params: { amount: { value: 900, currency: 'USD' }, category: 'books' } });
  assert.equal(over.permitted, false);
  assert.match(over.reasons[0], /exceeds/);
  assert.equal(evaluate(evalGrant, { action: 'commerce.subscribe' }).permitted, false);
  assert.equal(evaluate({ permissions: [{ type: 'x', unknown_rule: 1 }] }, { action: 'x.y' }).permitted, false, 'unknown constraints fail closed');
  const narrower = { authorization_details: [toRar({ action: 'commerce.purchase', constraints: { max_amount: { value: 100, currency: 'USD' }, categories: ['books'] } })], exp: 1000 };
  assert.ok(checkAttenuation(narrower, grant).ok);
  const wider = { authorization_details: [toRar({ action: 'commerce.purchase', constraints: { max_amount: { value: 1000, currency: 'USD' } } })], exp: 1000 };
  assert.equal(checkAttenuation(wider, grant).ok, false);
  const otherAction = { authorization_details: [toRar({ action: 'commerce.refund' })], exp: 1000 };
  assert.equal(checkAttenuation(otherAction, grant).ok, false);
});

test('RFC 9421 HTTP message signatures with Content-Digest', async () => {
  const key = generateSigningKey();
  const url = 'http://127.0.0.1:9999/v1/things?x=1';
  const body = JSON.stringify({ a: 1 });
  const headers = signRequest({ method: 'POST', url, body, key, keyid: 'k1', tag: 't', headers: { 'content-type': 'application/json' } });
  assert.match(headers['content-digest'], /^sha-256=:[A-Za-z0-9+/=]+:$/);
  assert.match(headers['signature-input'], /^sig1=\("@method" "@target-uri" "content-digest" "content-type"\);created=\d+;nonce="[^"]+";alg="ed25519";keyid="k1";tag="t"$/);
  const resolveKey = () => key.publicJwk;
  const ok = await verifyRequest({ method: 'POST', url, headers, body, resolveKey, tag: 't' });
  assert.equal(ok.keyid, 'k1');
  await assert.rejects(verifyRequest({ method: 'POST', url, headers, body: '{"a":2}', resolveKey }), /Content-Digest/);
  await assert.rejects(verifyRequest({ method: 'POST', url: 'http://127.0.0.1:9999/v1/other', headers, body, resolveKey }), /verification failed/);
  const replay = new Map();
  await verifyRequest({ method: 'POST', url, headers, body, resolveKey, replay });
  await assert.rejects(verifyRequest({ method: 'POST', url, headers, body, resolveKey, replay }), /nonce already used/);
});

test('SD-JWT key binding (kb+jwt)', () => {
  const issuer = generateSigningKey();
  const holder = generateSigningKey();
  const full = issueSdJwt({ cnf: { jwk: holder.publicJwk }, name: sd('Dana') }, issuer);
  const bound = addKeyBinding(present(full, () => false), holder, { aud: 'rp', nonce: 'n1' });
  assert.ok(verifySdJwt(bound, issuer.publicJwk, { keyBinding: { aud: 'rp', nonce: 'n1' } }).kb);
  assert.throws(() => verifySdJwt(bound, issuer.publicJwk, { keyBinding: { aud: 'other', nonce: 'n1' } }), /audience/);
  assert.throws(() => verifySdJwt(bound, issuer.publicJwk, { keyBinding: { aud: 'rp', nonce: 'n2' } }), /nonce/);
  // Adding a disclosure after binding breaks sd_hash.
  const tampered = bound.replace('~', `~${full.split('~')[1]}~`);
  assert.throws(() => verifySdJwt(tampered, issuer.publicJwk, { keyBinding: { aud: 'rp', nonce: 'n1' } }), /cover|kb/i);
  const thief = generateSigningKey();
  const stolen = addKeyBinding(present(full, () => false), thief, { aud: 'rp', nonce: 'n1' });
  assert.throws(() => verifySdJwt(stolen, issuer.publicJwk, { keyBinding: { aud: 'rp', nonce: 'n1' } }), /signature/);
});

test('Token Status List encoding (2 bits per entry, zlib)', () => {
  const values = new Map([[0, STATUS.INVALID], [1, STATUS.VALID], [7, STATUS.TRANSFERRED], [65535, STATUS.SUSPENDED]]);
  const list = encodeStatusList(values);
  assert.equal(list.bits, 2);
  for (const [idx, v] of values) assert.equal(statusAt(list, idx), v);
  assert.equal(statusAt(list, 12345), STATUS.VALID);
  assert.ok(list.lst.length < 200, 'a sparse list compresses to a few bytes');
  const key = generateSigningKey();
  const token = statusListToken({ issuer: 'https://i', key, uri: 'https://i/status-lists/1', values, ttl: 10 });
  assert.equal(statusAt(verifyStatusListToken(token, key.publicJwk, { uri: 'https://i/status-lists/1' }).status_list, 7), STATUS.TRANSFERRED);
  assert.throws(() => verifyStatusListToken(token, key.publicJwk, { uri: 'https://i/status-lists/2' }));
});

test('WebAuthn: registration and assertion with a software authenticator', async () => {
  const { SoftwareAuthenticator, creationOptions, requestOptions, verifyRegistration, verifyAssertion, bindingChallenge } = await import('../src/lib/webauthn.js');
  const rpId = 'modelhub.example';
  const origin = 'https://modelhub.example';
  const auth = new SoftwareAuthenticator();
  const reg = bindingChallenge('register', { account: 'victim-org' });
  const created = auth.create(creationOptions({ rpId, rpName: 'ModelHub', user: { id: 'u1', name: 'admin' }, challenge: reg.challenge }), origin);
  const cred = verifyRegistration({ response: created, expectedChallenge: reg.challenge, expectedOrigin: origin, rpId });
  assert.equal(cred.publicJwk.crv, 'P-256');
  const approve = bindingChallenge('approve-agent', { ppid: 'ppid:x', scope: 'dataset.read_private' });
  const assertion = auth.get(requestOptions({ rpId, challenge: approve.challenge, credentials: [cred.credentialId] }), origin);
  const ok = verifyAssertion({ response: assertion, expectedChallenge: approve.challenge, expectedOrigin: origin, rpId, credential: cred });
  assert.ok(ok.userVerified);
  // Wrong challenge, wrong origin, phishing site, and no user verification are all refused.
  assert.throws(() => verifyAssertion({ response: assertion, expectedChallenge: bindingChallenge('x', {}).challenge, expectedOrigin: origin, rpId, credential: cred }), /challenge/);
  assert.throws(() => verifyAssertion({ response: assertion, expectedChallenge: approve.challenge, expectedOrigin: 'https://evil.example', rpId, credential: cred }), /origin/);
  const lazy = auth.get(requestOptions({ rpId, challenge: approve.challenge, credentials: [cred.credentialId] }), origin, { userVerified: false });
  assert.throws(() => verifyAssertion({ response: lazy, expectedChallenge: approve.challenge, expectedOrigin: origin, rpId, credential: cred }), /verification/);
  // A different authenticator's passkey does not verify against the registered key.
  const other = new SoftwareAuthenticator();
  other.create(creationOptions({ rpId, rpName: 'ModelHub', user: { id: 'u2', name: 'attacker' }, challenge: reg.challenge }), origin);
  const forged = other.get(requestOptions({ rpId, challenge: approve.challenge, credentials: [] }), origin);
  assert.throws(() => verifyAssertion({ response: forged, expectedChallenge: approve.challenge, expectedOrigin: origin, rpId, credential: cred }), /signature/);
});
