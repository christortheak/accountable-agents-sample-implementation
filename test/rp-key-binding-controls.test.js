// Key binding between an agent request and its credential: replay identity,
// cache poisoning, request binding, KB-JWT iat, and the legitimate paths
// (cnf-signed agent requests, self-presented "jkt:" service requests).
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateSigningKey, nowSeconds, publicOf, signJws } from '../src/lib/crypto.js';
import { issueSdJwt, present, addKeyBinding, verifySdJwt, sdHash, sd, KB_JWT_TYP } from '../src/lib/sd-jwt.js';
import { signRequest } from '../src/lib/httpsig.js';
import { buildSignedRequest, createSignatureVerifier } from '../src/lib/http.js';
import { statusListToken, STATUS } from '../src/lib/status-list.js';
import { SD_JWT_VC_TYP, vct, AGENT_SIGNATURE_TAG, AGENT_SIGNED_COMPONENTS } from '../src/lib/credentials.js';
import { HEADERS, CLASSIFICATION as C } from '../src/lib/protocol.js';
import { createVerifier } from '../src/rp/verifier.js';

const TA = 'https://ta.example';
const REG = 'https://registry.example';
const RP = 'https://rp.example';
const URL = `${RP}/api/action`;
const STATUS_URI = `${REG}/status/1`;
const HOLDER_CHECK = 'request signed by the credential holder (RFC 9421 + key binding)';

function world() {
  const registryKey = generateSigningKey();
  const holder = generateSigningKey();
  const registry = { id: REG, jwks: { keys: [registryKey.publicJwk] } };
  const statusToken = statusListToken({ issuer: REG, key: registryKey, uri: STATUS_URI, values: new Map([[7, STATUS.VALID]]), ttl: 60 });
  const trust = {
    trustAnchor: { entity_id: TA },
    registry: (id) => (id === REG ? registry : null),
    recordKeeper: () => null,
    trustMarkIssuers: () => [],
    signingKey: (entity, kid) => entity?.jwks.keys.find((k) => !kid || k.kid === kid) ?? null,
    locate: () => `data:text/plain,${statusToken}`,
  };
  const now = nowSeconds();
  const credential = present(issueSdJwt({
    vct: vct(TA, 'accountability'), iss: REG, sub: 'ppid:registry.example:p_holder', aud: RP, iat: now, exp: now + 600,
    cnf: { jwk: publicOf(holder.publicJwk) }, ppid_mode: 'pairwise',
    accountability: { status: 'accountable', root_principal: { type: 'organization', verified: true, verification: {} }, chain_length: 1, attributes: [] },
    status: { status_list: { idx: 7, uri: STATUS_URI } },
  }, registryKey, { typ: SD_JWT_VC_TYP }), () => true);
  return { holder, credential, verifier: createVerifier({ rpId: RP, trust }) };
}

/** An agent request; every binding input can be overridden. */
function agentRequest(w, { key = w.holder, keyid, nonce = `n_${Math.random().toString(36).slice(2, 14)}`, kb = {}, params = { amount: 1 }, embed = false } = {}) {
  const presented = kb.raw ?? addKeyBinding(w.credential, w.holder, { aud: kb.aud ?? RP, nonce: kb.nonce ?? nonce, ...(kb.iat !== undefined ? { iat: kb.iat } : {}) });
  const presentation = Buffer.from(JSON.stringify({ v: 2, accountability: presented })).toString('base64url');
  const body = JSON.stringify(embed ? { ...params, signer_jwk: publicOf(key.publicJwk) } : params);
  const headers = signRequest({
    method: 'POST', url: URL, body, key, keyid: keyid ?? `cnf:${key.kid}`, tag: AGENT_SIGNATURE_TAG, nonce,
    components: AGENT_SIGNED_COMPONENTS, headers: { 'content-type': 'application/json', [HEADERS.presentation]: presentation },
  });
  return { headers, body, nonce };
}

const send = (w, req, { url = URL, body = req.body } = {}) =>
  w.verifier.verify({ headers: req.headers, url, method: 'POST', rawBody: body, action: 'commerce.purchase', params: JSON.parse(req.body) });

const accepted = (out) => out.classification === C.PROTECTED && out.checks.find((c) => c.name === HOLDER_CHECK)?.ok === true;
const rejected = (out, re) => {
  assert.equal(out.classification, C.UNSUPPORTED);
  if (re) assert.match(out.failure, re);
};

/** A KB-JWT with an arbitrary iat value (including ones addKeyBinding cannot produce). */
const kbWithIat = (w, nonce, iat) => {
  const claims = { aud: RP, nonce, sd_hash: sdHash(w.credential) };
  if (iat !== undefined) claims.iat = iat;
  return w.credential + signJws(claims, w.holder, { typ: KB_JWT_TYP });
};

test('RP accepts a cnf-signed agent request once and rejects its replay', async () => {
  const w = world();
  const req = agentRequest(w);
  assert.ok(accepted(await send(w, req)));
  rejected(await send(w, req), /replayed_request/);
});

test('RP replay identity is the verified key, not the keyid spelling', async () => {
  const w = world();
  const req = agentRequest(w);
  assert.ok(accepted(await send(w, req)));
  // The holder's own key, same nonce, spelled "jkt:" with the key in the body.
  rejected(await send(w, agentRequest(w, { keyid: `jkt:${w.holder.kid}`, nonce: req.nonce, embed: true })), /wrong_key/);
  rejected(await send(w, agentRequest(w, { nonce: req.nonce })), /replayed_request/);
});

test('RP rejects alternate keyid spellings and a wrong signer even with a fresh nonce', async () => {
  const w = world();
  const attacker = generateSigningKey();
  rejected(await send(w, agentRequest(w, { key: attacker, keyid: `jkt:${attacker.kid}`, embed: true })), /does not hold/);
  rejected(await send(w, agentRequest(w, { key: attacker, keyid: `cnf:${w.holder.kid}` })), /does not hold/);
  rejected(await send(w, agentRequest(w, { key: attacker })), /does not hold/);
  rejected(await send(w, agentRequest(w, { keyid: `jkt:${w.holder.kid}`, embed: true })), /wrong_key/);
  assert.ok(accepted(await send(w, agentRequest(w))));
});

test('RP binds the signature to body and target; invalid signatures do not consume the nonce', async () => {
  const w = world();
  const req = agentRequest(w);
  rejected(await send(w, req, { body: JSON.stringify({ amount: 900 }) }), /does not hold/);
  rejected(await send(w, req, { url: `${RP}/api/other` }), /does not hold/);
  const forged = { ...req, headers: { ...req.headers, signature: req.headers.signature.replace(/:(.)/, (_, c) => `:${c === 'A' ? 'B' : 'A'}`) } };
  rejected(await send(w, forged), /does not hold/);
  assert.ok(accepted(await send(w, req)));
});

test('RP failed key binding does not consume the nonce', async () => {
  const w = world();
  const nonce = 'n_bindingretry1';
  rejected(await send(w, agentRequest(w, { nonce, kb: { aud: 'https://other-rp.example' } })), /kb_wrong_audience|audience/);
  rejected(await send(w, agentRequest(w, { nonce, kb: { nonce: 'n_somethingelse' } })), /nonce/);
  rejected(await send(w, agentRequest(w, { nonce, kb: { iat: nowSeconds() - 3600 } })), /stale/);
  assert.ok(accepted(await send(w, agentRequest(w, { nonce }))));
});

test('RP requires a finite numeric KB-JWT iat within the freshness window', async () => {
  const w = world();
  const now = nowSeconds();
  const bad = [undefined, null, String(now), 'NaN', true, [now], { t: now }, now - 120, now + 120, now - 60.5, 1e308, -1e308];
  for (const iat of bad) {
    const nonce = `n_iat${Math.random().toString(36).slice(2, 12)}`;
    const out = await send(w, agentRequest(w, { nonce, kb: { raw: kbWithIat(w, nonce, iat) } }));
    rejected(out, /does not hold/);
  }
  for (const iat of [now - 55, now + 55, now - 0.5, now + 0.25, now - 30.5]) {
    const nonce = `n_iat${Math.random().toString(36).slice(2, 12)}`;
    assert.ok(accepted(await send(w, agentRequest(w, { nonce, kb: { raw: kbWithIat(w, nonce, iat) } }))), `iat ${iat - now}s`);
  }
});

test('SD-JWT key binding rejects missing and malformed iat', () => {
  const issuer = generateSigningKey();
  const holder = generateSigningKey();
  const presented = present(issueSdJwt({ cnf: { jwk: holder.publicJwk }, name: sd('Dana') }, issuer), () => true);
  const kb = (iat) => presented + signJws({ ...(iat !== undefined ? { iat } : {}), aud: 'rp', nonce: 'n1', sd_hash: sdHash(presented) }, holder, { typ: KB_JWT_TYP });
  const opts = { keyBinding: { aud: 'rp', nonce: 'n1' } };
  const now = nowSeconds();
  for (const iat of [undefined, null, String(now), 'NaN', true, [now], {}]) assert.throws(() => verifySdJwt(kb(iat), issuer.publicJwk, opts), /iat must be a NumericDate/);
  assert.throws(() => verifySdJwt(kb(now - 600), issuer.publicJwk, opts), /stale/);
  assert.throws(() => verifySdJwt(kb(now + 600), issuer.publicJwk, opts), /stale/);
  assert.ok(verifySdJwt(kb(now), issuer.publicJwk, opts).kb);
  assert.ok(verifySdJwt(kb(now - 0.75), issuer.publicJwk, opts).kb, 'fractional NumericDate is valid');
});

test('service self-presented jkt signing still works; replay is keyed by the verified key', async () => {
  const verifySigned = createSignatureVerifier();
  const principal = generateSigningKey();
  const url = 'http://127.0.0.1:9/v1/principals';
  const ctxFor = ({ body, headers }, target = url) => {
    const u = new globalThis.URL(target);
    return { req: { method: 'POST', url: u.pathname + u.search }, headers: { ...headers, host: u.host }, rawBody: body, body: JSON.parse(body) };
  };
  const named = () => null;
  const req = buildSignedRequest('POST', url, { type: 'organization' }, principal, { embedJwk: true });
  const out = await verifySigned(ctxFor(req), named);
  assert.equal(out.thumbprint, principal.kid);
  assert.equal(out.header.kid, `jkt:${principal.kid}`);
  assert.deepEqual(out.payload, { type: 'organization' });
  await assert.rejects(verifySigned(ctxFor(req), named), /nonce already used/);

  // An invalid signature does not consume its nonce.
  const fresh = buildSignedRequest('POST', url, { type: 'organization' }, principal, { embedJwk: true });
  await assert.rejects(verifySigned(ctxFor(fresh, 'http://127.0.0.1:9/v1/other'), named), /verification failed/);
  await verifySigned(ctxFor(fresh), named);

  // The same key and nonce under a named keyid is the same replay identity.
  const nonce = /nonce="([^"]+)"/.exec(fresh.headers['signature-input'])[1];
  const body = JSON.stringify({ type: 'organization' });
  const renamed = signRequest({ method: 'POST', url, body, key: principal, keyid: 'principal:p1', tag: 'aaf-request', nonce, headers: { 'content-type': 'application/json' } });
  await assert.rejects(verifySigned(ctxFor({ body, headers: renamed }), () => principal.publicJwk), /nonce already used/);
});
