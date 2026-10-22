// Regression: a relying party must accept an agent request only when the key
// that verifies the RFC 9421 signature is the presented credential's cnf key.
// A keyid spelling ("jkt:" with a key carried in the body) is not authority.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { generateSigningKey, nowSeconds, publicOf } from '../src/lib/crypto.js';
import { issueSdJwt, present } from '../src/lib/sd-jwt.js';
import { signRequest } from '../src/lib/httpsig.js';
import { buildPresentationRequest } from '../src/lib/presentation.js';
import { statusListToken, STATUS } from '../src/lib/status-list.js';
import { SD_JWT_VC_TYP, vct, AGENT_SIGNATURE_TAG, AGENT_SIGNED_COMPONENTS } from '../src/lib/credentials.js';
import { HEADERS, CLASSIFICATION as C } from '../src/lib/protocol.js';
import { createVerifier } from '../src/rp/verifier.js';

test('RP rejects an agent request signed by a key other than the credential cnf key', async () => {
  const TA = 'https://ta.example';
  const REG = 'https://registry.example';
  const RP = 'https://rp.example';
  const URL = `${RP}/api/action`;
  const STATUS_URI = `${REG}/status/1`;
  const registryKey = generateSigningKey();
  const holder = generateSigningKey();
  const attacker = generateSigningKey();
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
    vct: vct(TA, 'accountability'), iss: REG, sub: 'ppid:registry.example:p_victim', aud: RP, iat: now, exp: now + 600,
    cnf: { jwk: publicOf(holder.publicJwk) }, ppid_mode: 'pairwise',
    accountability: { status: 'accountable', root_principal: { type: 'organization', verified: true, verification: {} }, chain_length: 1, attributes: [] },
    status: { status_list: { idx: 7, uri: STATUS_URI } },
  }, registryKey, { typ: SD_JWT_VC_TYP }), () => true);

  // The holder's request, observed by an attacker (presentation and nonce).
  const legit = buildPresentationRequest({ url: URL, rpId: RP, params: { amount: 1 }, accountability: credential, key: holder });
  const presentation = legit.headers[HEADERS.presentation];

  // The attacker re-signs a new request with its own key, spelled "jkt:".
  const body = JSON.stringify({ amount: 900, signer_jwk: publicOf(attacker.publicJwk) });
  const headers = signRequest({
    method: 'POST', url: URL, body, key: attacker, keyid: `jkt:${attacker.kid}`, tag: AGENT_SIGNATURE_TAG, nonce: legit.nonce,
    components: AGENT_SIGNED_COMPONENTS, headers: { 'content-type': 'application/json', [HEADERS.presentation]: presentation },
  });

  const verifier = createVerifier({ rpId: RP, trust });
  const out = await verifier.verify({ headers, url: URL, method: 'POST', rawBody: body, action: 'commerce.purchase', params: { amount: 900 } });
  assert.equal(out.classification, C.UNSUPPORTED);
  assert.match(out.failure, /does not hold the credential's key/);
});
