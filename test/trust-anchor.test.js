// Trust anchor bootstrap: key pinning, fixed anchor keys, explicit re-pin and
// entity identity. Fixtures are generated keys served from 127.0.0.1 on an
// ephemeral port; nothing external is contacted.
import { test, before, after } from 'node:test';
import assert from 'node:assert/strict';
import http from 'node:http';
import { generateSigningKey, signJws } from '../src/lib/crypto.js';
import { entityConfiguration, subordinateStatement, jwksOf, WELL_KNOWN, ENTITY_STATEMENT_TYP } from '../src/lib/openid-federation.js';
import { fetchTrustAnchor, discoverFederation } from '../src/lib/trust.js';

// Logical entity identifier, deliberately different from where it is served.
const TA_ID = 'https://federation.anchor.test';
const MEMBER = 'https://registry.anchor.test';

const legit = generateSigningKey();
const attacker = generateSigningKey();
const successor = generateSigningKey();

// What the server currently answers; each test sets it.
let state;
const server = http.createServer((req, res) => {
  const u = new URL(req.url, 'http://x');
  const send = (body, type = 'application/entity-statement+jwt') => res.writeHead(200, { 'content-type': type }).end(body);
  if (u.pathname === WELL_KNOWN) return send(state.ec());
  if (u.pathname === '/list') return send(JSON.stringify(state.members ?? []), 'application/json');
  if (u.pathname === '/fetch') return send(state.statement(u.searchParams.get('sub')));
  res.writeHead(404).end();
});
let url;

const metadata = { federation_entity: { organization_name: 'Anchor Test' }, aaf_trust_anchor: { policies: {} } };
/** An anchor configuration signed by signer, advertising the given keys. */
const anchorEc = (signer, keys, { entityId = TA_ID, extra = {} } = {}) => () => entityConfiguration({ entityId, key: signer, jwks: jwksOf(...keys), metadata, extra });
const statementBy = (signer) => (sub) => subordinateStatement({ issuer: TA_ID, key: signer, sub, jwks: jwksOf(legit), metadata: { aaf_identity_verifier: { organization_name: 'Member' } } });

before(async () => {
  await new Promise((r) => server.listen(0, '127.0.0.1', r));
  url = `http://127.0.0.1:${server.address().port}`;
});
after(() => server.close());

test('a configured pin accepts the legitimate anchor and keeps only the pinned key', async () => {
  state = { ec: anchorEc(legit, [legit, attacker]) };
  const anchor = await fetchTrustAnchor(url, { pin: legit.kid });
  assert.equal(anchor.thumbprint, legit.kid);
  assert.deepEqual(anchor.jwks.keys.map((k) => k.kid), [legit.kid]);
  assert.equal(anchor.entity_id, TA_ID);
  assert.equal(anchor.url, url, 'physical endpoint is kept apart from the logical entity identifier');
});

test('a pinned key that is only listed, while another key signs, is refused', async () => {
  // Legitimate key advertised first, attacker key signs.
  state = { ec: anchorEc(attacker, [legit, attacker]) };
  await assert.rejects(fetchTrustAnchor(url, { pin: legit.kid }), /signature/);
  // Attacker key labelled with the pinned kid: the computed thumbprint is what counts.
  state = { ec: () => signJws({ iss: TA_ID, sub: TA_ID, iat: 0, exp: 4e9, jwks: { keys: [{ ...attacker.publicJwk, kid: legit.kid, use: 'sig' }] }, metadata }, attacker, { typ: ENTITY_STATEMENT_TYP, kid: legit.kid }) };
  await assert.rejects(fetchTrustAnchor(url, { pin: legit.kid }), /pinned thumbprint/);
});

test('a wrong pin is refused', async () => {
  state = { ec: anchorEc(legit, [legit]) };
  await assert.rejects(fetchTrustAnchor(url, { pin: attacker.kid }), /pinned thumbprint/);
});

test('a configured entity identifier is checked against iss and sub', async () => {
  state = { ec: anchorEc(legit, [legit]) };
  const ok = await fetchTrustAnchor(url, { pin: legit.kid, entityId: TA_ID });
  assert.equal(ok.entity_id_checked, true);
  await assert.rejects(fetchTrustAnchor(url, { pin: legit.kid, entityId: 'https://other.anchor.test' }), /expected https:\/\/other/);
  state = { ec: anchorEc(legit, [legit], { extra: { sub: 'https://elsewhere.test' } }) };
  await assert.rejects(fetchTrustAnchor(url, { pin: legit.kid }), /not its issuer/);
});

test('without a pin, trust on first use accepts the signing key and says the identity was not checked', async () => {
  state = { ec: anchorEc(legit, [attacker, legit]) };
  const anchor = await fetchTrustAnchor(url);
  assert.equal(anchor.thumbprint, legit.kid);
  assert.deepEqual(anchor.jwks.keys.map((k) => k.kid), [legit.kid]);
  assert.equal(anchor.entity_id_checked, false);
});

test('discovery keeps the pinned keys: newly advertised keys are not trusted', async () => {
  state = { ec: anchorEc(legit, [legit]), members: [MEMBER], statement: statementBy(legit) };
  const anchor = await fetchTrustAnchor(url, { pin: legit.kid, entityId: TA_ID });
  const fed = await discoverFederation(anchor);
  assert.equal(fed.doc.verifiers[0].id, MEMBER);
  assert.deepEqual(fed.trustAnchor.jwks.keys.map((k) => k.kid), [legit.kid]);

  // Still signed by the pinned key, but advertising a new one that signs a subordinate statement.
  state = { ec: anchorEc(legit, [legit, successor]), members: [MEMBER], statement: statementBy(successor) };
  await assert.rejects(discoverFederation(anchor), /signature/);
  // Entity Configuration itself moved to the new key.
  state = { ec: anchorEc(successor, [successor]), members: [MEMBER], statement: statementBy(successor) };
  await assert.rejects(discoverFederation(anchor), /signature/);
});

test('an explicit re-pin to the replacement key is accepted', async () => {
  state = { ec: anchorEc(successor, [successor]), members: [MEMBER], statement: statementBy(successor) };
  const repinned = await fetchTrustAnchor(url, { pin: successor.kid, entityId: TA_ID });
  const fed = await discoverFederation(repinned);
  assert.deepEqual(fed.trustAnchor.jwks.keys.map((k) => k.kid), [successor.kid]);
  assert.equal(fed.doc.verifiers[0].id, MEMBER);
  // The old pin no longer matches.
  await assert.rejects(fetchTrustAnchor(url, { pin: legit.kid }), /pinned thumbprint/);
});

test('trust on first use keeps an advertised opaque kid and still verifies with that key', async () => {
  const opaque = { ...legit.publicJwk, kid: 'anchor-2026', use: 'sig' };
  const decoy = { ...attacker.publicJwk, kid: 'decoy', use: 'sig' };
  const signed = (signer, kid) => () => signJws({ iss: TA_ID, sub: TA_ID, iat: 0, exp: 4e9, jwks: { keys: [decoy, opaque] }, metadata }, signer, { typ: ENTITY_STATEMENT_TYP, kid });
  state = { ec: signed(legit, 'anchor-2026') };
  const anchor = await fetchTrustAnchor(url);
  assert.equal(anchor.thumbprint, legit.kid);
  assert.deepEqual(anchor.jwks.keys.map((k) => k.kid), ['anchor-2026']);
  // The header names one key but another signed: refused.
  state = { ec: signed(attacker, 'anchor-2026') };
  await assert.rejects(fetchTrustAnchor(url), /signature/);
  // A pin still goes by computed thumbprint, whatever the kid says.
  state = { ec: signed(legit, 'anchor-2026') };
  assert.equal((await fetchTrustAnchor(url, { pin: legit.kid })).thumbprint, legit.kid);
});

test('an empty or wrong-type pin or entity identifier is refused, not treated as absent', async () => {
  state = { ec: anchorEc(legit, [legit]) };
  for (const pin of ['', '  ', null, true, 42]) await assert.rejects(fetchTrustAnchor(url, { pin }), /pin must be/);
  for (const entityId of ['', null, true, 'not a url', ` ${TA_ID}`]) await assert.rejects(fetchTrustAnchor(url, { pin: legit.kid, entityId }), /entityId must be/);
});

test('a self-asserted identity must be a meaningful iss equal to sub', async () => {
  for (const extra of [{ iss: '', sub: '' }, { iss: 'anchor', sub: 'anchor' }, { iss: 7, sub: 7 }]) {
    state = { ec: anchorEc(legit, [legit], { extra }) };
    await assert.rejects(fetchTrustAnchor(url, { pin: legit.kid }), /no usable iss/);
  }
});

test('the standalone relying party passes its trust anchor config through: null pin is first use, null entityId is refused', async () => {
  const { trustAnchorFrom } = await import('../src/rp/standalone.js');
  const prev = process.env.AAF_STARTUP_TIMEOUT_SECONDS;
  process.env.AAF_STARTUP_TIMEOUT_SECONDS = '0';
  try {
    state = { ec: anchorEc(legit, [legit]) };
    const tofu = await trustAnchorFrom({ trustAnchor: { url, pin: null } });
    assert.equal(tofu.entity_id_checked, false);
    const checked = await trustAnchorFrom({ trustAnchor: { url, pin: legit.kid, entityId: TA_ID } });
    assert.equal(checked.entity_id_checked, true);
    await assert.rejects(trustAnchorFrom({ trustAnchor: { url, pin: legit.kid, entityId: null } }), /entityId must be/);
    await assert.rejects(trustAnchorFrom({ trustAnchor: { url, pin: '' } }), /pin must be/);
  } finally {
    if (prev === undefined) delete process.env.AAF_STARTUP_TIMEOUT_SECONDS;
    else process.env.AAF_STARTUP_TIMEOUT_SECONDS = prev;
  }
});
