// HTTP binding for a record keeper. Run directly:  node src/recordkeeper/server.js <record-keeper-id>
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { createApp, createSignatureVerifier, HttpError, html, typed, closeServer } from '../lib/http.js';
import { loadTrustAnchor, loadKeys, loadFederationConfig, fileNameFor, discoverWithRetry, DATA_DIR } from '../lib/trust.js';
import { entityConfiguration, jwksOf, WELL_KNOWN } from '../lib/openid-federation.js';
import { decodeJws } from '../lib/crypto.js';
import { page, tiles, table, esc } from '../lib/dashboard.js';
import { RecordKeeper, OAuthError } from './recordkeeper.js';

export async function startRecordKeeper({ id, port, trustList, keys, dataDir, host = '127.0.0.1', allowTamperSimulation = false, quiet = false }) {
  const entry = trustList.recordKeeper(id);
  if (!entry) throw new Error(`record keeper ${id} is not a member of the federation`);
  const rk = new RecordKeeper({ id, name: entry.name, roles: entry.roles, keys, trustList, dataDir, allowTamperSimulation });
  // Callers sign the URL the federation publishes for this keeper.
  const verify = createSignatureVerifier({ publicBaseUrl: entry.url });
  // Callers of the record keeper present their own keys; the keeper checks
  // what each key is entitled to (grantor, grantee, designee, writer).
  const signed = (ctx) => verify(ctx, () => null);
  const app = createApp(id);

  app.get('/', () => html(dashboard(rk)));
  // OpenID Federation: self-signed Entity Configuration carrying the Trust Marks
  // (accreditations) this keeper received from registries.
  const marksFile = dataDir ? path.join(dataDir, 'trust-marks.json') : null;
  let trustMarks = marksFile && fs.existsSync(marksFile) ? JSON.parse(fs.readFileSync(marksFile, 'utf8')) : [];
  app.get(WELL_KNOWN, () =>
    typed(
      entityConfiguration({
        entityId: id, key: keys.signing, jwks: jwksOf(keys.signing),
        metadata: { aaf_record_keeper: rk.metadata(entry.url) }, authorityHints: [rk.trust.trustAnchor.entity_id], trustMarks,
      }),
      'application/entity-statement+jwt',
    ),
  );
  app.post('/admin/trust-marks', ({ body, headers }) => {
    if (headers.authorization !== `Bearer ${keys.adminToken}`) throw new HttpError(401, 'admin_only', 'operator token required');
    const byKey = new Map(trustMarks.map((m) => [`${m.trust_mark_type}|${m.trust_mark}`, m]));
    for (const m of body?.trust_marks ?? []) byKey.set(`${m.trust_mark_type}|${m.trust_mark}`, m);
    trustMarks = [...byKey.values()];
    if (marksFile) fs.writeFileSync(marksFile, JSON.stringify(trustMarks, null, 2));
    return { trust_marks: trustMarks.length };
  });

  app.post('/v1/grants', ({ body }) => rk.depositGrant(body ?? {}));
  app.post('/v1/grants/:id/revoke', async (ctx) => rk.revokeGrant(ctx.params.id, await signed(ctx)));
  // RFC 8693 Token Exchange endpoint (form-encoded, RFC 6749 errors).
  app.post('/token', ({ body }) => {
    try {
      return rk.tokenExchange(body ?? {});
    } catch (err) {
      if (err instanceof OAuthError) return { __raw: true, status: err.status, body: { error: err.error, error_description: err.message } };
      if (err instanceof HttpError) return { __raw: true, status: err.status, body: { error: 'invalid_request', error_description: err.message } };
      throw err;
    }
  });
  app.get('/status-lists/1', () => typed(rk.statusList(), 'application/statuslist+jwt'));
  // Passkeys for designated humans, and approvals made with them.
  app.post('/v1/webauthn/registration-options', ({ body }) => rk.passkeyRegistrationOptions(body ?? {}));
  app.post('/v1/webauthn/register', ({ body }) => rk.registerPasskey(body ?? {}));
  app.post('/v1/approvals/options', ({ body }) => rk.approvalOptions(body ?? {}));
  app.post('/v1/approvals', ({ body }) => rk.approve(body ?? {}));
  app.post('/v1/status', ({ body }) => rk.recordStatus(body?.ref));

  app.post('/v1/provenance', ({ body }) => rk.depositProvenance(body ?? {}));
  app.get('/v1/provenance/:id', ({ params }) => rk.getProvenance(params.id));

  app.post('/v1/activity', ({ body }) => rk.appendActivity(body ?? {}));
  app.post('/v1/activity/query', async (ctx) => rk.queryActivity(await signed(ctx)));

  app.get('/v1/log/sth', () => ({ sth: rk.log.signedTreeHead() }));
  app.get('/v1/log/proof', ({ query }) => {
    const index = Number(query.index);
    const size = Number(query.size ?? rk.log.size);
    if (!(index >= 0 && index < size && size <= rk.log.size)) throw new HttpError(400, 'bad_range', 'invalid index or size');
    return { index, tree_size: size, leaf_hash: rk.log.leafHashAt(index), inclusion_proof: rk.log.inclusionProof(index, size), root_hash: rk.log.rootHash(size) };
  });
  app.get('/v1/log/consistency', ({ query }) => {
    const first = Number(query.first);
    const second = Number(query.second ?? rk.log.size);
    if (!(first >= 1 && first <= second && second <= rk.log.size)) throw new HttpError(400, 'bad_range', 'invalid sizes');
    return { first, second, proof: rk.log.consistencyProof(first, second), second_root: rk.log.rootHash(second) };
  });
  app.get('/v1/stats', () => rk.stats());

  app.post('/admin/tamper', ({ body, headers }) => {
    if (headers.authorization !== `Bearer ${keys.adminToken}`) throw new HttpError(401, 'admin_only', 'operator token required');
    return rk.tamper(body ?? {});
  });

  const server = await app.listen(port, host);
  if (!quiet) console.log(`[${id}] ${entry.name} listening on http://${host}:${port}  (log size ${rk.log.size})`);
  return { recordKeeper: rk, server, close: () => closeServer(server), setTrust: (t) => (rk.trust = t) };
}

function dashboard(rk) {
  const s = rk.stats();
  const sth = decodeJws(rk.log.signedTreeHead()).payload;
  const recent = [];
  for (let i = rk.log.size - 1; i >= Math.max(0, rk.log.size - 40); i--) {
    const e = rk.log.get(i);
    recent.push([i, esc(e.kind), esc(e.at), `<code>${esc(rk.log.leafHashAt(i))}</code>`]);
  }
  return page(rk.name, `${rk.id} · keeps ${rk.roles.join(', ')} records · public view (hashes only)`, [
    tiles([
      ['grants held', s.grants],
      ['active grants', s.active_grants],
      ['authorization attestations', s.authorization_attestations],
      ['approvals', s.approvals],
      ['provenance records', s.provenance_records],
      ['activity subjects', s.activity_subjects],
      ['log entries', s.log_size],
    ]),
    '<h2>Signed tree head</h2>',
    table(['tree size', 'root hash', 'signed at'], [[sth.tree_size, `<code>${esc(sth.root_hash)}</code>`, new Date(sth.timestamp).toISOString()]]),
    '<h2>Log (latest 40)</h2>',
    table(['#', 'record', 'time', 'leaf hash'], recent),
  ]);
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const id = process.argv[2];
  const config = loadFederationConfig();
  const svc = config.services.find((s) => s.id === id && s.kind === 'record-keeper');
  if (!svc) {
    console.error(`usage: node src/recordkeeper/server.js <record-keeper-id>  (one of: ${config.services.filter((s) => s.kind === 'record-keeper').map((s) => s.id).join(', ')})`);
    process.exit(1);
  }
  const trustAnchor = loadTrustAnchor();
  const { setTrust } = await startRecordKeeper({
    id,
    port: svc.port,
    host: config.listenHost ?? config.host,
    trustList: await discoverWithRetry(trustAnchor),
    keys: loadKeys(id),
    dataDir: path.join(DATA_DIR, fileNameFor(id)),
    allowTamperSimulation: Boolean(svc.allowTamperSimulation),
  });
  setInterval(async () => {
    const fresh = await discoverWithRetry(trustAnchor).catch(() => null);
    if (fresh) setTrust(fresh);
  }, 30000).unref();
}
