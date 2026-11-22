// HTTP binding for a records service. Run directly:  node src/records/server.js <records-service-id>
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import fs from 'node:fs';
import { createApp, createSignatureVerifier, HttpError, html, typed, closeServer } from '../lib/http.js';
import { loadTrustAnchor, loadKeys, loadFederationConfig, fileNameFor, discoverWithRetry, DATA_DIR } from '../lib/trust.js';
import { entityConfiguration, jwksOf, WELL_KNOWN } from '../lib/openid-federation.js';
import { decodeJws } from '../lib/crypto.js';
import { page, tiles, table, esc } from '../lib/dashboard.js';
import { RecordsService, OAuthError } from './records.js';

export async function startRecordsService({ id, port, trustList, keys, dataDir, host = '127.0.0.1', allowTamperSimulation = false, quiet = false }) {
  const entry = trustList.recordsService(id);
  if (!entry) throw new Error(`records service ${id} is not a member of the federation`);
  const rs = new RecordsService({ id, name: entry.name, roles: entry.roles, keys, trustList, dataDir, allowTamperSimulation });
  // Callers sign the URL the federation publishes for this records service.
  const verify = createSignatureVerifier({ publicBaseUrl: entry.url });
  // Callers of the records service present their own keys; the records service checks
  // what each key is entitled to (grantor, grantee, designee, writer).
  const signed = (ctx) => verify(ctx, () => null);
  const app = createApp(id);

  app.get('/', () => html(dashboard(rs)));
  // OpenID Federation: self-signed Entity Configuration carrying the Trust Marks
  // (accreditations) this records service received from directories.
  const marksFile = dataDir ? path.join(dataDir, 'trust-marks.json') : null;
  let trustMarks = marksFile && fs.existsSync(marksFile) ? JSON.parse(fs.readFileSync(marksFile, 'utf8')) : [];
  app.get(WELL_KNOWN, () =>
    typed(
      entityConfiguration({
        entityId: id, key: keys.signing, jwks: jwksOf(keys.signing),
        metadata: { aaf_records_service: rs.metadata(entry.url) }, authorityHints: [rs.trust.trustAnchor.entity_id], trustMarks,
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

  app.post('/v1/grants', ({ body }) => rs.depositGrant(body ?? {}));
  app.post('/v1/grants/:id/revoke', async (ctx) => rs.revokeGrant(ctx.params.id, await signed(ctx)));
  // RFC 8693 Token Exchange endpoint (form-encoded, RFC 6749 errors).
  app.post('/token', ({ body }) => {
    try {
      return rs.tokenExchange(body ?? {});
    } catch (err) {
      if (err instanceof OAuthError) return { __raw: true, status: err.status, body: { error: err.error, error_description: err.message } };
      if (err instanceof HttpError) return { __raw: true, status: err.status, body: { error: 'invalid_request', error_description: err.message } };
      throw err;
    }
  });
  app.get('/status-lists/1', () => typed(rs.statusList(), 'application/statuslist+jwt'));
  // Passkeys for designated humans, and approvals made with them.
  app.post('/v1/webauthn/registration-options', ({ body }) => rs.passkeyRegistrationOptions(body ?? {}));
  app.post('/v1/webauthn/register', ({ body }) => rs.registerPasskey(body ?? {}));
  app.post('/v1/approvals/options', ({ body }) => rs.approvalOptions(body ?? {}));
  app.post('/v1/approvals', ({ body }) => rs.approve(body ?? {}));
  app.post('/v1/status', ({ body }) => rs.recordStatus(body?.ref));

  app.post('/v1/provenance', ({ body }) => rs.depositProvenance(body ?? {}));
  app.get('/v1/provenance/:id', ({ params }) => rs.getProvenance(params.id));

  app.post('/v1/activity', ({ body }) => rs.appendActivity(body ?? {}));
  app.post('/v1/activity/query', async (ctx) => rs.queryActivity(await signed(ctx)));

  app.get('/v1/log/sth', () => ({ sth: rs.log.signedTreeHead() }));
  app.get('/v1/log/proof', ({ query }) => {
    const index = Number(query.index);
    const size = Number(query.size ?? rs.log.size);
    if (!(index >= 0 && index < size && size <= rs.log.size)) throw new HttpError(400, 'bad_range', 'invalid index or size');
    return { index, tree_size: size, leaf_hash: rs.log.leafHashAt(index), inclusion_proof: rs.log.inclusionProof(index, size), root_hash: rs.log.rootHash(size) };
  });
  app.get('/v1/log/consistency', ({ query }) => {
    const first = Number(query.first);
    const second = Number(query.second ?? rs.log.size);
    if (!(first >= 1 && first <= second && second <= rs.log.size)) throw new HttpError(400, 'bad_range', 'invalid sizes');
    return { first, second, proof: rs.log.consistencyProof(first, second), second_root: rs.log.rootHash(second) };
  });
  app.get('/v1/stats', () => rs.stats());

  app.post('/admin/tamper', ({ body, headers }) => {
    if (headers.authorization !== `Bearer ${keys.adminToken}`) throw new HttpError(401, 'admin_only', 'operator token required');
    return rs.tamper(body ?? {});
  });

  const server = await app.listen(port, host);
  if (!quiet) console.log(`[${id}] ${entry.name} listening on http://${host}:${port}  (log size ${rs.log.size})`);
  return { recordsService: rs, server, close: () => closeServer(server), setTrust: (t) => (rs.trust = t) };
}

function dashboard(rs) {
  const s = rs.stats();
  const sth = decodeJws(rs.log.signedTreeHead()).payload;
  const recent = [];
  for (let i = rs.log.size - 1; i >= Math.max(0, rs.log.size - 40); i--) {
    const e = rs.log.get(i);
    recent.push([i, esc(e.kind), esc(e.at), `<code>${esc(rs.log.leafHashAt(i))}</code>`]);
  }
  return page(rs.name, `${rs.id} · keeps ${rs.roles.join(', ')} records · public view (hashes only)`, [
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
  const svc = config.services.find((s) => s.id === id && s.kind === 'records-service');
  if (!svc) {
    console.error(`usage: node src/records/server.js <records-service-id>  (one of: ${config.services.filter((s) => s.kind === 'records-service').map((s) => s.id).join(', ')})`);
    process.exit(1);
  }
  const trustAnchor = loadTrustAnchor();
  const { setTrust } = await startRecordsService({
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
