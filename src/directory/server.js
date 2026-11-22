// HTTP binding for the directory. Run directly:  node src/directory/server.js <directory-id>
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp, createSignatureVerifier, HttpError, html, typed, closeServer } from '../lib/http.js';
import { loadTrustAnchor, loadKeys, loadFederationConfig, fileNameFor, discoverWithRetry, DATA_DIR } from '../lib/trust.js';
import { entityConfiguration, jwksOf, WELL_KNOWN, TRUST_MARK_TYP } from '../lib/openid-federation.js';
import { Directory } from './directory.js';
import { directoryDashboard } from './dashboard.js';

export async function startDirectory({ id, port, trustList, keys, dataDir, host = '127.0.0.1', quiet = false }) {
  const entry = trustList.directory(id);
  if (!entry) throw new Error(`directory ${id} is not a member of the federation`);
  const directory = new Directory({ id, name: entry.name, jurisdiction: entry.jurisdiction, url: entry.url, keys, trustList, dataDir });
  // Callers sign the URL the federation publishes for this directory.
  const verify = createSignatureVerifier({ publicBaseUrl: entry.url });
  const signed = (ctx) => verify(ctx, (h) => directory.resolveSigner(h));
  const requireAdmin = (headers) => {
    if (headers.authorization !== `Bearer ${keys.adminToken}`) throw new HttpError(401, 'admin_only', 'operator token required');
  };
  const app = createApp(id);

  app.get('/', () => html(directoryDashboard(directory)));
  // OpenID Federation: this directory's self-signed Entity Configuration and its Trust Marks.
  app.get(WELL_KNOWN, () =>
    typed(
      entityConfiguration({
        entityId: id, key: keys.signing, jwks: jwksOf(keys.signing),
        metadata: { aaf_directory: directory.metadata() }, authorityHints: [directory.trust.trustAnchor.entity_id],
      }),
      'application/entity-statement+jwt',
    ),
  );
  app.get('/federation/trust-mark', ({ query }) => {
    const mark = directory.trustMark(query.trust_mark_type, query.sub);
    if (!mark) throw new HttpError(404, 'not_found', `no active trust mark of that type for ${query.sub}`);
    return typed(mark, `application/${TRUST_MARK_TYP}`);
  });

  // Principals ---------------------------------------------------------------
  app.post('/v1/principals', async (ctx) => {
    const req = await signed(ctx);
    if (!req.header.jwk) throw new HttpError(400, 'missing_key', 'enrollment must carry the principal key (jwk header)');
    return directory.enrollPrincipal(req);
  });
  app.post('/v1/principals/:id/verification', async (ctx) => {
    const { params } = ctx;
    const req = await signed(ctx);
    if (!req.header.kid?.startsWith('verifier:')) throw new HttpError(403, 'verifier_only', 'only trusted identity verifiers may record verification');
    return directory.recordVerification(params.id, req);
  });
  app.post('/v1/principals/:id/attributes', async (ctx) => {
    const { params } = ctx;
    const req = await signed(ctx);
    if (!req.header.kid?.startsWith('verifier:')) throw new HttpError(403, 'verifier_only', 'attributes must be attested by a trusted verifier');
    return directory.recordAttributes(params.id, req.header.kid.slice('verifier:'.length), req.payload.attributes ?? []);
  });
  app.put('/v1/principals/:id/disclosure-policy', async (ctx) => {
    const { params } = ctx;
    const req = await signed(ctx);
    if (req.header.kid !== `principal:${params.id}`) throw new HttpError(403, 'principal_only', 'only the principal may set its disclosure policy');
    return directory.setDisclosurePolicy(params.id, req.payload.policy);
  });
  app.post('/v1/principals/:id/notifications', async (ctx) => {
    const { params } = ctx;
    const req = await signed(ctx);
    if (req.header.kid !== `principal:${params.id}`) throw new HttpError(403, 'principal_only', 'only the principal may read its notifications');
    return { notifications: directory.notificationsFor(params.id) };
  });

  // Registrations --------------------------------------------------------------
  app.post('/v1/registrations', async (ctx) => directory.register(await signed(ctx)));
  app.post('/v1/registrations/:id/revoke', async (ctx) => directory.revoke(ctx.params.id, await signed(ctx)));
  app.post('/v1/registrations/:id/receipt', async (ctx) => directory.refreshReceipt(ctx.params.id, await signed(ctx)));
  app.post('/v1/registrations/:id/rotate-key', async (ctx) => directory.rotateKey(ctx.params.id, await signed(ctx)));
  app.post('/v1/registrations/:id/transfer-offers', async (ctx) => directory.offerTransfer(ctx.params.id, await signed(ctx)));
  app.post('/v1/transfer-offers/:id/accept', async (ctx) => directory.acceptTransfer(ctx.params.id, await signed(ctx)));
  app.post('/v1/transfer-offers/:id/cancel', async (ctx) => directory.cancelTransfer(ctx.params.id, await signed(ctx)));

  // Attestations, status ------------------------------------------------------
  app.post('/v1/attestations', async (ctx) => {
    const req = await signed(ctx);
    if (!req.header.kid?.startsWith('registration:')) throw new HttpError(403, 'agent_only', 'attestations are issued to registered agents');
    return directory.issueAttestation(req.header.kid.slice('registration:'.length), req.payload);
  });
  // IETF Token Status List for every credential this directory issued.
  app.get('/status-lists/1', async () => typed(await directory.statusList(), 'application/statuslist+jwt'));
  // Live, per-ID status with reasons: used between federation peers and by investigators.
  app.post('/v1/status', async ({ body }) => directory.status(body ?? {}));

  // Federation ----------------------------------------------------------------
  app.post('/v1/federation/status-changed', async (ctx) => {
    const req = await signed(ctx);
    if (!req.header.kid?.startsWith('directory:')) throw new HttpError(403, 'peer_only', 'only federation peers may push status changes');
    return directory.statusChangedUpstream(req.header.kid.slice('directory:'.length), req.payload.aaf_ids ?? []);
  });

  // Incidents and attribution -------------------------------------------------
  app.post('/v1/incidents', async (ctx) => directory.incident(await signed(ctx)));
  app.post('/v1/attributions', async ({ body }) => directory.trace(body ?? {}));
  // Revocation under a legal order that carries the revoke_registration scope.
  app.post('/v1/revocations', async ({ body }) => directory.revokeUnderOrder(body ?? {}));
  // Published practices (also in this directory's Entity Configuration).
  app.get('/v1/practices', () => directory.practices());

  app.get('/v1/accreditations', () => ({
    accreditations: [...directory.accreditations.values()].map((a) => ({ rs: a.rs, roles: a.roles, status: a.status, trust_mark_types: Object.keys(a.marks ?? {}) })),
  }));

  // Transparency -------------------------------------------------------------
  app.get('/v1/transparency/sth', () => ({ sth: directory.log.signedTreeHead() }));
  app.get('/v1/transparency/entries', ({ query }) => ({
    entries: directory.transparencyEntries(Number(query.start ?? 0), Number(query.end ?? directory.log.size)),
  }));
  app.get('/v1/transparency/consistency', ({ query }) => ({
    first: Number(query.first), second: Number(query.second),
    proof: directory.log.consistencyProof(Number(query.first), Number(query.second)),
  }));
  app.get('/v1/stats', () => directory.stats());

  // Operator -----------------------------------------------------------------
  app.post('/admin/accreditations', ({ body, headers }) => {
    requireAdmin(headers);
    return directory.accredit(body.rs);
  });
  app.post('/admin/accreditations/:rs/withdraw', ({ params, headers }) => {
    requireAdmin(headers);
    return directory.withdrawAccreditation(params.rs);
  });
  app.post('/admin/registrations/:id/revoke', ({ params, body, headers }) => {
    requireAdmin(headers);
    return directory.applyRevocation(directory.mustRegistration(params.id), body.reason ?? 'fraud', 'operator');
  });
  // Close a principal record so the same verified identity can enroll again (for example after a lost key).
  app.post('/admin/principals/:id/close', ({ params, body, headers }) => {
    requireAdmin(headers);
    return directory.closePrincipal(params.id, body?.reason ?? 'operator');
  });

  const server = await app.listen(port, host);
  if (!quiet) console.log(`[${id}] ${entry.name} listening on http://${host}:${port}  (log size ${directory.log.size})`);
  return { directory, server, close: () => closeServer(server), setTrust: (t) => (directory.trust = t) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const id = process.argv[2];
  const config = loadFederationConfig();
  const svc = config.services.find((s) => s.id === id && s.kind === 'directory');
  if (!svc) {
    console.error(`usage: node src/directory/server.js <directory-id>  (one of: ${config.services.filter((s) => s.kind === 'directory').map((s) => s.id).join(', ')})`);
    process.exit(1);
  }
  const trustAnchor = loadTrustAnchor();
  const { setTrust } = await startDirectory({
    id,
    port: svc.port,
    host: config.listenHost ?? config.host,
    trustList: await discoverWithRetry(trustAnchor),
    keys: loadKeys(id),
    dataDir: path.join(DATA_DIR, fileNameFor(id)),
  });
  // Refresh trust chains periodically (and pick up peers that started later).
  setInterval(async () => {
    const fresh = await discoverWithRetry(trustAnchor).catch(() => null);
    if (fresh) setTrust(fresh);
  }, 30000).unref();
}
