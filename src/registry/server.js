// HTTP binding for the registry. Run directly:  node src/registry/server.js <registry-id>
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp, createSignatureVerifier, HttpError, html, typed, closeServer } from '../lib/http.js';
import { loadTrustAnchor, loadKeys, loadFederationConfig, fileNameFor, discoverWithRetry, DATA_DIR } from '../lib/trust.js';
import { entityConfiguration, jwksOf, WELL_KNOWN, TRUST_MARK_TYP } from '../lib/openid-federation.js';
import { Registry } from './registry.js';
import { registryDashboard } from './dashboard.js';

export async function startRegistry({ id, port, trustList, keys, dataDir, host = '127.0.0.1', quiet = false }) {
  const entry = trustList.registry(id);
  if (!entry) throw new Error(`registry ${id} is not a member of the federation`);
  const registry = new Registry({ id, name: entry.name, jurisdiction: entry.jurisdiction, url: entry.url, keys, trustList, dataDir });
  // Callers sign the URL the federation publishes for this registry.
  const verify = createSignatureVerifier({ publicBaseUrl: entry.url });
  const signed = (ctx) => verify(ctx, (h) => registry.resolveSigner(h));
  const requireAdmin = (headers) => {
    if (headers.authorization !== `Bearer ${keys.adminToken}`) throw new HttpError(401, 'admin_only', 'operator token required');
  };
  const app = createApp(id);

  app.get('/', () => html(registryDashboard(registry)));
  // OpenID Federation: this registry's self-signed Entity Configuration and its Trust Marks.
  app.get(WELL_KNOWN, () =>
    typed(
      entityConfiguration({
        entityId: id, key: keys.signing, jwks: jwksOf(keys.signing),
        metadata: { aaf_registry: registry.metadata() }, authorityHints: [registry.trust.trustAnchor.entity_id],
      }),
      'application/entity-statement+jwt',
    ),
  );
  app.get('/federation/trust-mark', ({ query }) => {
    const mark = registry.trustMark(query.trust_mark_type, query.sub);
    if (!mark) throw new HttpError(404, 'not_found', `no active trust mark of that type for ${query.sub}`);
    return typed(mark, `application/${TRUST_MARK_TYP}`);
  });

  // Principals ---------------------------------------------------------------
  app.post('/v1/principals', async (ctx) => {
    const req = await signed(ctx);
    if (!req.header.jwk) throw new HttpError(400, 'missing_key', 'enrollment must carry the principal key (jwk header)');
    return registry.enrollPrincipal(req);
  });
  app.post('/v1/principals/:id/verification', async (ctx) => {
    const { params } = ctx;
    const req = await signed(ctx);
    if (!req.header.kid?.startsWith('verifier:')) throw new HttpError(403, 'verifier_only', 'only trusted identity verifiers may record verification');
    return registry.recordVerification(params.id, req);
  });
  app.post('/v1/principals/:id/attributes', async (ctx) => {
    const { params } = ctx;
    const req = await signed(ctx);
    if (!req.header.kid?.startsWith('verifier:')) throw new HttpError(403, 'verifier_only', 'attributes must be attested by a trusted verifier');
    return registry.recordAttributes(params.id, req.header.kid.slice('verifier:'.length), req.payload.attributes ?? []);
  });
  app.put('/v1/principals/:id/disclosure-policy', async (ctx) => {
    const { params } = ctx;
    const req = await signed(ctx);
    if (req.header.kid !== `principal:${params.id}`) throw new HttpError(403, 'principal_only', 'only the principal may set its disclosure policy');
    return registry.setDisclosurePolicy(params.id, req.payload.policy);
  });
  app.post('/v1/principals/:id/notifications', async (ctx) => {
    const { params } = ctx;
    const req = await signed(ctx);
    if (req.header.kid !== `principal:${params.id}`) throw new HttpError(403, 'principal_only', 'only the principal may read its notifications');
    return { notifications: registry.notificationsFor(params.id) };
  });

  // Registrations --------------------------------------------------------------
  app.post('/v1/registrations', async (ctx) => registry.register(await signed(ctx)));
  app.post('/v1/registrations/:id/revoke', async (ctx) => registry.revoke(ctx.params.id, await signed(ctx)));
  app.post('/v1/registrations/:id/receipt', async (ctx) => registry.refreshReceipt(ctx.params.id, await signed(ctx)));
  app.post('/v1/registrations/:id/rotate-key', async (ctx) => registry.rotateKey(ctx.params.id, await signed(ctx)));
  app.post('/v1/registrations/:id/transfer-offers', async (ctx) => registry.offerTransfer(ctx.params.id, await signed(ctx)));
  app.post('/v1/transfer-offers/:id/accept', async (ctx) => registry.acceptTransfer(ctx.params.id, await signed(ctx)));
  app.post('/v1/transfer-offers/:id/cancel', async (ctx) => registry.cancelTransfer(ctx.params.id, await signed(ctx)));

  // Attestations, status ------------------------------------------------------
  app.post('/v1/attestations', async (ctx) => {
    const req = await signed(ctx);
    if (!req.header.kid?.startsWith('registration:')) throw new HttpError(403, 'agent_only', 'attestations are issued to registered agents');
    return registry.issueAttestation(req.header.kid.slice('registration:'.length), req.payload);
  });
  // IETF Token Status List for every credential this registry issued.
  app.get('/status-lists/1', async () => typed(await registry.statusList(), 'application/statuslist+jwt'));
  // Live, per-PPID status with reasons: used between federation peers and by investigators.
  app.post('/v1/status', async ({ body }) => registry.status(body ?? {}));

  // Federation ----------------------------------------------------------------
  app.post('/v1/federation/status-changed', async (ctx) => {
    const req = await signed(ctx);
    if (!req.header.kid?.startsWith('registry:')) throw new HttpError(403, 'peer_only', 'only federation peers may push status changes');
    return registry.statusChangedUpstream(req.header.kid.slice('registry:'.length), req.payload.ppids ?? []);
  });

  // Incidents and resolution -------------------------------------------------
  app.post('/v1/incidents', async (ctx) => registry.incident(await signed(ctx)));
  app.post('/v1/resolutions', async ({ body }) => registry.resolve(body ?? {}));

  app.get('/v1/accreditations', () => ({
    accreditations: [...registry.accreditations.values()].map((a) => ({ rk: a.rk, roles: a.roles, status: a.status, trust_mark_types: Object.keys(a.marks ?? {}) })),
  }));

  // Transparency -------------------------------------------------------------
  app.get('/v1/transparency/sth', () => ({ sth: registry.log.signedTreeHead() }));
  app.get('/v1/transparency/entries', ({ query }) => ({
    entries: registry.transparencyEntries(Number(query.start ?? 0), Number(query.end ?? registry.log.size)),
  }));
  app.get('/v1/transparency/consistency', ({ query }) => ({
    first: Number(query.first), second: Number(query.second),
    proof: registry.log.consistencyProof(Number(query.first), Number(query.second)),
  }));
  app.get('/v1/stats', () => registry.stats());

  // Operator -----------------------------------------------------------------
  app.post('/admin/accreditations', ({ body, headers }) => {
    requireAdmin(headers);
    return registry.accredit(body.rk);
  });
  app.post('/admin/accreditations/:rk/withdraw', ({ params, headers }) => {
    requireAdmin(headers);
    return registry.withdrawAccreditation(params.rk);
  });
  app.post('/admin/registrations/:id/revoke', ({ params, body, headers }) => {
    requireAdmin(headers);
    return registry.applyRevocation(registry.mustRegistration(params.id), body.reason ?? 'legal_order', 'operator');
  });

  const server = await app.listen(port, host);
  if (!quiet) console.log(`[${id}] ${entry.name} listening on http://${host}:${port}  (log size ${registry.log.size})`);
  return { registry, server, close: () => closeServer(server), setTrust: (t) => (registry.trust = t) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const id = process.argv[2];
  const config = loadFederationConfig();
  const svc = config.services.find((s) => s.id === id && s.kind === 'registry');
  if (!svc) {
    console.error(`usage: node src/registry/server.js <registry-id>  (one of: ${config.services.filter((s) => s.kind === 'registry').map((s) => s.id).join(', ')})`);
    process.exit(1);
  }
  const trustAnchor = loadTrustAnchor();
  const { setTrust } = await startRegistry({
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
