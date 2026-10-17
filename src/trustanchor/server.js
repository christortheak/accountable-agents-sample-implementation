// The federation's Trust Anchor (its governance body), per OpenID Federation 1.0:
// publishes its Entity Configuration, lists its subordinates, and signs a
// Subordinate Statement about each. Run directly:  node src/trustanchor/server.js
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createApp, html, typed, closeServer, HttpError } from '../lib/http.js';
import { loadKeys, loadFederationConfig, DATA_DIR } from '../lib/trust.js';
import { entityConfiguration, subordinateStatement, jwksOf, WELL_KNOWN } from '../lib/openid-federation.js';
import { page, table, esc } from '../lib/dashboard.js';

const STATEMENT = 'application/entity-statement+jwt';

export async function startTrustAnchor({ dataDir = DATA_DIR, port, host = '127.0.0.1', quiet = false }) {
  const members = JSON.parse(fs.readFileSync(path.join(dataDir, 'federation-members.json'), 'utf8'));
  const ta = members.trust_anchor;
  const keys = loadKeys(ta.entity_id, path.join(dataDir, 'keys'));
  const app = createApp(ta.entity_id);

  app.get(WELL_KNOWN, () =>
    typed(
      entityConfiguration({
        entityId: ta.entity_id,
        key: keys.signing,
        jwks: jwksOf(keys.signing),
        metadata: {
          federation_entity: {
            organization_name: ta.name,
            federation_fetch_endpoint: `${ta.entity_id}/fetch`,
            federation_list_endpoint: `${ta.entity_id}/list`,
          },
          aaf_trust_anchor: { policies: members.policies },
        },
        extra: { trust_mark_issuers: members.trust_mark_issuers },
      }),
      STATEMENT,
    ),
  );
  app.get('/list', ({ query }) => members.members.filter((m) => !query.entity_type || m.entity_type === query.entity_type).map((m) => m.entity_id));
  app.get('/fetch', ({ query }) => {
    const m = members.members.find((x) => x.entity_id === query.sub);
    if (!m) throw new HttpError(404, 'not_found', `${query.sub} is not a subordinate of ${ta.entity_id}`);
    return typed(
      subordinateStatement({ issuer: ta.entity_id, key: keys.signing, sub: m.entity_id, jwks: m.jwks, metadata: { [m.entity_type]: m.metadata } }),
      STATEMENT,
    );
  });
  app.get('/', () =>
    html(
      page(ta.name, `${ta.entity_id} · OpenID Federation trust anchor`, [
        '<h2>Subordinates</h2>',
        table(['entity', 'type', 'name'], members.members.map((m) => [`<code>${esc(m.entity_id)}</code>`, esc(m.entity_type), esc(m.metadata.organization_name)])),
        '<h2>Trust mark issuers</h2>',
        table(['trust mark type', 'may be issued by'], Object.entries(members.trust_mark_issuers).map(([t, list]) => [`<code>${esc(t)}</code>`, esc(list.join(', '))])),
      ]),
    ),
  );

  const server = await app.listen(port, host);
  if (!quiet) console.log(`[${ta.entity_id}] ${ta.name} listening on http://${host}:${port}`);
  return { server, close: () => closeServer(server) };
}

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  const config = loadFederationConfig();
  await startTrustAnchor({ port: config.trustAnchor.port, host: config.listenHost ?? config.host });
}
