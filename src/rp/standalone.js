// A standalone relying party for live transactions:
//   node src/rp/standalone.js --config config/rp.local.json
//
// Policy comes from the config file. Nothing real is bought or provided: each
// allowed action returns a reference number. The home page shows every
// decision, the checks behind it, and what the relying party learned.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { generateSigningKey, keyFromJwk, randomId } from '../lib/crypto.js';
import { html } from '../lib/http.js';
import { discoverWithRetry, fetchTrustAnchor, loadTrustAnchor, fileNameFor, DATA_DIR } from '../lib/trust.js';
import { page, table, tiles, esc } from '../lib/dashboard.js';
import { describePermission } from '../lib/scope.js';
import { startRelyingParty } from './server.js';
import { whatWasLearned } from './learned.js';

const OPS = {
  '<=': (a, b) => a <= b, '<': (a, b) => a < b, '>=': (a, b) => a >= b, '>': (a, b) => a > b,
  '==': (a, b) => a === b, '!=': (a, b) => a !== b, in: (a, b) => Array.isArray(b) && b.includes(a),
};

/** Turn a declarative condition { param: "amount.value", op: "<=", value: 20 } into a predicate. */
function predicate(when) {
  if (!when) return undefined;
  const op = OPS[when.op] ?? (() => false);
  return (params) => op(String(when.param).split('.').reduce((o, k) => (o == null ? undefined : o[k]), params), when.value);
}

function rulesFrom(config) {
  return Object.fromEntries(Object.entries(config.rules).map(([action, tiers]) => [action, tiers.map((t) => ({ ...t, when: predicate(t.when) }))]));
}

/** Keep the relying party's signing key across restarts, so its log entries stay attributable. */
function persistentKey(id) {
  const file = path.join(DATA_DIR, `rp-${fileNameFor(id)}.json`);
  if (fs.existsSync(file)) return keyFromJwk(JSON.parse(fs.readFileSync(file, 'utf8')).signing);
  const key = generateSigningKey();
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.writeFileSync(file, JSON.stringify({ signing: key.privateJwk }, null, 2), { mode: 0o600 });
  return key;
}

async function trustAnchorFrom(config) {
  if (config.trustAnchor === 'local') return loadTrustAnchor();
  const deadline = Date.now() + Number(process.env.AAF_STARTUP_TIMEOUT_SECONDS ?? 15) * 1000;
  for (;;) {
    try {
      return await fetchTrustAnchor(config.trustAnchor.url, { pin: config.trustAnchor.pin ?? undefined, entityId: config.trustAnchor.entityId ?? undefined });
    } catch (err) {
      if (Date.now() > deadline) throw err;
      await new Promise((r) => setTimeout(r, 1000));
    }
  }
}

export async function startStandaloneRp(config, { quiet = false } = {}) {
  const trust = await discoverWithRetry(await trustAnchorFrom(config));
  const rp = await startRelyingParty({
    id: config.id,
    name: config.name,
    port: config.port,
    host: config.listenHost ?? '127.0.0.1',
    publicUrl: config.publicUrl,
    key: persistentKey(config.id),
    trust,
    requests: config.requests ?? {},
    rules: rulesFrom(config),
    handlers: Object.fromEntries(Object.keys(config.rules).map((action) => [action, async () => ({ reference: randomId('ref', 8), note: 'simulated: nothing real was bought or provided' })])),
    routes: (app, self) => {
      app.get('/', () => html(dashboard(self, config)));
      app.get('/v1/decisions', () => ({ decisions: self.evidence.slice(-100).map(({ status_tokens: _t, ...e }) => e) }));
    },
  });
  // Keep the evidence list bounded in a long-running process.
  setInterval(() => {
    if (rp.evidence.length > 1000) rp.evidence.splice(0, rp.evidence.length - 1000);
    if (rp.received.length > 1000) rp.received.splice(0, rp.received.length - 1000);
  }, 60000).unref();
  if (!quiet) console.log(`[${config.id}] ${config.name} listening on ${rp.url} (port ${config.port})`);
  return rp;
}

function dashboard(rp, config) {
  const recent = rp.evidence.slice(-40).reverse();
  const count = (d) => rp.evidence.filter((e) => e.decision === d).length;
  const policyRows = Object.entries(config.rules).flatMap(([action, tiers]) =>
    tiers.map((t) => [
      `<code>${esc(action)}</code>`,
      esc(t.label),
      esc(t.when ? `${t.when.param} ${t.when.op} ${JSON.stringify(t.when.value)}` : 'otherwise'),
      esc(Object.entries(t.require).map(([k, v]) => `${k}: ${v}`).join(', ')),
    ]),
  );
  return page(config.name, `${rp.id} · a relying party in an Accountable Agents federation · simulated: nothing real is bought`, [
    tiles([['decisions', rp.evidence.length], ['allowed', count('allow')], ['denied', count('deny')], ['step-up or deferred', count('step_up') + count('deferred')]]),
    '<h2>Policy</h2>',
    table(['action', 'tier', 'when', 'requires'], policyRows),
    '<h2>Recent decisions</h2>',
    recent.length
      ? table(
          ['time', 'action', 'decision', 'what this relying party learned', 'why'],
          recent.map((e) => [
            esc(e.at.slice(11, 19)),
            `<code>${esc(e.action)}</code>`,
            `<b class="${e.decision === 'allow' ? 'ok' : 'bad'}">${esc(e.decision)}</b><br><span class="mono">${esc(e.classification)}</span>`,
            whatWasLearned(e).map(esc).join('<br>'),
            esc((e.reasons ?? []).join('; ') || (e.authority_relied_on?.length ? `authorized: ${e.authority_relied_on.map(describePermission).join('; ')}` : 'open to everyone')),
          ]),
        )
      : '<p>No requests yet. Try: <code>aaf act &lt;agent&gt; ' + esc(rp.url) + ' &lt;action&gt;</code></p>',
  ]);
}

if (process.argv[1] && fs.realpathSync(process.argv[1]) === fileURLToPath(import.meta.url)) {
  const i = process.argv.indexOf('--config');
  const configFile = i > 0 ? process.argv[i + 1] : 'config/rp.local.json';
  await startStandaloneRp(JSON.parse(fs.readFileSync(path.resolve(configFile), 'utf8')));
}
