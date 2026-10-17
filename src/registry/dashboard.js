// Public status page. Shows only what the registry publishes anyway: counts,
// accreditations and the redacted transparency log. No principal data.
import { page, tiles, table, esc } from '../lib/dashboard.js';
import { decodeJws } from '../lib/crypto.js';

export function registryDashboard(registry) {
  const s = registry.stats();
  const sth = decodeJws(registry.log.signedTreeHead()).payload;
  const entries = registry.transparencyEntries(Math.max(0, registry.log.size - 40)).reverse();
  return page(registry.name, `${registry.id} · jurisdiction ${registry.jurisdiction} · public view (no principal data)`, [
    tiles([
      ['verified principals', s.verified_principals],
      ['active registrations', s.active_registrations],
      ['revoked registrations', s.revoked_registrations],
      ['pairwise PPIDs issued', s.pairwise_ppids],
      ['incidents relayed', s.incidents],
      ['log entries', s.log_size],
    ]),
    '<h2>Signed tree head</h2>',
    table(['tree size', 'root hash', 'signed at'], [[sth.tree_size, `<code>${esc(sth.root_hash)}</code>`, new Date(sth.timestamp).toISOString()]]),
    '<h2>Accredited record keepers (OpenID Federation trust marks issued)</h2>',
    table(
      ['record keeper', 'roles', 'status'],
      [...registry.accreditations.values()].map((a) => [esc(a.rk), esc(a.roles.join(', ')), `<span class="${a.status === 'active' ? 'ok' : 'bad'}">${esc(a.status)}</span>`]),
    ),
    '<h2>Transparency log (latest 40, redacted)</h2>',
    table(['#', 'event', 'time', 'leaf hash'], entries.map((e) => [e.index, esc(e.type), esc(e.at), `<code>${esc(e.leaf_hash)}</code>`])),
  ]);
}
