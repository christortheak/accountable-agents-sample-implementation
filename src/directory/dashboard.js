// Public status page. Shows only what the directory publishes anyway: counts,
// accreditations and the redacted transparency log. No principal data.
import { page, tiles, table, esc } from '../lib/dashboard.js';
import { decodeJws } from '../lib/crypto.js';

export function directoryDashboard(directory) {
  const s = directory.stats();
  const sth = decodeJws(directory.log.signedTreeHead()).payload;
  const entries = directory.transparencyEntries(Math.max(0, directory.log.size - 40)).reverse();
  return page(directory.name, `${directory.id} · jurisdiction ${directory.jurisdiction} · public view (no principal data)`, [
    tiles([
      ['verified principals', s.verified_principals],
      ['active registrations', s.active_registrations],
      ['revoked registrations', s.revoked_registrations],
      ['PPIDs issued (reusable IDs)', s.pairwise_ppids],
      ['incidents relayed', s.incidents],
      ['log entries', s.log_size],
    ]),
    '<h2>Signed tree head</h2>',
    table(['tree size', 'root hash', 'signed at'], [[sth.tree_size, `<code>${esc(sth.root_hash)}</code>`, new Date(sth.timestamp).toISOString()]]),
    '<h2>Accredited records services (OpenID Federation trust marks issued)</h2>',
    table(
      ['records service', 'roles', 'status'],
      [...directory.accreditations.values()].map((a) => [esc(a.rs), esc(a.roles.join(', ')), `<span class="${a.status === 'active' ? 'ok' : 'bad'}">${esc(a.status)}</span>`]),
    ),
    '<h2>Transparency log (latest 40, redacted)</h2>',
    table(['#', 'event', 'time', 'leaf hash'], entries.map((e) => [e.index, esc(e.type), esc(e.at), `<code>${esc(e.leaf_hash)}</code>`])),
  ]);
}
