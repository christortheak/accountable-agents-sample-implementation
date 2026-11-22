// What a counterparty learned from one decision, in plain language.
import { describePermission } from '../lib/scope.js';

/** Plain-language list of what a counterparty learned from one evidence record. */
export function whatWasLearned(ev) {
  const items = [];
  if (!ev.aaf_id) {
    items.push('nothing verifiable about who stands behind the agent');
    return items;
  }
  const kind = ev.id_mode === 'unlinkable' ? 'single-use ID' : 'PPID, the same at every visit here';
  items.push(`an ID for this agent, valid only here: ${ev.aaf_id.slice(0, 44)}… (${kind})`);
  items.push(`that ${ev.directory ?? 'its directory'} verified a principal who answers for it`);
  const principal = ev.principal ?? {};
  const more = [
    principal.type && (principal.type === 'natural_person' ? 'the principal is a natural person' : 'the principal is a legal person (organization)'),
    principal.assurance && `verified at assurance "${principal.assurance}"`,
    principal.verifier && `by ${principal.verifier}`,
    ev.chain_length != null && `chain length ${ev.chain_length}`,
  ].filter(Boolean);
  if (more.length) items.push(`because it asked: ${more.join(', ')}`);
  if (principal.identity) {
    const order = ['legal_name', 'jurisdiction', 'registration_number', 'lei'];
    const shown = order.filter((k) => principal.identity[k]).map((k) => principal.identity[k]);
    items.push(`identity, disclosed with the principal's consent: ${shown.join(', ')}`);
  } else items.push('NOT who the principal is (identity protected; only the directory can recover it, under legal process)');
  for (const a of ev.attributes ?? []) items.push(`verified principal attribute: ${a.name} = ${a.value}`);
  if (ev.authority_relied_on) {
    items.push(`authority shown: ${ev.authority_relied_on.map(describePermission).join('; ') || '(none for this action)'}`);
  }
  return items;
}
