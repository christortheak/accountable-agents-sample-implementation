// What a relying party learned from one decision, in plain language.
import { describePermission } from '../lib/scope.js';

/** Plain-language list of what a relying party learned from one evidence record. */
export function whatWasLearned(ev) {
  const items = [];
  if (!ev.ppid) {
    items.push('nothing verifiable about who stands behind the agent');
    return items;
  }
  items.push(`an identifier for this agent, valid only here: ${ev.ppid.slice(0, 44)}… (${ev.ppid_mode})`);
  if (ev.root) {
    const who = ev.root.type === 'natural_person' ? 'a natural person' : 'a legal person (organization)';
    items.push(`${who} stands behind it, verified at assurance "${ev.root.assurance}" by ${ev.root.verifier}; chain length ${ev.chain_length}`);
    if (ev.root.identity) {
      const order = ['legal_name', 'jurisdiction', 'registration_number', 'lei'];
      const shown = order.filter((k) => ev.root.identity[k]).map((k) => ev.root.identity[k]);
      items.push(`identity, disclosed with the principal's consent: ${shown.join(', ')}`);
    }
    else items.push("NOT who the principal is (identity protected; only the registry can resolve it, under legal process)");
  }
  for (const a of ev.attributes ?? []) items.push(`verified principal attribute: ${a.name} = ${a.value}`);
  if (ev.authority_relied_on) {
    items.push(`authority shown: ${ev.authority_relied_on.map(describePermission).join('; ') || '(none for this action)'}`);
  }
  return items;
}
