// Scenario 5: federation and delegation chains (paper §3.1 "Registries", Figure 0's
// authorizing agent and acting agent). A parent agent registered in the US
// registers a sub-agent with an EU registry and delegates part of its authority.
import { ServiceError, postJson } from '../../lib/http.js';
import { describePermission } from '../../lib/scope.js';
import { money, short } from '../world.js';
import { whatWasLearned } from '../privacy.js';

export default {
  id: 'federation',
  title: 'Scenario 5 — Federated registries and delegation chains',
  framing:
    'Registries are organized by jurisdiction and federate. A PPID must embed its issuing registry, resolve to a root principal even when its links were issued by different registries, ' +
    'and carry consistent status, so an agent revoked in one registry is treated as revoked by relying parties that query another. Delegated authority may only narrow.',

  async run(world, n) {
    const { regA, regB, ledgerline } = world;

    n.step('An authorizing agent in the US registry');
    const helios = await world.verifiedPrincipal({
      type: 'legal_person', identity: { legal_name: 'Helios Logistics Inc.', jurisdiction: 'US-IL', registration_number: 'IL-0088123' },
      registry: regA, assurance: 'high', method: 'KYB: registry extract + beneficial ownership',
    });
    const dispatch = world.agent('Dispatch');
    await helios.registerAgent(dispatch, { label: 'Dispatch (travel orchestrator)', records: world.records() });
    await helios.grant(dispatch, {
      rk: ledgerline,
      permissions: [{ action: 'commerce.purchase', constraints: { max_amount: money(2000, 'EUR'), categories: ['rail', 'lodging', 'freight'] } }],
      delegation: { allowed: true, max_depth: 1 },
      purpose: 'European freight team travel',
    });
    n.act('Helios Logistics Inc.', `registers Dispatch with ${regA.name}: purchases ≤ €2,000 (rail, lodging, freight); may delegate one level`);

    n.step('Dispatch registers an acting agent with the EU registry');
    const { provenanceId } = await world.provider('Continental Agents GmbH', 'sicherheit@continental-agents.example').publishProvenance(ledgerline, {
      build: 'RailBooker 1.8', components: [{ type: 'model', name: 'mistral-large-3', supplier: 'Mistral AI' }, { type: 'tool', name: 'rail-gds-connector' }],
      incidentResponse: { contact: 'sicherheit@continental-agents.example' },
    });
    const railbooker = world.agent('RailBooker');
    const reg = await dispatch.registerSubagent(railbooker, { registry: regB, label: 'RailBooker (EU)', records: world.records(provenanceId), provider: { name: 'Continental Agents GmbH' } });
    n.act('Dispatch', `proves its own registration to ${regB.name} with a PPID addressed to that registry, then registers RailBooker → chain depth ${reg.depth}`);
    n.say(`Chain: RailBooker @ ${regB.id} → Dispatch @ ${regA.id} → Helios Logistics Inc. (verified legal person). ${regB.name} learns that a verified legal person stands at the top, not who it is.`);
    n.expect(reg.depth === 2, 'cross-registry chain recorded with two links');

    n.step('Delegation can only narrow authority');
    let over;
    try {
      await dispatch.delegate(railbooker, { permissions: [{ action: 'commerce.purchase', constraints: { max_amount: money(10000, 'EUR'), categories: ['rail'] } }] });
    } catch (err) {
      over = err;
    }
    n.act('Dispatch', `tries to delegate €10,000 of purchasing → ${over instanceof ServiceError ? `rejected by ${ledgerline.name}: ${over.message}` : 'accepted (!)'}`);
    n.expect(over?.code === 'exceeds_parent_authority', 'over-delegation rejected at deposit');
    const delegated = await dispatch.delegate(railbooker, { permissions: [{ action: 'commerce.purchase', constraints: { max_amount: money(400, 'EUR'), categories: ['rail'] } }], validForDays: 7 });
    n.act('Dispatch', `delegates purchases ≤ €400 (rail only) for 7 days → ${short(delegated.grant_id, 16)}`);

    n.step('RailBooker books a train at an EU relying party');
    const railEuropa = await world.relyingParty({
      id: 'raileuropa.example', name: 'Rail Europa',
      rules: { 'commerce.purchase': [{ label: 'ticketing', require: { accountability: 'established', authorization: true } }] },
      handlers: { 'commerce.purchase': async (p) => ({ ticket: `RE-${Math.floor(Math.random() * 1e6)}`, item: p.item }) },
    });
    const book = await railbooker.act(railEuropa.url, 'commerce.purchase', { item: 'Paris → Lyon, 2nd class', amount: money(129, 'EUR'), category: 'rail' });
    const ev = railEuropa.evidence.at(-1);
    n.decision('Rail Europa', book);
    n.learned('Rail Europa', [...whatWasLearned(ev), `attestation issued by ${ev.registry}; the authority is delegated, not granted directly by the principal`]);
    n.expect(book.decision === 'allow' && ev.chain_length === 2 && ev.registry === regB.id, 'relying party verifies a two-registry chain through the registry it knows');
    const lodging = await railbooker.act(railEuropa.url, 'commerce.purchase', { item: 'Hotel, Lyon', amount: money(200, 'EUR'), category: 'lodging' });
    n.decision('Rail Europa (hotel)', lodging);
    n.expect(lodging.decision === 'deny', `delegated authority is narrower than the parent's: ${ev.authority_relied_on.map(describePermission).join('; ')}`);

    n.step('An incident report crosses the registries');
    const inc = await railEuropa.fileIncident({ ppid: book.ppid, registry: regB, summary: 'Booking pattern inconsistent with stated purpose' });
    const notes = (await helios.notifications()).filter((x) => x.kind === 'incident');
    n.act('Rail Europa', `reports to ${regB.name}, which relays to ${regA.name}`);
    n.act('Helios Logistics Inc.', `notified: "${notes.at(-1)?.summary}"`);
    n.expect(inc.principal_notified && notes.length === 1, 'root principal notified across registries without the reporter learning who it is');

    n.step('Revocation in one registry is honored in the other');
    const rev = await helios.revokeAgent(dispatch, 'authority_ended');
    n.act('Helios Logistics Inc.', `revokes Dispatch in ${regA.name}; peers notified: ${rev.peers_notified.join(', ') || 'none'}`);
    const after = await railbooker.act(railEuropa.url, 'commerce.purchase', { item: 'Lyon → Paris', amount: money(129, 'EUR'), category: 'rail' }).catch((e) => ({ decision: 'deny', classification: 'REVOKED', reasons: [e.message] }));
    n.decision('Rail Europa (checks Registry B\'s status list)', after);
    const bView = await postJson(`${regB.url}/v1/status`, { ppid: book.ppid });
    n.act('Registry B', `its own record for RailBooker reads: ${bView.status} (${bView.reason})`);
    n.note(`Registry A pushes the change to Registry B at once. If the push failed, Registry B's cache of upstream status expires within ${world.trust.policies.statusCacheSeconds}s. Relying parties see only INVALID in the status list; the reason stays with the registries.`);
    n.expect(after.decision === 'deny' && after.classification === 'REVOKED' && /upstream/.test(bView.reason), 'the EU sub-agent is treated as revoked because its US parent was');

    n.step('Resolution follows the chain across registries');
    const order = world.court.order({ caseId: 'Tribunal judiciaire de Lyon, RG 26/0412 (via MLAT, simulated)', ppids: [book.ppid], relyingParty: railEuropa.id, requester: 'Rail Europa' });
    const res = await world.court.resolve(regB, { order, ppid: book.ppid });
    n.detail('chain', res.result.chain.map((c) => `${c.label} @ ${c.registry} [${c.status}]`).join(' → '));
    n.detail('root principal', `${res.result.root_principal.identity.legal_name} (via ${res.result.root_principal.registry})`);
    n.expect(res.result.chain.length === 2 && res.result.root_principal.identity.legal_name === 'Helios Logistics Inc.', 'a PPID issued by Registry B resolves to a root principal held by Registry A');
  },
};
