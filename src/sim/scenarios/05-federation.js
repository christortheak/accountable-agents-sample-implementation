// Scenario 5: several directories and delegation chains (the paper's "Interoperable"
// advantage, and delegating agents, AG-3). A delegating agent registered in the US
// registers a sub-agent with an EU directory and delegates part of its authority.
import { ServiceError, postJson } from '../../lib/http.js';
import { describePermission } from '../../lib/scope.js';
import { money, short } from '../world.js';
import { whatWasLearned } from '../privacy.js';

export default {
  id: 'federation',
  title: 'Scenario 5 — Federated directories and delegation chains',
  framing:
    'Directories are organized by jurisdiction and federate. An ID must embed its issuing directory, trace to a principal even when its links were issued by different directories, ' +
    'and carry consistent status, so an agent revoked in one directory is treated as revoked by counterparties that query another. Delegated authority may only narrow.',

  async run(world, n) {
    const { regA, regB, ledgerline } = world;

    n.step('An authorizing agent in the US directory');
    const helios = await world.verifiedPrincipal({
      type: 'legal_person', identity: { legal_name: 'Helios Logistics Inc.', jurisdiction: 'US-IL', registration_number: 'IL-0088123' },
      directory: regA, assurance: 'high', method: 'KYB: directory extract + beneficial ownership',
    });
    const dispatch = world.agent('Dispatch');
    await helios.registerAgent(dispatch, { label: 'Dispatch (travel orchestrator)', records: world.records() });
    await helios.grant(dispatch, {
      rs: ledgerline,
      permissions: [{ action: 'commerce.purchase', constraints: { max_amount: money(2000, 'EUR'), categories: ['rail', 'lodging', 'freight'] } }],
      delegation: { allowed: true, max_depth: 1 },
      purpose: 'European freight team travel',
    });
    n.act('Helios Logistics Inc.', `registers Dispatch with ${regA.name}: purchases ≤ €2,000 (rail, lodging, freight); may delegate one level`);

    n.step('Dispatch registers an acting agent with the EU directory');
    const { provenanceId } = await world.provider('Continental Agents GmbH', 'sicherheit@continental-agents.example').publishProvenance(ledgerline, {
      build: 'RailBooker 1.8', components: [{ type: 'model', name: 'mistral-large-3', supplier: 'Mistral AI' }, { type: 'tool', name: 'rail-gds-connector' }],
      incidentResponse: { contact: 'sicherheit@continental-agents.example' },
    });
    const railbooker = world.agent('RailBooker');
    const reg = await dispatch.registerSubagent(railbooker, { directory: regB, label: 'RailBooker (EU)', records: world.records(provenanceId), provider: { name: 'Continental Agents GmbH' } });
    n.act('Dispatch', `proves its own registration to ${regB.name} with a PPID addressed to that directory, then registers RailBooker → chain depth ${reg.depth}`);
    n.say(`Chain: RailBooker @ ${regB.id} → Dispatch @ ${regA.id} → Helios Logistics Inc. (verified legal person). ${regB.name} learns that a verified legal person stands at the top, not who it is.`);
    n.expect(reg.depth === 2, 'cross-directory chain recorded with two links');

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

    n.step('RailBooker books a train at an EU counterparty');
    const railEuropa = await world.counterparty({
      id: 'raileuropa.example', name: 'Rail Europa',
      // Rail Europa accepts agents up to three links from their principal, so it asks for the chain length.
      rules: { 'commerce.purchase': [{ label: 'ticketing', require: { accountability: 'established', authorization: true, maxChainLength: 3 } }] },
      handlers: { 'commerce.purchase': async (p) => ({ ticket: `RE-${Math.floor(Math.random() * 1e6)}`, item: p.item }) },
    });
    const book = await railbooker.act(railEuropa.url, 'commerce.purchase', { item: 'Paris → Lyon, 2nd class', amount: money(129, 'EUR'), category: 'rail' });
    const ev = railEuropa.evidence.at(-1);
    n.decision('Rail Europa', book);
    n.learned('Rail Europa', [...whatWasLearned(ev), `attestation issued by ${ev.directory}; the authority is delegated, not granted directly by the principal`]);
    n.expect(book.decision === 'allow' && ev.chain_length === 2 && ev.directory === regB.id, 'counterparty verifies a two-directory chain through the directory it knows');
    const lodging = await railbooker.act(railEuropa.url, 'commerce.purchase', { item: 'Hotel, Lyon', amount: money(200, 'EUR'), category: 'lodging' });
    n.decision('Rail Europa (hotel)', lodging);
    n.expect(lodging.decision === 'deny', `delegated authority is narrower than the parent's: ${ev.authority_relied_on.map(describePermission).join('; ')}`);

    n.step('An incident report crosses the directories');
    const inc = await railEuropa.fileIncident({ aaf_id: book.aaf_id, directory: regB, summary: 'Booking pattern inconsistent with stated purpose' });
    const notes = (await helios.notifications()).filter((x) => x.kind === 'incident');
    n.act('Rail Europa', `reports to ${regB.name}, which relays to ${regA.name}`);
    n.act('Helios Logistics Inc.', `notified: "${notes.at(-1)?.summary}"`);
    n.expect(inc.principal_notified && notes.length === 1, 'principal notified across directories without the reporter learning who it is');

    n.step('Revocation in one directory is honored in the other');
    const rev = await helios.revokeAgent(dispatch, 'authority_ended');
    n.act('Helios Logistics Inc.', `revokes Dispatch in ${regA.name}; peers notified: ${rev.peers_notified.join(', ') || 'none'}`);
    const after = await railbooker.act(railEuropa.url, 'commerce.purchase', { item: 'Lyon → Paris', amount: money(129, 'EUR'), category: 'rail' }).catch((e) => ({ decision: 'deny', classification: 'REVOKED', reasons: [e.message] }));
    n.decision('Rail Europa (checks Directory B\'s status list)', after);
    const bView = await postJson(`${regB.url}/v1/status`, { aaf_id: book.aaf_id });
    n.act('Directory B', `its own record for RailBooker reads: ${bView.status} (${bView.reason})`);
    n.note(`Directory A pushes the change to Directory B at once. If the push failed, Directory B's cache of upstream status expires within ${world.trust.policies.statusCacheSeconds}s. Counterparties see only INVALID in the status list; the reason stays with the directories.`);
    n.expect(after.decision === 'deny' && after.classification === 'REVOKED' && /upstream/.test(bView.reason), 'the EU sub-agent is treated as revoked because its US parent was');

    n.step('Attribution follows the chain across directories');
    const order = world.court.order({ caseId: 'Tribunal judiciaire de Lyon, RG 26/0412 (via MLAT, simulated)', aaf_ids: [book.aaf_id], counterparty: railEuropa.id, requester: 'Rail Europa' });
    const res = await world.court.trace(regB, { order, aaf_id: book.aaf_id });
    n.detail('chain', res.result.chain.map((c) => `${c.label} @ ${c.directory} [${c.status}]`).join(' → '));
    n.detail('principal', `${res.result.principal.identity.legal_name} (via ${res.result.principal.directory})`);
    n.expect(res.result.chain.length === 2 && res.result.principal.identity.legal_name === 'Helios Logistics Inc.', 'a PPID issued by Directory B resolves to a principal held by Directory A');
  },
};
