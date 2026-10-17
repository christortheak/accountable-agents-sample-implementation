// Scenario 7: agent lineages (ephemeral sub-agents, depth limits, cascading
// deregistration) and transfer of an agent, with its sub-agents, to another principal.
import { Principal } from '../../actors/principal.js';
import { short } from '../world.js';
import { sharedHandles, publicValuesOf } from '../privacy.js';

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const query = (dataset) => ({ dataset, rows: 100 });
const attempt = (p) => p.catch((err) => ({ decision: 'refused', classification: '—', reasons: [err.message], error: err }));

export default {
  id: 'lineage',
  title: 'Scenario 7 — Agent lineages and transfer between principals',
  framing:
    'Agents register other agents, so registrations form lineages. Short-lived sub-agents lapse on their own, and a principal can cap how deep a lineage may grow. ' +
    'Deregistering an agent ends it and everything below it. An agent can also be transferred, with its sub-agents, to another principal: both sign, the relationship is new, and the old principal remains answerable for what came before.',

  async run(world, n) {
    const { ledgerline } = world;
    const datamart = await world.relyingParty({
      id: 'datamart.example', name: 'DataMart',
      rules: { 'data.query': [{ label: 'licensed data', require: { accountability: 'established', authorization: true } }] },
      handlers: { 'data.query': async (p) => ({ dataset: p.dataset, rows: p.rows }) },
    });
    const dataGrant = (depth) => ({ rk: ledgerline, permissions: [{ action: 'data.query' }], delegation: { allowed: depth > 0, max_depth: depth } });

    n.step('A lineage with a depth budget');
    const orchard = await world.verifiedPrincipal({
      type: 'legal_person', identity: { legal_name: 'Orchard Analytics LLC', jurisdiction: 'US-WA', registration_number: 'WA-604112877' },
      assurance: 'high', method: 'KYB: registry extract',
    });
    const atlas = world.agent('Atlas');
    await orchard.registerAgent(atlas, { label: 'Atlas (research orchestrator)', records: world.records(), lineage: { max_depth: 2 } });
    await orchard.grant(atlas, dataGrant(2));
    n.act('Orchard Analytics LLC', 'registers Atlas and caps its lineage at two levels of sub-agents');

    n.step('Ephemeral task agents');
    const started = performance.now();
    const tasks = [];
    for (let i = 1; i <= 25; i++) {
      const t = world.agent(`task-${i}`);
      await atlas.registerSubagent(t, { label: `task-${i}`, records: world.records(), expiresIn: 1.5 });
      tasks.push(t);
    }
    const spawnMs = Math.round(performance.now() - started);
    n.act('Atlas', `spawns 25 task agents that expire in 1.5 s (${spawnMs} ms in total, including signing)`);
    const helper = world.agent('task-1/helper');
    const helperReg = await tasks[0].registerSubagent(helper, { label: 'task-1 helper', records: world.records(), expiresIn: 3600 });
    const clampedMs = Date.parse(helperReg.expires_at) - Date.now();
    n.act('task-1', `registers a helper and asks for an hour; the registry clamps it to its parent's lifetime (${(clampedMs / 1000).toFixed(1)} s left)`);
    n.expect(clampedMs < 1600, 'no sub-agent outlives its parent');
    const tooDeep = await attempt(helper.registerSubagent(world.agent('too-deep'), { label: 'too deep', records: world.records() }));
    n.act('task-1 helper', `tries to add a third level → ${tooDeep.reasons?.[0] ?? 'accepted'}`);
    n.expect(tooDeep.error?.code === 'lineage_depth_exceeded', "Atlas's lineage budget is enforced at every level below it");

    for (const t of tasks.slice(0, 3)) await atlas.delegate(t, { permissions: [{ action: 'data.query' }], validForDays: 1 });
    const live = [];
    for (const t of tasks.slice(0, 3)) live.push(await t.act(datamart.url, 'data.query', query('weather-2026')));
    n.decision('DataMart ← task-1..3 (while alive)', live.every((r) => r.decision === 'allow') ? live[0] : live.find((r) => r.decision !== 'allow'));
    await sleep(1600);
    const lapsed = await attempt(tasks[1].act(datamart.url, 'data.query', query('weather-2026')));
    const lapsedHelper = await attempt(helper.contextFor('datamart.example'));
    n.act('task-2 (after 1.5 s)', `asks for fresh credentials → ${lapsed.reasons?.[0]}`);
    n.act('task-1 helper', `→ ${lapsedHelper.reasons?.[0] ?? 'issued'}`);
    n.expect(live.every((r) => r.decision === 'allow') && lapsed.error?.code === 'registration_inactive' && lapsedHelper.error?.code === 'registration_inactive',
      'ephemeral agents work while alive, then lapse on their own, together with anything they spawned');

    n.step('Deregistration ends an agent and everything below it');
    const scout = world.agent('Scout');
    const fetcher = world.agent('Fetcher');
    const courier = world.agent('Courier');
    const courierSub = world.agent('Courier/sub');
    await atlas.registerSubagent(scout, { label: 'Scout', records: world.records() });
    await atlas.delegate(scout, { permissions: [{ action: 'data.query' }], delegation: { allowed: true, max_depth: 1 } });
    await scout.registerSubagent(fetcher, { label: 'Fetcher', records: world.records() });
    await scout.delegate(fetcher, { permissions: [{ action: 'data.query' }] });
    await atlas.registerSubagent(courier, { label: 'Courier', records: world.records() });
    await atlas.delegate(courier, { permissions: [{ action: 'data.query' }], delegation: { allowed: true, max_depth: 1 } });
    await courier.registerSubagent(courierSub, { label: 'Courier/sub', records: world.records() });
    await courier.delegate(courierSub, { permissions: [{ action: 'data.query' }] });
    const dereg = await atlas.revokeSubagent(courier, 'principal_request');
    n.act('Atlas', `deregisters Courier → ${dereg.status}, cascading to ${dereg.cascades_to} sub-agent(s)`);
    const results = {};
    for (const a of [atlas, scout, fetcher, courier, courierSub]) results[a.name] = await attempt(a.act(datamart.url, 'data.query', query('census')));
    n.table(['agent', 'decision', 'why'], Object.entries(results).map(([k, r]) => [k, r.decision, r.reasons?.join('; ') || '—']));
    n.expect(
      results.Atlas.decision === 'allow' && results.Scout.decision === 'allow' && results.Fetcher.decision === 'allow' &&
        results.Courier.decision !== 'allow' && results['Courier/sub'].decision !== 'allow',
      'the deregistered branch is cut off; the rest of the lineage keeps working',
    );

    n.step('Atlas is sold, with its sub-agents, to another principal');
    const meridian = await world.verifiedPrincipal({
      type: 'legal_person', identity: { legal_name: 'Meridian Research Inc.', jurisdiction: 'US-NY', registration_number: 'NY-7740021' },
      assurance: 'high', method: 'KYB: registry extract + beneficial ownership',
    });
    const before = { atlas: results.Atlas.ppid, scout: results.Scout.ppid };
    const oldAtlasCtx = atlas.contexts.get(datamart.id);
    const oldGrant = atlas.grants[0];

    const unverified = new Principal({
      type: 'legal_person', identity: { legal_name: 'Unvetted Holdings Ltd', jurisdiction: 'US-NV' }, registry: world.regA, trust: world.trust,
    });
    await unverified.enroll();
    const badOffer = await orchard.offerTransfer(atlas, unverified);
    const badAccept = await attempt(unverified.acceptTransfer(badOffer.offer_id, world.agent('x')));
    await orchard.cancelTransfer(badOffer.offer_id);
    n.act('Unvetted Holdings Ltd', `tries to accept an offer of Atlas → ${badAccept.reasons?.[0]}`);
    n.expect(badAccept.error?.code === 'principal_not_verified', 'an agent can only pass to a verified principal');

    const offer = await orchard.offerTransfer(atlas, meridian, { subtree: 'move' });
    n.act('Orchard Analytics LLC', `signs an offer of Atlas and its lineage to Meridian (${short(offer.offer_id, 14)}, valid 7 days)`);
    const offered = (await meridian.notifications()).find((x) => x.kind === 'transfer_offer');
    n.act('Meridian Research Inc.', `is notified of the offer (${offered?.agent_label}, ${offered?.descendants} sub-agent(s)) and signs its acceptance with a fresh key for Atlas`);
    const accepted = await meridian.acceptTransfer(offer.offer_id, atlas);
    n.act('Registry A', `records the transfer: ${accepted.descendants_moved} sub-agent(s) move with Atlas; every old PPID in the lineage is now "transferred"`);
    n.expect(accepted.descendants_moved === 2, 'Scout and Fetcher move with Atlas (the deregistered branch stays deregistered)');

    n.step('The old relationship has ended');
    const replay = await world.handBuiltRequest({ rp: datamart, action: 'data.query', params: query('census'), accountability: oldAtlasCtx.attestation, authorization: oldAtlasCtx.authorization, proofKey: oldAtlasCtx.key });
    n.decision("DataMart ← Atlas's pre-transfer credentials", replay);
    atlas.addGrant(oldGrant);
    const oldAuthority = await attempt(atlas.act(datamart.url, 'data.query', query('census')));
    atlas.grants = [];
    n.act('Atlas', `tries to exercise Orchard's grant under Meridian → ${oldAuthority.reasons?.[0] ?? oldAuthority.decision}`);
    n.expect(replay.decision === 'deny' && /custody_transferred/.test(replay.reasons.join()) && oldAuthority.decision !== 'allow',
      "credentials and authority from the old principal no longer work");

    n.step('Meridian grants authority afresh; the lineage carries on');
    const receivedBefore = datamart.received.length - 1; // everything before the replay above
    const newGrant = await meridian.grant(atlas, dataGrant(2));
    n.act('Meridian Research Inc.', `grants Atlas data access; Ledgerline marks Orchard's earlier grant superseded (${newGrant.superseded.length})`);
    const after = await atlas.act(datamart.url, 'data.query', query('census'));
    const refreshed = await scout.refreshReceipt();
    await atlas.delegate(scout, { permissions: [{ action: 'data.query' }], delegation: { allowed: true, max_depth: 1 } });
    const scoutAfter = await scout.act(datamart.url, 'data.query', query('census'));
    n.decision('DataMart ← Atlas', after);
    n.decision('DataMart ← Scout', scoutAfter);
    n.detail('Atlas PPID at DataMart', `${short(before.atlas.split(':').pop(), 12)} → ${short(after.ppid.split(':').pop(), 12)}`);
    n.detail('Scout PPID at DataMart', `${short(before.scout.split(':').pop(), 12)} → ${short(scoutAfter.ppid.split(':').pop(), 12)} (receipt version ${refreshed.version})`);
    n.expect(after.decision === 'allow' && scoutAfter.decision === 'allow' && after.ppid !== before.atlas && scoutAfter.ppid !== before.scout,
      'new principal, new relationship, new PPIDs; sub-agents continue once re-authorized');
    const shared = sharedHandles(datamart.received.slice(0, receivedBefore), datamart.received.slice(receivedBefore + 1), publicValuesOf(world.trust, [datamart.id]));
    n.detail('values shared before and after the transfer', shared.length ? shared.map((x) => x.whereA).join(', ') : 'none');
    n.expect(shared.length === 0, "DataMart cannot link Meridian's use of Atlas to Orchard's history from what it was shown");

    n.step('Who answers for what: accountability follows the time of the conduct');
    const order = world.court.order({ caseId: 'DataMart v. Does (licence audit)', ppids: [before.atlas, after.ppid], relyingParty: datamart.id, requester: 'DataMart' });
    const r0 = await world.court.resolve(world.regA, { order, ppid: before.atlas });
    const r1 = await world.court.resolve(world.regA, { order, ppid: after.ppid });
    n.detail(`pre-transfer PPID (${r0.result.ppid_status})`, `${r0.result.root_principal.identity.legal_name}; current holder ${r0.result.current_principal?.legal_name}`);
    n.detail('post-transfer PPID', r1.result.root_principal.identity.legal_name);
    n.detail('custody history', r1.result.chain[0].custody.map((c) => `${c.principal} (${c.from.slice(11, 19)}–${c.to ? c.to.slice(11, 19) : 'now'})`).join(' → '));
    n.expect(r0.result.root_principal.identity.legal_name === 'Orchard Analytics LLC' && r1.result.root_principal.identity.legal_name === 'Meridian Research Inc.',
      'the old principal answers for conduct before the transfer; the new one for conduct after');

    n.step('A transfer can also end the lineage instead of moving it');
    const northgate = await world.verifiedPrincipal({
      type: 'legal_person', identity: { legal_name: 'Northgate Labs Inc.', jurisdiction: 'US-MA' }, assurance: 'high', method: 'KYB: registry extract',
    });
    const offer2 = await meridian.offerTransfer(atlas, northgate, { subtree: 'end' });
    const accepted2 = await northgate.acceptTransfer(offer2.offer_id, atlas);
    const scoutEnded = await attempt(scout.act(datamart.url, 'data.query', query('census')));
    n.act('Meridian → Northgate', `transfers Atlas alone: ${accepted2.descendants_ended} sub-agent(s) deregistered`);
    n.act('Scout', `→ ${scoutEnded.reasons?.[0] ?? scoutEnded.decision}`);
    n.expect(accepted2.descendants_ended === 2 && scoutEnded.decision !== 'allow', 'sub-agents left behind are deregistered, not handed over');
  },
};
