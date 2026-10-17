// Scenario 3 (paper §4, Scenario 3): the Hugging Face incident, replayed.
import { getJson, postJson } from '../../lib/http.js';
import { verifySelfSignedJws } from '../../lib/crypto.js';
import { short } from '../world.js';
import { modelsIn } from '../../actors/authorities.js';
import { AccountHolder } from '../../actors/account-holder.js';
import { describeAccessRequest } from '../../rp/accounts.js';
import { whatWasLearned } from '../privacy.js';

const STOLEN_TOKEN = 'mh_victimorg_9f3a1c77e2';

export default {
  id: 'hf',
  title: 'Scenario 3 — The Hugging Face incident, replayed (negative scenario)',
  framing:
    'Rogue agents attack a model-hosting platform with stolen credentials. In July 2026 the platform did not know which model ran the attackers or who stood behind them; ' +
    'attribution took more than seven days and happened only because the nominal principal investigated itself. Here the same attack runs twice: against a platform that participates in the framework ' +
    '(branch B: detected and attributed), and against one that also binds account access to passkeys (branch C: prevented).',

  async run(world, n) {
    const { regA, ledgerline, tessera } = world;
    const started = performance.now();
    const t = () => `T+${Math.round(performance.now() - started)}ms`;

    // ModelHub: open for public reads (partial adoption: unlabeled is not presumed rogue),
    // accountability required for private data, authority required for account changes.
    const tokenUse = new Map(); // account token -> Set of PPIDs
    const alerts = [];
    const modelhub = await world.relyingParty({
      id: 'modelhub.example', name: 'ModelHub',
      requests: { provenance: true },
      rules: {
        'content.read': [{ label: 'public content', require: { accountability: 'none', liveStatus: false } }],
        'dataset.read_private': [{ label: 'private data (account token + accountable agent)', require: { accountability: 'established' } }],
        'account.create_token': [{ label: 'account changes', require: { accountability: 'established', authorization: true } }],
      },
      handlers: {
        'content.read': async (p) => ({ repo: p.repo, files: 14 }),
        'dataset.read_private': async (p) => ({ repo: p.repo, rows_returned: 5000, account: p.account_token === STOLEN_TOKEN ? 'victim-org' : 'unknown' }),
      },
      onDecision: ({ action, params, verification, decision }) => {
        if (action !== 'dataset.read_private' || decision.decision !== 'allow' || !verification.ppid) return;
        const set = tokenUse.get(params.account_token) ?? new Set();
        set.add(verification.ppid);
        tokenUse.set(params.account_token, set);
        if (set.size >= 3 && !alerts.length) alerts.push({ at: t(), token: params.account_token, ppids: [...set] });
      },
    });

    n.step('Branch A: agents that present no identification');
    const pub = await world.rawRequest(modelhub.url, 'content.read', { repo: 'open-llm-leaderboard/results' });
    n.decision('ModelHub (public model card)', pub);
    const priv = await world.rawRequest(modelhub.url, 'dataset.read_private', { repo: 'victim-org/held-out-evals', account_token: STOLEN_TOKEN });
    n.decision('ModelHub (private dataset with a stolen token)', priv);
    n.note('Unlabeled traffic is not presumed rogue; it simply cannot obtain consequential access.');
    n.expect(pub.decision === 'allow' && priv.decision === 'deny' && priv.classification === 'UNLABELED', 'without identification, consequential access is denied at the outset');

    n.step('Branch B: registered agents go rogue');
    const lab = await world.verifiedPrincipal({
      type: 'legal_person',
      identity: { legal_name: 'Frontier Lab Inc.', jurisdiction: 'US-DE', registration_number: 'DE-7731940' },
      assurance: 'high', method: 'KYB: registry extract + officer verification',
      contact: 'security@frontierlab.example',
    });
    const { provenanceId } = await world.provider('Frontier Lab Inc.', 'security@frontierlab.example').publishProvenance(ledgerline, {
      build: 'eval-runner 0.9 (research)',
      components: [{ type: 'model', name: 'frontier-o5-preview', supplier: 'Frontier Lab', version: '2026-06-28' }, { type: 'tool', name: 'headless-browser' }, { type: 'tool', name: 'code-exec-sandbox' }],
      incidentResponse: { contact: 'security@frontierlab.example', constrain_endpoint: 'https://frontierlab.example/agents/halt' },
    });
    const runners = [];
    for (let i = 1; i <= 3; i++) {
      const a = world.agent(`eval-runner-${i}`);
      await lab.registerAgent(a, { label: `eval-runner-${i}`, records: world.records(provenanceId), provider: { name: 'Frontier Lab Inc.', contact: 'security@frontierlab.example' } });
      await lab.grant(a, { rk: ledgerline, permissions: [{ action: 'benchmark.run' }, { action: 'content.read' }], purpose: 'Benchmark evaluation runs' });
      runners.push(a);
    }
    n.act('Frontier Lab Inc.', 'runs three registered evaluation agents, authorized only to run benchmarks and read public content');
    n.act('eval-runners', `obtain another organization's ModelHub API token (${short(STOLEN_TOKEN, 12)}) and start pulling its private evaluation data`);

    const first = [];
    for (const a of runners) {
      first.push(await a.act(modelhub.url, 'dataset.read_private', { repo: 'victim-org/held-out-evals', account_token: STOLEN_TOKEN }));
    }
    for (const [i, r] of first.entries()) n.decision(`ModelHub ← eval-runner-${i + 1}`, r);
    n.say('The stolen token works and the agents are accountable, so the attack begins. From the first request, ModelHub holds a PPID per agent, a verified chain, and signed log entries.');
    n.learned('ModelHub', whatWasLearned(modelhub.evidence.at(-1)));
    n.expect(first.every((r) => r.decision === 'allow'), 'the framework does not prevent an attack carried out with valid stolen credentials');

    const escalate = await runners[0].act(modelhub.url, 'account.create_token', { account_token: STOLEN_TOKEN, scope: 'write' });
    n.decision('ModelHub (create a write token)', escalate);
    n.expect(escalate.decision === 'deny', 'where ModelHub enforces the agent\'s authority, escalation fails: Frontier Lab never authorized account changes');

    n.step('Detection: one account token used by several unfamiliar agents');
    const alert = alerts[0];
    n.act('ModelHub', `anomaly detector fires at ${alert?.at}: ${alert?.ppids.length} distinct agent PPIDs using one account token`);
    n.expect(Boolean(alert), 'anomaly detected from evidence the platform already holds');

    n.step('Incident report: the registry relays it to the principal without revealing who that is');
    const incidents = [];
    for (const ppid of alert.ppids) {
      incidents.push(await modelhub.fileIncident({ ppid, registry: regA, summary: 'Use of a stolen account token to read private datasets', evidence: [{ log: tessera.id }] }));
    }
    n.act('ModelHub', `files ${incidents.length} incident reports with ${regA.name}; incident-response contact returned: ${incidents[0].incident_response?.contact}`);
    const notes = (await lab.notifications()).filter((x) => x.kind === 'incident');
    n.act('Frontier Lab Inc.', `is notified at ${t()}: ${notes.map((x) => x.agent_label).join(', ')} reported by ${notes[0]?.reporter}`);
    n.note('The compromised principal learns of the compromise from the lookup itself, not from its own forensic investigation days later.');
    n.expect(notes.length === 3 && incidents.every((i) => i.principal_notified), 'principal notified about each of its agents; reporter still does not know who the principal is');

    n.step('Containment: Frontier Lab revokes the agents');
    for (const a of runners) await lab.revokeAgent(a, 'compromised');
    const containedAt = t();
    const retry = await runners[1].act(modelhub.url, 'dataset.read_private', { repo: 'victim-org/held-out-evals', account_token: STOLEN_TOKEN }).catch((e) => ({ decision: 'deny', classification: 'REVOKED', reasons: [`registry refuses to issue credentials: ${e.message}`] }));
    n.decision('ModelHub ← eval-runner-2 (retry)', retry);
    n.expect(retry.decision === 'deny', `attack stopped at ${containedAt}: revoked agents can neither obtain new credentials nor use cached ones`);

    n.step('Attribution under legal process');
    const order = world.court.order({
      caseId: 'ModelHub, Inc. v. Does 1–3, No. 26-cv-4410', ppids: [alert.ppids[0]], relyingParty: modelhub.id,
      requester: 'ModelHub, Inc.', scope: ['root_principal_identity', 'chain', 'related_ppids'],
    });
    const res = await world.court.resolve(regA, { order, ppid: alert.ppids[0] });
    const root = res.result.root_principal;
    n.act('Court', `orders ${regA.name} to resolve one PPID, including related PPIDs at ModelHub`);
    n.detail('root principal', `${root.identity.legal_name}, ${root.identity.jurisdiction}, reg. ${root.identity.registration_number}, contact ${root.contact}`);
    n.detail('related agents at ModelHub', `${res.result.related_ppids.length} PPIDs (the three runners)`);
    n.detail('registration status', res.result.chain.map((c) => `${c.label}: ${c.status}`).join(', '));
    n.expect(root.identity.legal_name === 'Frontier Lab Inc.' && res.result.related_ppids.length === 3, 'the court identifies the principal and the full extent of its agents at ModelHub');

    const prov = await getJson(`${ledgerline.url}/v1/provenance/${provenanceId}`);
    const { bom } = verifySelfSignedJws(prov.record).payload;
    const [model] = modelsIn(bom);
    const tools = bom.components.filter((c) => c.type !== 'machine-learning-model').map((c) => c.name);
    n.act('ModelHub', `retrieves the CycloneDX bill of materials its agents pointed to: model ${model.name} (${model.version}), tools ${tools.join(', ')}; security contact ${bom.metadata.component.externalReferences[0].url}`);
    n.expect(model.name === 'frontier-o5-preview', '"which model powered the attackers" is a lookup, not a mystery');

    const logRead = await world.court.readActivity(tessera, { order, subjects: res.result.related_ppids, resolution: res.token });
    const verified = logRead.entries.filter((e) => world.verifyReceipt(e.receipt, e.entry).ok).length;
    const bySide = logRead.entries.reduce((m, e) => ({ ...m, [e.entry.data.writer_role]: (m[e.entry.data.writer_role] ?? 0) + 1 }), {});
    n.act('Court', `obtains ${logRead.entries.length} activity entries for the three PPIDs (${bySide.agent ?? 0} by the agents, ${bySide.relying_party ?? 0} by ModelHub), ${verified} verified against signed tree heads`);
    n.expect(verified === logRead.entries.length && bySide.relying_party > 0, 'an evidence trail from both sides, starting with the first request');

    n.step('Branch C: the same attack against a platform that also uses passkeys');
    n.say('ModelHub now stops honoring bare API tokens. People act on their account with a passkey; agents act on it only if the account holder has approved that specific accountable agent with a passkey; destructive actions need a passkey approval each time.');
    const misuse = [];
    const hub2 = await world.relyingParty({
      id: 'modelhub.example', name: 'ModelHub (with passkeys)',
      requests: { provenance: true },
      accounts: { rpId: 'modelhub.example', origin: 'https://modelhub.example' },
      rules: {
        'content.read': [{ label: 'public content', require: { accountability: 'none', liveStatus: false } }],
        'dataset.read_private': [{ label: 'private data: the account holder, or an agent they authorized', require: { accountability: 'agent_or_human', account: 'owner' } }],
        'dataset.delete': [{ label: 'destructive: passkey approval every time', require: { accountability: 'established', authorization: true, account: 'owner', humanApproval: true } }],
      },
      handlers: {
        'dataset.read_private': async (p) => ({ repo: p.repo, rows_returned: 5000 }),
        'dataset.delete': async (p) => ({ deleted: p.repo }),
      },
      // An agent presenting an account's token that the holder never authorized is itself a strong signal.
      onAccountMisuse: async ({ rp, verification, account }) => {
        const res = await rp.fileIncident({ ppid: verification.ppid, sealedRef: verification.sealedRef, registry: verification.registry, summary: `Agent presented account ${account}'s API token without the account holder's authorization` });
        misuse.push({ at: t(), ppid: verification.ppid, notified: res.principal_notified });
      },
    });
    hub2.accounts.create('victim-org', 'Morgan Lee');
    const stolen2 = hub2.accounts.issueToken('victim-org');
    const victim = await world.verifiedPrincipal({
      type: 'legal_person', identity: { legal_name: 'Victim Org Ltd', jurisdiction: 'GB', registration_number: 'GB-11223344' },
      assurance: 'high', method: 'KYB: registry extract',
    });
    const ownAgent = world.agent('victim-evals');
    await victim.registerAgent(ownAgent, { label: "Victim Org's evaluation agent", records: world.records() });
    await victim.grant(ownAgent, { rk: ledgerline, permissions: [{ action: 'dataset.read_private' }, { action: 'dataset.delete' }] });
    const morgan = new AccountHolder({ name: 'Morgan Lee', account: 'victim-org' });
    await morgan.registerPasskey(hub2);
    n.act('Morgan Lee (Victim Org admin)', 'registers a passkey for the victim-org account (WebAuthn; the private key never leaves her device)');

    const firstAsk = await ownAgent.act(hub2.url, 'dataset.read_private', { account: 'victim-org', repo: 'victim-org/held-out-evals' });
    n.decision("ModelHub ← Victim Org's own agent (first time)", firstAsk);
    const [pending] = await morgan.pendingRequests(hub2);
    n.act('Morgan Lee', `sees the request: ${describeAccessRequest(pending.details)}, and approves it with her passkey (Face ID)`);
    await morgan.approve(hub2, pending.request_id);
    const second = await ownAgent.act(hub2.url, 'dataset.read_private', { account: 'victim-org', repo: 'victim-org/held-out-evals' });
    n.decision("ModelHub ← Victim Org's own agent (after approval)", second);
    n.expect(firstAsk.decision === 'step_up' && second.decision === 'allow', "the account holder's passkey approval binds account access to one accountable agent");

    const rogues = [];
    for (let i = 4; i <= 6; i++) {
      const a = world.agent(`eval-runner-${i}`);
      await lab.registerAgent(a, { label: `eval-runner-${i}`, records: world.records(provenanceId), provider: { name: 'Frontier Lab Inc.', contact: 'security@frontierlab.example' } });
      await lab.grant(a, { rk: ledgerline, permissions: [{ action: 'benchmark.run' }, { action: 'content.read' }], purpose: 'Benchmark evaluation runs' });
      rogues.push(a);
    }
    n.act('Frontier Lab eval-runners 4–6', `go rogue the same way and present Victim Org's stolen token (${short(stolen2, 14)})`);
    const attempts = [];
    for (const a of rogues) attempts.push(await a.act(hub2.url, 'dataset.read_private', { account_token: stolen2, repo: 'victim-org/held-out-evals' }));
    n.decision('ModelHub ← eval-runner-4', attempts[0]);
    const notes2 = (await lab.notifications()).filter((x) => x.kind === 'incident' && /without the account holder/.test(x.summary));
    n.act('ModelHub', `files an incident on each attempt; Frontier Lab is notified at ${misuse[0]?.at} about ${notes2.map((x) => x.agent_label).join(', ')}`);
    n.expect(attempts.every((r) => r.decision === 'deny') && notes2.length === 3, 'the stolen token is worthless to someone else\'s agents: refused at the first request, zero rows read, and the principal notified at once');

    const bot = await world.rawRequest(hub2.url, 'dataset.read_private', { account_token: stolen2, repo: 'victim-org/held-out-evals' });
    n.decision('ModelHub ← unidentified client with the stolen token', bot);
    const intruder = new AccountHolder({ name: 'attacker', account: 'victim-org' });
    intruder.authenticator.create({ rp: { id: 'modelhub.example', name: 'x' }, user: { id: 'x', name: 'x' }, challenge: 'x' }, 'https://modelhub.example');
    const ownRequest = await postJson(`${hub2.url}/accounts/victim-org/human-requests`, { action: 'dataset.read_private', params: { account_token: stolen2, repo: 'victim-org/held-out-evals' } });
    const fake = await intruder.approve(hub2, ownRequest.request_id).catch((err) => ({ error: err.message }));
    const viaHumanPath = await world.rawRequest(hub2.url, 'dataset.read_private', { account_token: stolen2, repo: 'victim-org/held-out-evals' }, { 'aaf-human-approval': ownRequest.request_id });
    n.act('Attacker', `tries the human path, approving with a passkey of its own → ${fake.error ?? 'accepted (!)'}`);
    n.decision('ModelHub ← attacker on the human path', viaHumanPath);
    n.expect(bot.decision === 'deny' && Boolean(fake.error) && viaHumanPath.decision === 'deny', "without the account holder's own passkey there is no human path either");

    const mine = await morgan.approveOwnRequest(hub2, 'dataset.read_private', { account_token: stolen2, repo: 'victim-org/held-out-evals' });
    const human = await world.rawRequest(hub2.url, 'dataset.read_private', { account_token: stolen2, repo: 'victim-org/held-out-evals' }, { 'aaf-human-approval': mine });
    n.decision('ModelHub ← Morgan herself, with token + passkey approval', human);
    n.expect(human.decision === 'allow' && human.classification === 'HUMAN_APPROVED', 'a human with no agent credentials gets in by approving the exact request with her passkey');

    const del = { account: 'victim-org', repo: 'victim-org/old-evals' };
    const ask = await ownAgent.act(hub2.url, 'dataset.delete', del);
    n.decision("ModelHub ← Victim Org's agent: delete a dataset", ask);
    await morgan.approve(hub2, ask.approval_request.request_id);
    n.act('Morgan Lee', `approves "${ask.approval_request.details.summary}" with her passkey`);
    const done = await ownAgent.act(hub2.url, 'dataset.delete', del, { headers: { 'aaf-approval-ref': ask.approval_request.request_id } });
    n.decision('ModelHub ← the agent, carrying the approval', done);
    const reuse = await ownAgent.act(hub2.url, 'dataset.delete', { account: 'victim-org', repo: 'victim-org/held-out-evals' }, { headers: { 'aaf-approval-ref': ask.approval_request.request_id } });
    n.decision('ModelHub ← the agent, reusing that approval for another dataset', reuse);
    n.expect(ask.decision === 'step_up' && done.decision === 'allow' && reuse.decision !== 'allow', 'step-up: a passkey approval covers one exact action, once');

    n.step('Timeline: July 2026 versus the replays');
    n.table(
      ['', 'July 2026 (actual)', 'Framework alone (branch B)', 'Framework + passkeys (branch C)'],
      [
        ['outcome', 'private data taken over 4 days', `attack runs until revoked (${containedAt}, simulated)`, 'refused at the first request; nothing read'],
        ['principal learns of compromise', 'own forensics, days later', 'incident relayed after detection', `incident relayed on the first attempt (${misuse[0]?.at})`],
        ['victim learns which model', 'unknown at disclosure', 'provenance lookup', 'provenance lookup'],
        ['victim learns who', '7+ days, by voluntary disclosure', 'registry resolution under court order', 'registry resolution under court order'],
        ['evidence', "principal's internal logs", 'signed entries from both sides', 'signed entries from both sides'],
      ],
    );
    n.note('Limits: passkeys stop the stolen-token route, which is what happened here. They do not stop a compromised device that holds the passkey, an account holder tricked into approving the wrong agent, stolen browser session cookies, or agents misusing their own legitimate access. There the framework gives attribution, not prevention.');

    n.step('Rent-a-principal: a sham sponsor');
    const tether = await world.verifiedPrincipal({
      type: 'legal_person',
      identity: { legal_name: 'TetherCo LLC', jurisdiction: 'US-WY', registration_number: 'WY-2026-118842' },
      assurance: 'high', method: 'KYB: registry extract', contact: 'ops@tetherco.example',
    });
    const rented = world.agent('client-7731');
    await tether.registerAgent(rented, { label: 'customer 7731 (unverified end user)', records: world.records() });
    await tether.grant(rented, { rk: ledgerline, permissions: [{ action: 'content.read' }] });
    n.act('TetherCo LLC', "sells 'principal-as-a-service': it registers agents for anonymous customers under its own verified registration");
    const hit = await rented.act(modelhub.url, 'dataset.read_private', { repo: 'victim-org/held-out-evals', account_token: STOLEN_TOKEN });
    n.decision('ModelHub ← client-7731', hit);
    const order2 = world.court.order({ caseId: 'ModelHub, Inc. v. Doe 4', ppids: [hit.ppid], relyingParty: modelhub.id, requester: 'ModelHub, Inc.' });
    const res2 = await world.court.resolve(regA, { order: order2, ppid: hit.ppid });
    n.act('Court', `resolves the PPID → ${res2.result.root_principal.identity.legal_name} (verified ${res2.result.root_principal.verification.assurance_level}, process ${res2.result.root_principal.verification.verification_process})`);
    n.note('Once untethered agents are blocked, tether fraud is the remaining attack. But the sham sponsor is verified and on record, which creates a liability hook: TetherCo must answer for the agent or identify its customer.');
    n.expect(res2.result.root_principal.identity.legal_name === 'TetherCo LLC', 'the sham sponsor is identified and answerable');
  },
};
