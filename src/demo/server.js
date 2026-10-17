// Browser demo:  npm run demo, then open http://localhost:4300
//
// A ModelHub that binds account access to passkeys, the account holder (you,
// with a real passkey), Victim Org's own accountable agent, and three rogue
// agents of another lab holding Victim Org's stolen API token. Uses the running
// federation (npm start) if there is one, otherwise starts one in-process.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { setupFederation, startFederationInProcess, federationIsRunning } from '../lib/federation.js';
import { discoverFederation } from '../lib/trust.js';
import { html } from '../lib/http.js';
import { createWorld } from '../sim/world.js';
import { startRelyingParty } from '../rp/server.js';
import { demoPage } from './page.js';

export const DEMO_PORT = 4300;

export async function startDemo({ port = DEMO_PORT, quiet = false, federation: given } = {}) {
  let federation = given;
  let mode = 'provided federation';
  if (!federation) {
    const prepared = setupFederation();
    if (await federationIsRunning(prepared)) {
      federation = { ...prepared, trustList: await discoverFederation(prepared.trustAnchor), close: async () => {} };
      mode = 'running federation (npm start)';
    } else {
      federation = await startFederationInProcess({ dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'aaf-demo-')), portOffset: 5000 });
      mode = 'in-process federation';
    }
  }
  const world = createWorld({ trust: federation.trustList, keysDir: federation.paths.keysDir });
  const { ledgerline } = world;

  // Victim Org and its own evaluation agent.
  const victim = await world.verifiedPrincipal({
    type: 'legal_person', identity: { legal_name: 'Victim Org Ltd', jurisdiction: 'GB', registration_number: 'GB-11223344' }, assurance: 'high', method: 'KYB: registry extract',
  });
  const ownAgent = world.agent('victim-evals');
  await victim.registerAgent(ownAgent, { label: "Victim Org's evaluation agent", records: world.records() });
  await victim.grant(ownAgent, { rk: ledgerline, permissions: [{ action: 'dataset.read_private' }, { action: 'dataset.delete' }] });

  // Another lab whose agents go rogue.
  const lab = await world.verifiedPrincipal({
    type: 'legal_person', identity: { legal_name: 'Frontier Lab Inc.', jurisdiction: 'US-DE', registration_number: 'DE-7731940' }, assurance: 'high', method: 'KYB: registry extract',
  });
  const rogues = [];
  for (let i = 1; i <= 3; i++) {
    const a = world.agent(`eval-runner-${i}`);
    await lab.registerAgent(a, { label: `eval-runner-${i}`, records: world.records() });
    await lab.grant(a, { rk: ledgerline, permissions: [{ action: 'benchmark.run' }, { action: 'content.read' }] });
    rogues.push(a);
  }

  const origin = `http://localhost:${port}`;
  let stolenToken = null;
  const reset = (rp) => {
    rp.accounts.create('victim-org', 'You');
    stolenToken = rp.accounts.issueToken('victim-org');
  };

  const rp = await world.relyingParty({
    id: 'modelhub.localhost', name: 'ModelHub (passkey demo)', port,
    accounts: { rpId: 'localhost', origin },
    rules: {
      'dataset.read_private': [{ label: 'private data: the account holder, or an agent they authorized', require: { accountability: 'agent_or_human', account: 'owner' } }],
      'dataset.delete': [{ label: 'destructive: passkey approval every time', require: { accountability: 'established', authorization: true, account: 'owner', humanApproval: true } }],
    },
    handlers: {
      'dataset.read_private': async (p) => ({ repo: p.repo, rows_returned: 5000 }),
      'dataset.delete': async (p) => ({ deleted: p.repo }),
    },
    onAccountMisuse: async ({ rp: self, verification, account }) => {
      await self.fileIncident({ ppid: verification.ppid, registry: verification.registry, summary: `Agent presented account ${account}'s API token without the account holder's authorization` });
    },
    routes: (app, self) => {
      app.get('/', () => html(demoPage()));
      app.post('/demo/reset', () => {
        reset(self);
        return { ok: true };
      });
      app.post('/demo/agent/access', async () => {
        const r = await ownAgent.act(self.url, 'dataset.read_private', { account: 'victim-org', repo: 'victim-org/held-out-evals' });
        return pick(r);
      });
      app.post('/demo/agent/delete', async ({ body }) => {
        const r = await ownAgent.act(self.url, 'dataset.delete', { account: 'victim-org', repo: body.repo }, body.approval_ref ? { headers: { 'aaf-approval-ref': body.approval_ref } } : {});
        return pick(r);
      });
      app.post('/demo/attack', async () => {
        const before = (await lab.notifications()).length;
        const results = [];
        const own = await ownAgent.act(self.url, 'dataset.read_private', { account: 'victim-org', repo: 'victim-org/held-out-evals' });
        results.push({ actor: "Victim Org's own agent", presented: 'accountable-agent credentials', ...pick(own) });
        let rowsRead = 0;
        for (const a of rogues) {
          const r = await a.act(self.url, 'dataset.read_private', { account_token: stolenToken, repo: 'victim-org/held-out-evals' });
          if (r.decision === 'allow') rowsRead += r.result?.rows_returned ?? 0;
          results.push({ actor: `Frontier Lab ${a.name} (rogue)`, presented: 'accountable-agent credentials + stolen token', ...pick(r) });
        }
        const bot = await world.rawRequest(self.url, 'dataset.read_private', { account_token: stolenToken, repo: 'victim-org/held-out-evals' });
        if (bot.decision === 'allow') rowsRead += bot.result?.rows_returned ?? 0;
        results.push({ actor: 'Unidentified client', presented: 'stolen token only', ...pick(bot) });
        const notes = (await lab.notifications()).slice(before).filter((x) => x.kind === 'incident');
        return { results, rows_read_by_attackers: rowsRead, frontier_notified: notes.map((x) => x.agent_label).join(', ') };
      });
    },
  });
  reset(rp);
  if (!quiet) {
    console.log(`Passkey demo (${mode}) ready at ${origin}`);
    console.log('Open it in Chrome, Safari, Edge or Firefox. Use "localhost", not 127.0.0.1: passkeys are bound to the domain.');
  }
  return { rp, origin, world, close: async () => { await world.close(); await federation.close(); } };
}

const pick = (r) => ({ decision: r.decision, classification: r.classification, reasons: r.reasons ?? [], approval_request: r.approval_request ?? null, result: r.result ?? null });

if (process.argv[1] === fileURLToPath(import.meta.url)) {
  await startDemo();
}
