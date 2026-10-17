// Transaction simulator.
//
//   npm run sim                      run every scenario
//   npm run sim -- payment hf        run selected scenarios (by id or number)
//   npm run sim -- --list            list scenarios
//   npm run sim -- --fresh           run against a throwaway federation (temporary data)
//
// If the federation started by `npm start` is running, scenarios run against
// it (watch the dashboards). Otherwise the services are started in-process.
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { setupFederation, startFederationInProcess, federationIsRunning, accreditAll } from '../lib/federation.js';
import { PROJECT_ROOT, discoverFederation } from '../lib/trust.js';
import { createNarrator } from './narrator.js';
import { createWorld } from './world.js';
import { scenarios } from './scenarios/index.js';

export async function runSimulation({ selected = [], fresh = false, quiet = false, reportFile = path.join(PROJECT_ROOT, 'reports', 'simulation-report.md') } = {}) {
  let federation;
  let mode;
  if (fresh) {
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aaf-sim-'));
    federation = await startFederationInProcess({ dataDir, portOffset: 2000 });
    mode = `throwaway federation (${dataDir})`;
  } else {
    const prepared = setupFederation();
    if (await federationIsRunning(prepared)) {
      const trustList = await discoverFederation(prepared.trustAnchor);
      await accreditAll({ ...prepared, trustList });
      federation = { ...prepared, trustList: await discoverFederation(prepared.trustAnchor), close: async () => {} };
      mode = 'running federation (npm start)';
    } else {
      federation = await startFederationInProcess({});
      mode = 'in-process federation (start it with `npm start` to watch the dashboards)';
    }
  }

  const narrator = createNarrator({ quiet });
  const world = createWorld({ trust: federation.trustList, keysDir: federation.paths.keysDir });
  if (!quiet) console.log(`Accountable Agents Framework simulator, using ${mode}`);

  const chosen = selected.length
    ? scenarios.filter((s, i) => selected.includes(s.id) || selected.includes(String(i + 1)))
    : scenarios;
  try {
    for (const scenario of chosen) {
      narrator.scenario(scenario.id, scenario.title, scenario.framing);
      try {
        await scenario.run(world, narrator);
      } catch (err) {
        narrator.error(err);
      }
    }
  } finally {
    await world.close();
    await federation.close();
  }
  const ok = narrator.summary();
  if (reportFile) {
    fs.mkdirSync(path.dirname(reportFile), { recursive: true });
    fs.writeFileSync(reportFile, narrator.markdown('Accountable Agents Framework: simulation report'));
    if (!quiet) console.log(`Report written to ${path.relative(process.cwd(), reportFile)}`);
  }
  return { ok, results: narrator.results };
}

if (import.meta.url === `file://${process.argv[1]}` || process.argv[1]?.endsWith('src/sim/run.js')) {
  const args = process.argv.slice(2);
  if (args.includes('--list')) {
    scenarios.forEach((s, i) => console.log(`${i + 1}. ${s.id.padEnd(12)} ${s.title}`));
    process.exit(0);
  }
  const { ok } = await runSimulation({ selected: args.filter((a) => !a.startsWith('--')), fresh: args.includes('--fresh') });
  process.exit(ok ? 0 : 1);
}
