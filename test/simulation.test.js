// Runs every simulator scenario against a throwaway federation. Each scenario
// asserts its expected outcomes, so this is the integration test suite.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runSimulation } from '../src/sim/run.js';
import { Agent } from '../src/actors/agent.js';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startFederationInProcess } from '../src/lib/federation.js';
import { getJson } from '../src/lib/http.js';

test('all simulator scenarios meet their expectations', { timeout: 60000 }, async () => {
  const { ok, results } = await runSimulation({ fresh: true, quiet: true, reportFile: null });
  const failures = results.flatMap((r) => r.assertions.filter((a) => !a.ok).map((a) => `${r.title}: ${a.description}`));
  assert.ok(ok, `unmet expectations:\n${failures.join('\n')}`);
  assert.equal(results.length, 7);
});

// Regression: a grandchild delegation made in a later wall-clock second than its
// parent's must still not outlive the parent. Delay exactly those two calls.
test('lineage grandchild delegations survive a second boundary', { timeout: 60000 }, async () => {
  const delayed = new Set();
  const original = Agent.prototype.delegate;
  Agent.prototype.delegate = async function (child, opts) {
    if (child.name === 'Fetcher' || child.name === 'Courier/sub') {
      delayed.add(child.name);
      await new Promise((r) => setTimeout(r, 1100));
    }
    return original.call(this, child, opts);
  };
  try {
    const { ok, results } = await runSimulation({ selected: ['lineage'], fresh: true, quiet: true, reportFile: null });
    const failures = results.flatMap((r) => r.assertions.filter((a) => !a.ok).map((a) => `${r.title}: ${a.description}`));
    assert.ok(ok, `unmet expectations:\n${failures.join('\n')}`);
    assert.deepEqual([...delayed].sort(), ['Courier/sub', 'Fetcher']);
  } finally {
    Agent.prototype.delegate = original;
  }
});

// The simulator can be run again and again against services that keep running
// (`npm start`). Each directory keeps one principal record per verified
// identity, so on a second run the characters' earlier records are closed (the
// lost-key procedure) and they are verified afresh.
test('the simulator can be rerun against the same running federation', { timeout: 120000 }, async () => {
  const federation = await startFederationInProcess({ dataDir: fs.mkdtempSync(path.join(os.tmpdir(), 'aaf-test-')), portOffset: 5000 });
  try {
    for (const run of [1, 2]) {
      const { ok, results } = await runSimulation({ federation, quiet: true, reportFile: null });
      const failures = results.flatMap((r) => r.assertions.filter((a) => !a.ok).map((a) => `${r.title}: ${a.description}`));
      assert.ok(ok, `run ${run}: unmet expectations:\n${failures.join('\n')}`);
    }
    // Two runs, but each character still has only one open record: verified principals did not double.
    const stats = await getJson(`${federation.trustList.registry('https://registry-a.aaf.test').url}/v1/stats`);
    assert.ok(stats.principals > stats.verified_principals, 'the first run\'s records were closed, not duplicated');
  } finally {
    await federation.close();
  }
});
