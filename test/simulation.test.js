// Runs every simulator scenario against a throwaway federation. Each scenario
// asserts its expected outcomes, so this is the integration test suite.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runSimulation } from '../src/sim/run.js';
import { Agent } from '../src/actors/agent.js';

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
