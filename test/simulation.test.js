// Runs every simulator scenario against a throwaway federation. Each scenario
// asserts its expected outcomes, so this is the integration test suite.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { runSimulation } from '../src/sim/run.js';

test('all simulator scenarios meet their expectations', { timeout: 60000 }, async () => {
  const { ok, results } = await runSimulation({ fresh: true, quiet: true, reportFile: null });
  const failures = results.flatMap((r) => r.assertions.filter((a) => !a.ok).map((a) => `${r.title}: ${a.description}`));
  assert.ok(ok, `unmet expectations:\n${failures.join('\n')}`);
  assert.equal(results.length, 7);
});
