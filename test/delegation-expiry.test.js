// Delegated grants never outlive the grant they come from. With no requested
// length the default is cut to the parent's expiry; a longer requested length
// is refused with the parent's expiry in the message.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import fs from 'node:fs';
import os from 'node:os';
import path from 'node:path';
import { startFederationInProcess } from '../src/lib/federation.js';
import { loadKeys } from '../src/lib/trust.js';
import { decodeJws } from '../src/lib/crypto.js';
import { Principal } from '../src/actors/principal.js';
import { Agent, delegatedGrantExpiry, DEFAULT_DELEGATION_DAYS } from '../src/actors/agent.js';
import { IdentityVerifier } from '../src/actors/authorities.js';

const DAY = 86400;

test('default delegated grant lengths are cut to the parent grant; longer requests are refused', () => {
  const now = 1_800_000_000;
  // Default, parent ends later: the full default.
  assert.equal(delegatedGrantExpiry({ now, parentExp: now + 30 * DAY }), now + DEFAULT_DELEGATION_DAYS * DAY);
  // Default, parent ends sooner (even by one second): the parent's expiry.
  assert.equal(delegatedGrantExpiry({ now, parentExp: now + DEFAULT_DELEGATION_DAYS * DAY - 1 }), now + DEFAULT_DELEGATION_DAYS * DAY - 1);
  // Default, parent without an expiry: the full default.
  assert.equal(delegatedGrantExpiry({ now, parentExp: undefined }), now + DEFAULT_DELEGATION_DAYS * DAY);
  // Requested, within the parent: as requested, including exactly the parent's expiry.
  assert.equal(delegatedGrantExpiry({ now, parentExp: now + 10 * DAY, validForDays: 3 }), now + 3 * DAY);
  assert.equal(delegatedGrantExpiry({ now, parentExp: now + 3 * DAY, validForDays: 3 }), now + 3 * DAY);
  // Requested, past the parent: refused, naming the parent's expiry.
  assert.throws(() => delegatedGrantExpiry({ now, parentExp: now + 2 * DAY, validForDays: 3 }), new RegExp(`outlive its parent grant, which expires ${new Date((now + 2 * DAY) * 1000).toISOString()}`));
  // Requested lengths must be positive numbers.
  for (const validForDays of [0, -1, Number.NaN, Number.POSITIVE_INFINITY, '3']) {
    assert.throws(() => delegatedGrantExpiry({ now, parentExp: now + 30 * DAY, validForDays }), /positive number of days/);
  }
});

test('a default-length grandchild delegation made a second later stays within its parent grant', { timeout: 30000 }, async () => {
  const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'aaf-test-'));
  const fed = await startFederationInProcess({ dataDir, portOffset: 6000 });
  try {
    const { trustList, paths } = fed;
    const reg = trustList.registry('https://registry-a.aaf.test');
    const rk = trustList.recordKeeper('https://records-1.aaf.test');
    const records = [{ role: 'authorization', rk: rk.id }];
    const p = new Principal({ type: 'legal_person', identity: { legal_name: 'Lineage Test Ltd', jurisdiction: 'US' }, registry: reg, trust: trustList });
    await p.enroll();
    await new IdentityVerifier({ id: 'https://kyc.verifier.test', keys: loadKeys('https://kyc.verifier.test', paths.keysDir) }).verify(p, { assurance: 'high', method: 'test' });

    const parent = new Agent({ name: 'Parent', trust: trustList });
    const child = new Agent({ name: 'Child', trust: trustList });
    const grandchild = new Agent({ name: 'Grandchild', trust: trustList });
    const other = new Agent({ name: 'Other', trust: trustList });
    await p.registerAgent(parent, { label: 'parent', records });
    await p.grant(parent, { rk, permissions: [{ action: 'data.query' }], delegation: { allowed: true, max_depth: 2 } });
    await parent.registerSubagent(child, { label: 'child', records });
    await parent.delegate(child, { permissions: [{ action: 'data.query' }], delegation: { allowed: true, max_depth: 1 } });
    const childExp = decodeJws(child.grants[0].grant).payload.exp;

    // A full second later, the default seven days from now would end after the child's grant.
    await new Promise((r) => setTimeout(r, 1100));
    await child.registerSubagent(grandchild, { label: 'grandchild', records });
    const res = await child.delegate(grandchild, { permissions: [{ action: 'data.query' }] });
    assert.ok(res.grant_id, 'the record keeper accepted the default-length grandchild grant');
    assert.equal(decodeJws(grandchild.grants[0].grant).payload.exp, childExp);

    // Asking explicitly for longer than the parent grant is refused before anything is sent.
    await child.registerSubagent(other, { label: 'other', records });
    await assert.rejects(child.delegate(other, { permissions: [{ action: 'data.query' }], validForDays: 8 }), /8-day grant would outlive its parent grant, which expires/);
    assert.equal(other.grants.length, 0);
  } finally {
    await fed.close();
  }
});
