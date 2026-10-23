// Token Status List input validation: indices, sizes, status codes and bit
// widths. Library only; no servers or ports.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import zlib from 'node:zlib';
import { b64u } from '../src/lib/crypto.js';
import { encodeStatusList, statusAt, STATUS, LIST_SIZE } from '../src/lib/status-list.js';

const BAD_INDICES = [-1, -0.5, 0.5, 1.5, '1', '0', null, undefined, NaN, Infinity, -Infinity, 2 ** 31, 2 ** 32, 2 ** 53, Number.MAX_VALUE, 1n, [1], {}];

test('statusAt refuses invalid indices instead of reading some other entry', () => {
  const list = encodeStatusList(new Map([[0, STATUS.INVALID], [3, STATUS.SUSPENDED]]));
  for (const idx of BAD_INDICES) assert.throws(() => statusAt(list, idx), /status index out of range/, `idx ${String(idx)}`);
  assert.throws(() => statusAt(list, LIST_SIZE), /out of range/);
  assert.equal(statusAt(list, LIST_SIZE - 1), STATUS.VALID);
});

test('encodeStatusList refuses invalid indices, sizes and status codes', () => {
  for (const idx of [...BAD_INDICES, LIST_SIZE]) assert.throws(() => encodeStatusList(new Map([[idx, STATUS.INVALID]])), /out of range/, `idx ${String(idx)}`);
  for (const status of [-1, 4, 1.5, '1', true, NaN]) assert.throws(() => encodeStatusList(new Map([[0, status]])), /status code/, `status ${String(status)}`);
  for (const size of [0, -4, 3, 4.5, NaN, Infinity, '16']) assert.throws(() => encodeStatusList(new Map(), size), /size/, `size ${String(size)}`);
  // Status 0 and small valid sizes are fine.
  assert.equal(statusAt(encodeStatusList(new Map([[0, STATUS.VALID], [3, STATUS.INVALID]]), 4), 3), STATUS.INVALID);
});

test('statusAt reads only the bit widths the Token Status List defines', () => {
  const list = encodeStatusList(new Map([[1, STATUS.INVALID]]), 8);
  for (const bits of [0, 3, 16, '2', undefined, 2.5]) assert.throws(() => statusAt({ ...list, bits }, 1), /unsupported status list bits/);
  // Other defined widths over the same bytes: 0b00000100 in byte 0.
  const raw = { lst: b64u.encode(zlib.deflateSync(Buffer.from([0b00000100, 0xff]))) };
  assert.equal(statusAt({ ...raw, bits: 1 }, 2), 1);
  assert.equal(statusAt({ ...raw, bits: 1 }, 3), 0);
  assert.equal(statusAt({ ...raw, bits: 4 }, 0), 4);
  assert.equal(statusAt({ ...raw, bits: 8 }, 1), 0xff);
  assert.throws(() => statusAt({ ...raw, bits: 8 }, 2), /out of range/);
});

test('generated values round-trip at their own indices', () => {
  // Deterministic generated data: a spread of indices across the whole list, including both ends.
  const values = new Map();
  for (let i = 0; i < 500; i++) values.set((i * 2654435761) % LIST_SIZE, i % 4);
  values.set(0, STATUS.TRANSFERRED);
  values.set(LIST_SIZE - 1, STATUS.SUSPENDED);
  const list = encodeStatusList(values);
  for (const [idx, v] of values) assert.equal(statusAt(list, idx), v, `idx ${idx}`);
  // Unset entries stay VALID.
  for (let idx = 1; idx < 64; idx++) if (!values.has(idx)) assert.equal(statusAt(list, idx), STATUS.VALID);
});
