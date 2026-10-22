// IETF OAuth Token Status List: a compressed bit array of credential statuses,
// published as a signed Status List Token. A credential names its entry with
// `status: { status_list: { idx, uri } }`. A relying party fetches the whole
// list, so the issuer does not learn which credential is being checked.
import zlib from 'node:zlib';
import crypto from 'node:crypto';
import { b64u, signJws, verifyJws, nowSeconds } from './crypto.js';

export const STATUS_LIST_TYP = 'statuslist+jwt';
export const BITS = 2;
export const LIST_SIZE = 1 << 16; // entries per list; large lists give herd privacy

// 0x00-0x02 are defined by the Token Status List; 0x03 is application-specific.
export const STATUS = { VALID: 0, INVALID: 1, SUSPENDED: 2, TRANSFERRED: 3 };
export const STATUS_NAME = ['VALID', 'INVALID', 'SUSPENDED', 'TRANSFERRED'];

/** Random free index, so an index reveals nothing about issuance order. */
export function allocateIndex(used) {
  if (used.size >= LIST_SIZE) throw new Error('status list full');
  for (;;) {
    const idx = crypto.randomInt(0, LIST_SIZE);
    if (!used.has(idx)) return idx;
  }
}

// Bits per entry the Token Status List defines; any of them can be read.
export const SUPPORTED_BITS = [1, 2, 4, 8];

/** An index must be a safe non-negative integer below the list's entry count; nothing is coerced. */
function checkIndex(idx, entries) {
  if (!Number.isSafeInteger(idx) || idx < 0 || idx >= entries) throw new Error('status index out of range');
}

/** values: Map idx -> status code. Returns the status_list claim { bits, lst }. */
export function encodeStatusList(values, size = LIST_SIZE) {
  if (!Number.isSafeInteger(size) || size <= 0 || (size * BITS) % 8 !== 0) throw new Error(`status list size must be a positive multiple of ${8 / BITS}`);
  const bytes = Buffer.alloc((size * BITS) / 8);
  for (const [idx, status] of values) {
    checkIndex(idx, size);
    if (!Number.isInteger(status) || status < 0 || status >= 1 << BITS) throw new Error(`status code must be an integer from 0 to ${(1 << BITS) - 1}`);
    if (!status) continue;
    // Plain arithmetic: 32-bit shifts would wrap for large indices.
    const bit = idx * BITS;
    bytes[Math.floor(bit / 8)] |= status << (bit % 8);
  }
  return { bits: BITS, lst: b64u.encode(zlib.deflateSync(bytes)) };
}

export function statusAt(statusList, idx) {
  const { bits } = statusList;
  if (!SUPPORTED_BITS.includes(bits)) throw new Error(`unsupported status list bits ${bits}`);
  const bytes = zlib.inflateSync(b64u.decode(statusList.lst));
  checkIndex(idx, (bytes.length * 8) / bits);
  const bit = idx * bits;
  return (bytes[Math.floor(bit / 8)] >> (bit % 8)) & ((1 << bits) - 1);
}

export function statusListToken({ issuer, key, uri, values, ttl }) {
  const now = nowSeconds();
  return signJws({ iss: issuer, sub: uri, iat: now, exp: now + Math.max(ttl * 6, 60), ttl, status_list: encodeStatusList(values) }, key, { typ: STATUS_LIST_TYP });
}

export function verifyStatusListToken(jwt, issuerKey, { uri }) {
  const { payload } = verifyJws(jwt, issuerKey, { typ: STATUS_LIST_TYP });
  if (payload.sub !== uri) throw new Error('status list token is for a different list');
  if (payload.exp && payload.exp < nowSeconds()) throw new Error('status list token expired');
  return payload;
}
