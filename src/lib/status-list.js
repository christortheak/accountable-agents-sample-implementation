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

/** values: Map idx -> status code. Returns the status_list claim { bits, lst }. */
export function encodeStatusList(values, size = LIST_SIZE) {
  const bytes = Buffer.alloc((size * BITS) / 8);
  for (const [idx, status] of values) {
    if (!status) continue;
    const bit = idx * BITS;
    bytes[bit >> 3] |= (status & 0b11) << (bit & 7);
  }
  return { bits: BITS, lst: b64u.encode(zlib.deflateSync(bytes)) };
}

export function statusAt(statusList, idx) {
  const bytes = zlib.inflateSync(b64u.decode(statusList.lst));
  const bit = idx * statusList.bits;
  if ((bit >> 3) >= bytes.length) throw new Error('status index out of range');
  return (bytes[bit >> 3] >> (bit & 7)) & ((1 << statusList.bits) - 1);
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
