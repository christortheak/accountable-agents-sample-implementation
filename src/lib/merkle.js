// Merkle tree hashing, inclusion proofs and consistency proofs as defined in
// RFC 9162 (Certificate Transparency 2.0) §2.1. Hashes are raw Buffers internally
// and base64url strings at the API boundary.
import crypto from 'node:crypto';
import { b64u } from './crypto.js';

const H = (...parts) => crypto.createHash('sha256').update(Buffer.concat(parts)).digest();
const EMPTY = H(Buffer.alloc(0));

export const leafHash = (data) => H(Buffer.from([0x00]), Buffer.from(data));
export const nodeHash = (left, right) => H(Buffer.from([0x01]), left, right);

const largestPowerOfTwoBelow = (n) => {
  let k = 1;
  while (k * 2 < n) k *= 2;
  return k;
};

// Complete (power-of-two) subtrees never change once filled, so their hashes are
// memoized per leaves array. Appending with push() keeps the cache valid; any
// rewrite of history must build a new array.
const subtreeCache = new WeakMap();

/** Merkle Tree Hash over an array of leaf hashes (Buffers). */
export function treeHash(leaves, start = 0, end = leaves.length) {
  const n = end - start;
  if (n === 0) return EMPTY;
  if (n === 1) return leaves[start];
  const complete = (n & (n - 1)) === 0;
  let memo;
  if (complete) {
    memo = subtreeCache.get(leaves);
    if (!memo) subtreeCache.set(leaves, (memo = new Map()));
    const hit = memo.get(`${start}:${n}`);
    if (hit) return hit;
  }
  const k = largestPowerOfTwoBelow(n);
  const hash = nodeHash(treeHash(leaves, start, start + k), treeHash(leaves, start + k, end));
  if (complete) memo.set(`${start}:${n}`, hash);
  return hash;
}

/** Audit path for leaf index m in the tree formed by leaves[0:n]. */
export function inclusionProof(leaves, m, n = leaves.length) {
  const path = (m, start, end) => {
    const size = end - start;
    if (size <= 1) return [];
    const k = largestPowerOfTwoBelow(size);
    if (m < k) return [...path(m, start, start + k), treeHash(leaves, start + k, end)];
    return [...path(m - k, start + k, end), treeHash(leaves, start, start + k)];
  };
  if (m >= n) throw new Error('leaf index out of range');
  return path(m, 0, n).map((h) => b64u.encode(h));
}

/** RFC 9162 §2.1.3.2 */
export function verifyInclusion({ leafIndex, treeSize, leafHash: leaf, proof, rootHash }) {
  if (leafIndex >= treeSize) return false;
  let fn = leafIndex;
  let sn = treeSize - 1;
  let r = typeof leaf === 'string' ? b64u.decode(leaf) : leaf;
  for (const p64 of proof) {
    const p = b64u.decode(p64);
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      r = nodeHash(p, r);
      if ((fn & 1) === 0) {
        while ((fn & 1) === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      r = nodeHash(r, p);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && b64u.encode(r) === rootHash;
}

/** Consistency proof between tree sizes m <= n (RFC 9162 §2.1.4.1). */
export function consistencyProof(leaves, m, n = leaves.length) {
  if (m < 1 || m > n) throw new Error('invalid tree sizes');
  const subproof = (m, start, end, complete) => {
    const size = end - start;
    if (m === size) return complete ? [] : [treeHash(leaves, start, end)];
    const k = largestPowerOfTwoBelow(size);
    if (m <= k) return [...subproof(m, start, start + k, complete), treeHash(leaves, start + k, end)];
    return [...subproof(m - k, start + k, end, false), treeHash(leaves, start, start + k)];
  };
  return subproof(m, 0, n, true).map((h) => b64u.encode(h));
}

/** RFC 9162 §2.1.4.2 */
export function verifyConsistency({ firstSize, secondSize, firstRoot, secondRoot, proof }) {
  if (firstSize > secondSize) return false;
  if (firstSize === secondSize) return proof.length === 0 && firstRoot === secondRoot;
  if (firstSize === 0) return true;
  let path = proof.map((p) => b64u.decode(p));
  if ((firstSize & (firstSize - 1)) === 0) path = [b64u.decode(firstRoot), ...path];
  if (path.length === 0) return false;
  let fn = firstSize - 1;
  let sn = secondSize - 1;
  while ((fn & 1) === 1) {
    fn >>= 1;
    sn >>= 1;
  }
  let fr = path[0];
  let sr = path[0];
  for (const c of path.slice(1)) {
    if (sn === 0) return false;
    if ((fn & 1) === 1 || fn === sn) {
      fr = nodeHash(c, fr);
      sr = nodeHash(c, sr);
      if ((fn & 1) === 0) {
        while ((fn & 1) === 0 && fn !== 0) {
          fn >>= 1;
          sn >>= 1;
        }
      }
    } else {
      sr = nodeHash(sr, c);
    }
    fn >>= 1;
    sn >>= 1;
  }
  return sn === 0 && b64u.encode(fr) === firstRoot && b64u.encode(sr) === secondRoot;
}
