// Append-only, tamper-evident log. Each entry is canonical JSON hashed into an
// RFC 9162 Merkle tree; the operator signs tree heads (STHs). A receipt
// (inclusion proof + STH) lets the submitter later prove what the log held.
//
// The log is also the service's database: services rebuild their state by
// replaying entries at startup, so state cannot diverge from the evidence.
import fs from 'node:fs';
import path from 'node:path';
import { canonicalize, signJws, verifyJws, b64u } from './crypto.js';
import { leafHash, treeHash, inclusionProof, consistencyProof, verifyInclusion } from './merkle.js';

export const STH_TYP = 'aaf-sth+jwt';

export class MerkleLog {
  /**
   * @param {object} opts
   * @param {string} opts.logId   identifier of the operator (service id)
   * @param {object} opts.signer  key holder used to sign tree heads
   * @param {string|null} opts.file  JSONL file for persistence (null = memory only)
   */
  constructor({ logId, signer, file = null }) {
    this.logId = logId;
    this.signer = signer;
    this.file = file;
    this.entries = [];
    this.leaves = [];
    if (file && fs.existsSync(file)) {
      for (const line of fs.readFileSync(file, 'utf8').split('\n')) {
        if (!line.trim()) continue;
        const { entry } = JSON.parse(line);
        this.entries.push(entry);
        this.leaves.push(leafHash(canonicalize(entry)));
      }
    } else if (file) {
      fs.mkdirSync(path.dirname(file), { recursive: true });
    }
  }

  get size() {
    return this.entries.length;
  }

  append(entry) {
    const index = this.entries.length;
    const leaf = leafHash(canonicalize(entry));
    this.entries.push(entry);
    this.leaves.push(leaf);
    if (this.file) fs.appendFileSync(this.file, JSON.stringify({ index, entry }) + '\n');
    return { index, leafHash: b64u.encode(leaf) };
  }

  get(index) {
    return this.entries[index];
  }

  leafHashAt(index) {
    return b64u.encode(this.leaves[index]);
  }

  rootHash(size = this.size) {
    return b64u.encode(treeHash(this.leaves, 0, size));
  }

  /** Signed tree head for the current size. */
  signedTreeHead() {
    const payload = {
      log_id: this.logId,
      tree_size: this.size,
      root_hash: this.rootHash(),
      timestamp: Date.now(),
    };
    return signJws(payload, this.signer, { typ: STH_TYP });
  }

  receipt(index) {
    const sth = this.signedTreeHead();
    return {
      log_id: this.logId,
      index,
      leaf_hash: this.leafHashAt(index),
      tree_size: this.size,
      inclusion_proof: inclusionProof(this.leaves, index, this.size),
      sth,
    };
  }

  inclusionProof(index, treeSize = this.size) {
    return inclusionProof(this.leaves, index, treeSize);
  }

  consistencyProof(firstSize, secondSize = this.size) {
    return consistencyProof(this.leaves, firstSize, secondSize);
  }

  /**
   * Development-only: rewrite history the way a dishonest operator would,
   * recomputing the tree so the log stays internally consistent.
   */
  rewriteEntry(index, newEntry) {
    this.entries[index] = newEntry;
    this.leaves = this.entries.map((e) => leafHash(canonicalize(e)));
    if (this.file) {
      fs.writeFileSync(this.file, this.entries.map((entry, i) => JSON.stringify({ index: i, entry })).join('\n') + '\n');
    }
  }
}

/** Hash an entry exactly as the log does, for independent verification. */
export const entryLeafHash = (entry) => b64u.encode(leafHash(canonicalize(entry)));

/** Verify a receipt against the log operator's public key. */
export function verifyReceipt(receipt, operatorPublicJwk, { entry } = {}) {
  const { payload: sth } = verifyJws(receipt.sth, operatorPublicJwk, { typ: STH_TYP });
  if (sth.log_id !== receipt.log_id) return { ok: false, reason: 'log id mismatch' };
  if (entry && entryLeafHash(entry) !== receipt.leaf_hash) return { ok: false, reason: 'entry does not match receipt' };
  const included = verifyInclusion({
    leafIndex: receipt.index,
    treeSize: sth.tree_size,
    leafHash: receipt.leaf_hash,
    proof: receipt.inclusion_proof,
    rootHash: sth.root_hash,
  });
  return included ? { ok: true, sth } : { ok: false, reason: 'inclusion proof does not match signed tree head' };
}
