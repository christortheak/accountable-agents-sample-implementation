// Minimal CBOR (RFC 8949): the subset WebAuthn needs for attestation objects
// and COSE keys: unsigned/negative integers, byte and text strings, arrays,
// maps, booleans and null. Definite lengths only.

export function encodeCbor(value) {
  const out = [];
  const head = (major, n) => {
    if (n < 24) out.push((major << 5) | n);
    else if (n < 0x100) out.push((major << 5) | 24, n);
    else if (n < 0x10000) out.push((major << 5) | 25, n >> 8, n & 0xff);
    else out.push((major << 5) | 26, (n >>> 24) & 0xff, (n >> 16) & 0xff, (n >> 8) & 0xff, n & 0xff);
  };
  const enc = (v) => {
    if (v === null) out.push(0xf6);
    else if (v === true) out.push(0xf5);
    else if (v === false) out.push(0xf4);
    else if (typeof v === 'number') {
      if (!Number.isInteger(v)) throw new Error('CBOR: floats not supported');
      if (v >= 0) head(0, v);
      else head(1, -1 - v);
    } else if (typeof v === 'string') {
      const b = Buffer.from(v, 'utf8');
      head(3, b.length);
      out.push(...b);
    } else if (Buffer.isBuffer(v) || v instanceof Uint8Array) {
      head(2, v.length);
      out.push(...v);
    } else if (Array.isArray(v)) {
      head(4, v.length);
      v.forEach(enc);
    } else if (v instanceof Map) {
      head(5, v.size);
      for (const [k, val] of v) {
        enc(k);
        enc(val);
      }
    } else if (typeof v === 'object') {
      const entries = Object.entries(v);
      head(5, entries.length);
      for (const [k, val] of entries) {
        enc(k);
        enc(val);
      }
    } else throw new Error(`CBOR: cannot encode ${typeof v}`);
  };
  enc(value);
  return Buffer.from(out);
}

/** Decode one CBOR item. Returns { value, length }. Maps decode to Map (keys may be integers). */
export function decodeCbor(buf, offset = 0) {
  let pos = offset;
  const readLen = (info) => {
    if (info < 24) return info;
    if (info === 24) return buf[pos++];
    if (info === 25) {
      const n = buf.readUInt16BE(pos);
      pos += 2;
      return n;
    }
    if (info === 26) {
      const n = buf.readUInt32BE(pos);
      pos += 4;
      return n;
    }
    throw new Error('CBOR: unsupported length');
  };
  const dec = () => {
    const ib = buf[pos++];
    const major = ib >> 5;
    const info = ib & 0x1f;
    switch (major) {
      case 0:
        return readLen(info);
      case 1:
        return -1 - readLen(info);
      case 2: {
        const n = readLen(info);
        const b = buf.subarray(pos, pos + n);
        pos += n;
        return Buffer.from(b);
      }
      case 3: {
        const n = readLen(info);
        const s = buf.subarray(pos, pos + n).toString('utf8');
        pos += n;
        return s;
      }
      case 4: {
        const n = readLen(info);
        return Array.from({ length: n }, dec);
      }
      case 5: {
        const n = readLen(info);
        const m = new Map();
        for (let i = 0; i < n; i++) {
          const k = dec();
          m.set(k, dec());
        }
        return m;
      }
      case 7:
        if (info === 20) return false;
        if (info === 21) return true;
        if (info === 22) return null;
        throw new Error('CBOR: unsupported simple value');
      default:
        throw new Error(`CBOR: unsupported major type ${major}`);
    }
  };
  const value = dec();
  return { value, length: pos - offset };
}
