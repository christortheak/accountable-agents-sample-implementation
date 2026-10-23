// Trust: the federation as each party sees it.
//
// Every party is configured with one thing out of band: the Trust Anchor's
// entity identifier, URL and keys (data/trust-anchor.json), much as a
// browser ships root certificates. Everything else is discovered with OpenID
// Federation: the Trust Anchor lists its subordinates and signs a Subordinate
// Statement about each; online members' own Entity Configurations are fetched
// and checked against those statements. The result is a Federation snapshot
// with synchronous lookups.
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { decodeJws, keyFromJwk, thumbprint } from './crypto.js';
import { getJson } from './http.js';
import { WELL_KNOWN, verifyEntityStatement } from './openid-federation.js';

export const PROJECT_ROOT = path.resolve(path.dirname(fileURLToPath(import.meta.url)), '../..');
// Runtime state (generated keys, admin tokens, service logs). Git-ignored; set AAF_DATA_DIR to move it.
export const DATA_DIR = process.env.AAF_DATA_DIR ?? path.join(PROJECT_ROOT, 'data');
export const KEYS_DIR = path.join(DATA_DIR, 'keys');
// Which federation to run: config/federation.json (local simulation) unless AAF_CONFIG names another file.
export const FEDERATION_CONFIG = process.env.AAF_CONFIG ? path.resolve(process.env.AAF_CONFIG) : path.join(PROJECT_ROOT, 'config', 'federation.json');
const STARTUP_TIMEOUT_MS = Number(process.env.AAF_STARTUP_TIMEOUT_SECONDS ?? 15) * 1000;

export const loadFederationConfig = (file = FEDERATION_CONFIG) => JSON.parse(fs.readFileSync(file, 'utf8'));

/** File-system-safe name for an entity identifier. */
export const fileNameFor = (entityId) => entityId.replace(/^https?:\/\//, '').replace(/[^a-zA-Z0-9.-]/g, '_');

/** Load the private keys generated for a service or authority by setup. */
export function loadKeys(id, dir = KEYS_DIR) {
  const raw = JSON.parse(fs.readFileSync(path.join(dir, `${fileNameFor(id)}.json`), 'utf8'));
  return {
    signing: keyFromJwk(raw.signing),
    encryption: raw.encryption ? keyFromJwk(raw.encryption) : null,
    pairwiseSecret: raw.pairwiseSecret ?? null,
    adminToken: raw.adminToken ?? null,
  };
}

export function loadTrustAnchor(dataDir = DATA_DIR) {
  const file = path.join(dataDir, 'trust-anchor.json');
  if (!fs.existsSync(file)) throw new Error(`trust anchor configuration not found at ${file}; run "npm run setup" first`);
  return JSON.parse(fs.readFileSync(file, 'utf8'));
}

async function getText(url) {
  const res = await fetch(url, { signal: AbortSignal.timeout(5000) });
  if (!res.ok) throw new Error(`${url} answered ${res.status}`);
  return res.text();
}

/** Resolve the federation from its Trust Anchor (OpenID Federation discovery). */
//
// The Trust Anchor's keys are the ones configured in trustAnchor.jwks and stay
// fixed: keys its Entity Configuration newly advertises are not trusted for
// anything. Moving to a new key takes an explicit re-pin (aaf init --pin).
export async function discoverFederation(trustAnchor) {
  const taConfig = verifyEntityStatement(await getText(`${trustAnchor.url}${WELL_KNOWN}`), trustAnchor.jwks, { iss: trustAnchor.entity_id, sub: trustAnchor.entity_id });
  const members = await getJson(`${trustAnchor.url}/list`);
  const doc = {
    federation: taConfig.metadata.federation_entity.organization_name,
    trust_anchor: { entity_id: trustAnchor.entity_id, url: trustAnchor.url, jwks: trustAnchor.jwks },
    policies: taConfig.metadata.aaf_trust_anchor.policies,
    trust_mark_issuers: taConfig.trust_mark_issuers ?? {},
    registries: [],
    record_keepers: [],
    verifiers: [],
    resolution_authorities: [],
  };
  await Promise.all(
    members.map(async (sub) => {
      const st = verifyEntityStatement(await getText(`${trustAnchor.url}/fetch?sub=${encodeURIComponent(sub)}`), trustAnchor.jwks, { iss: trustAnchor.entity_id, sub });
      const [type, md] = Object.entries(st.metadata).find(([k]) => k.startsWith('aaf_'));
      const entry = { id: sub, name: md.organization_name, jwks: md.jwks ?? st.jwks, chain: 'subordinate-statement' };
      if (md.endpoint_base) {
        entry.url = md.endpoint_base;
        try {
          // Leaf Entity Configuration, checked against the keys the Trust Anchor vouched for.
          const ec = verifyEntityStatement(await getText(`${md.endpoint_base}${WELL_KNOWN}`), st.jwks, { iss: sub, sub });
          if (!(ec.authority_hints ?? []).includes(trustAnchor.entity_id)) throw new Error('no authority hint to the trust anchor');
          entry.chain = 'verified';
          entry.trust_marks = ec.trust_marks ?? [];
        } catch {
          // Not reachable yet: the Trust Anchor's statement alone vouches for it.
        }
      }
      if (type === 'aaf_registry') doc.registries.push({ ...entry, jurisdiction: md.jurisdiction });
      else if (type === 'aaf_record_keeper') doc.record_keepers.push({ ...entry, roles: md.roles });
      else if (type === 'aaf_identity_verifier') doc.verifiers.push(entry);
      else if (type === 'aaf_resolution_authority') doc.resolution_authorities.push(entry);
    }),
  );
  for (const list of [doc.registries, doc.record_keepers, doc.verifiers, doc.resolution_authorities]) list.sort((a, b) => a.id.localeCompare(b.id));
  return new Federation(doc);
}

/**
 * Bootstrap from a trust anchor's URL (where it is served; its entity
 * identifier may differ, as in the local simulation).
 *
 * With pin (an RFC 7638 key thumbprint), the Entity Configuration must be
 * signed by the advertised key whose computed thumbprint equals the pin; that
 * key alone becomes the trusted key. A pinned key that is merely listed while
 * another key signs is refused.
 *
 * Without pin, this is trust on first use: the advertised signing key whose
 * kid matches the JWS header (else the first signing key) is selected, the
 * signature must verify with it, and it alone is kept; its computed thumbprint
 * is returned so a person can compare it with one published out of band.
 *
 * pin and entityId are either omitted (undefined) or valid: an empty or
 * non-string value is refused rather than treated as not configured. iss must
 * be an absolute URL string and equal sub.
 *
 * With entityId, iss and sub must equal it (entity_id_checked: true). Without
 * it, the self-asserted iss is used as the entity identifier and
 * entity_id_checked is false: it was not independently checked.
 */
export async function fetchTrustAnchor(url, { pin, entityId } = {}) {
  // Omitted (undefined) means "not configured"; anything else must be a usable value, never a silent downgrade.
  if (pin !== undefined && (typeof pin !== 'string' || !pin.trim())) throw new Error('pin must be a non-empty key thumbprint string');
  if (entityId !== undefined && !isEntityId(entityId)) throw new Error('entityId must be an absolute URL string');
  const base = url.replace(/\/$/, '');
  const res = await fetch(`${base}${WELL_KNOWN}`, { signal: AbortSignal.timeout(10000) });
  if (!res.ok) throw new Error(`could not fetch ${base}${WELL_KNOWN} (${res.status})`);
  const jwt = await res.text();
  const { header, payload: unverified } = decodeJws(jwt);
  const signingKeys = (unverified.jwks?.keys ?? []).filter((k) => k.use !== 'enc' && k.kty === 'OKP');
  // Pinned: by computed thumbprint only. First use: by advertised kid, as verifyEntityStatement selects keys.
  const key = pin !== undefined
    ? signingKeys.find((k) => thumbprint(k) === pin)
    : signingKeys.find((k) => k.kid === header.kid) ?? signingKeys[0];
  if (!key) throw new Error(pin !== undefined ? `trust anchor does not advertise a key with the pinned thumbprint ${pin}` : 'trust anchor entity configuration advertises no signing key');
  const kid = thumbprint(key);
  const jwks = { keys: [{ ...key, kid: key.kid ?? kid }] };
  // Throws unless that one selected key itself signed it.
  const ec = verifyEntityStatement(jwt, jwks, entityId !== undefined ? { iss: entityId, sub: entityId } : {});
  if (!isEntityId(ec.iss)) throw new Error('trust anchor entity configuration has no usable iss');
  if (ec.sub !== ec.iss) throw new Error(`trust anchor entity configuration is about ${ec.sub}, not its issuer ${ec.iss}`);
  return { entity_id: ec.iss, name: ec.metadata.federation_entity.organization_name, url: base, jwks, thumbprint: kid, entity_id_checked: entityId !== undefined };
}

const isEntityId = (v) => typeof v === 'string' && v.trim() === v && URL.canParse(v);

/** Discover the federation, retrying while the trust anchor starts. */
export async function discoverWithRetry(trustAnchor, timeoutMs = STARTUP_TIMEOUT_MS) {
  const deadline = Date.now() + timeoutMs;
  for (;;) {
    try {
      return await discoverFederation(trustAnchor);
    } catch (err) {
      if (Date.now() > deadline) throw err;
      await new Promise((r) => setTimeout(r, 150));
    }
  }
}

export class Federation {
  constructor(doc) {
    this.doc = doc;
  }

  get policies() {
    return this.doc.policies;
  }

  get trustAnchor() {
    return this.doc.trust_anchor;
  }

  /** Registries the Trust Anchor allows to issue a given Trust Mark type. */
  trustMarkIssuers(type) {
    return this.doc.trust_mark_issuers[type] ?? [];
  }

  /** A copy in which some service URLs are replaced (to simulate an outage or partition). */
  withUrlOverrides(overrides) {
    const copy = structuredClone(this.doc);
    for (const list of [copy.registries, copy.record_keepers]) {
      for (const entry of list) if (overrides[entry.id]) entry.url = overrides[entry.id];
    }
    return new Federation(copy);
  }

  registry(id) {
    return this.doc.registries.find((r) => r.id === id) ?? null;
  }

  recordKeeper(id) {
    return this.doc.record_keepers.find((r) => r.id === id) ?? null;
  }

  authority(id, kind) {
    const list = kind === 'verifier' ? this.doc.verifiers : this.doc.resolution_authorities;
    return list.find((a) => a.id === id) ?? null;
  }

  /** The member whose entity identifier prefixes a URI (e.g. a status list URI). */
  entityForUri(uri) {
    return [...this.doc.registries, ...this.doc.record_keepers].find((e) => uri === e.id || uri.startsWith(`${e.id}/`)) ?? null;
  }

  /** Map an https URI under a member's entity identifier to where that member is actually served. */
  locate(uri) {
    const e = this.entityForUri(uri);
    if (!e?.url) throw new Error(`no endpoint known for ${uri}`);
    return e.url + uri.slice(e.id.length);
  }

  get registries() {
    return this.doc.registries;
  }

  get recordKeepers() {
    return this.doc.record_keepers;
  }

  signingKey(entity, kid) {
    if (!entity) return null;
    const keys = entity.jwks.keys.filter((k) => k.use !== 'enc');
    return (kid ? keys.find((k) => k.kid === kid) : keys[0]) ?? null;
  }

  encryptionKey(entity) {
    return entity?.jwks.keys.find((k) => k.use === 'enc') ?? null;
  }
}
