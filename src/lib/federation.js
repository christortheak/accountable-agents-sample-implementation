// Bootstrapping the local federation: key generation, the trust anchor's
// records (its governance decisions), starting services, and accreditation.
import fs from 'node:fs';
import path from 'node:path';
import crypto from 'node:crypto';
import { generateSigningKey, generateEncryptionKey, b64u } from './crypto.js';
import { loadFederationConfig, loadKeys, discoverFederation, fileNameFor, DATA_DIR } from './trust.js';
import { postJson } from './http.js';
import { jwksOf, trustMarkType, WELL_KNOWN } from './openid-federation.js';
import { startTrustAnchor } from '../trustanchor/server.js';
import { startRegistry } from '../registry/server.js';
import { startRecordKeeper } from '../recordkeeper/server.js';

export const pathsFor = (dataDir = DATA_DIR) => ({ dataDir, keysDir: path.join(dataDir, 'keys') });

const urlFor = (config, port, portOffset) => `http://${config.host}:${port + portOffset}`;

/**
 * Generate any missing keys and write the trust anchor's records: its own
 * bootstrap document (trust-anchor.json, distributed to every party) and the
 * membership it will vouch for (federation-members.json).
 */
export function setupFederation({ dataDir = DATA_DIR, reset = false, portOffset = 0, config = loadFederationConfig() } = {}) {
  const paths = pathsFor(dataDir);
  if (reset) fs.rmSync(dataDir, { recursive: true, force: true });
  fs.mkdirSync(paths.keysDir, { recursive: true });

  const ensureKeys = (id, { encryption = false, pairwise = false, admin = false }) => {
    const file = path.join(paths.keysDir, `${fileNameFor(id)}.json`);
    if (!fs.existsSync(file)) {
      const keys = { signing: generateSigningKey().privateJwk };
      if (encryption) keys.encryption = generateEncryptionKey().privateJwk;
      if (pairwise) keys.pairwiseSecret = b64u.encode(crypto.randomBytes(32));
      if (admin) keys.adminToken = b64u.encode(crypto.randomBytes(18));
      fs.writeFileSync(file, JSON.stringify(keys, null, 2), { mode: 0o600 });
    }
    return loadKeys(id, paths.keysDir);
  };

  const ta = config.trustAnchor;
  const taKeys = ensureKeys(ta.id, {});
  // Published addresses: a service's public URL if it has one (pilot deployments
  // behind HTTPS), otherwise its local port.
  const publicOr = (entry) => entry.publicUrl ?? urlFor(config, entry.port, portOffset);
  const trustAnchor = { entity_id: ta.id, name: ta.name, url: publicOr(ta), jwks: jwksOf(taKeys.signing) };

  const members = [];
  const trustMarkIssuers = {};
  for (const svc of config.services) {
    const endpointBase = publicOr(svc);
    if (svc.kind === 'registry') {
      const keys = ensureKeys(svc.id, { encryption: true, pairwise: true, admin: true });
      members.push({
        entity_id: svc.id, entity_type: 'aaf_registry',
        jwks: jwksOf(keys.signing),
        metadata: { organization_name: svc.name, jurisdiction: svc.jurisdiction, endpoint_base: endpointBase, jwks: jwksOf(keys.signing, keys.encryption) },
      });
    } else {
      const keys = ensureKeys(svc.id, { admin: true });
      members.push({
        entity_id: svc.id, entity_type: 'aaf_record_keeper',
        jwks: jwksOf(keys.signing),
        metadata: { organization_name: svc.name, roles: svc.roles, endpoint_base: endpointBase, jwks: jwksOf(keys.signing) },
      });
      // Governance decision: which registries may accredit record keepers for which roles.
      for (const role of svc.roles) {
        const type = trustMarkType(ta.id, role);
        trustMarkIssuers[type] = [...new Set([...(trustMarkIssuers[type] ?? []), ...svc.accreditedBy])];
      }
    }
  }
  for (const a of config.authorities) {
    const keys = ensureKeys(a.id, {});
    const type = a.kind === 'verifier' ? 'aaf_identity_verifier' : 'aaf_resolution_authority';
    members.push({ entity_id: a.id, entity_type: type, jwks: jwksOf(keys.signing), metadata: { organization_name: a.name, jwks: jwksOf(keys.signing) } });
  }

  fs.writeFileSync(path.join(dataDir, 'trust-anchor.json'), JSON.stringify(trustAnchor, null, 2));
  fs.writeFileSync(
    path.join(dataDir, 'federation-members.json'),
    JSON.stringify({ trust_anchor: { entity_id: ta.id, name: ta.name, url: trustAnchor.url }, policies: config.policies, trust_mark_issuers: trustMarkIssuers, members }, null, 2),
  );
  return { trustAnchor, paths, config, portOffset };
}

/** Start the trust anchor and every service in this process (tests, and `npm run sim` when nothing is running). */
export async function startFederationInProcess({ dataDir = DATA_DIR, portOffset = 0, quiet = true, reset = false } = {}) {
  const setup = setupFederation({ dataDir, portOffset, reset });
  const { trustAnchor, paths, config } = setup;
  const listenHost = config.listenHost ?? config.host;
  const handles = [await startTrustAnchor({ dataDir, port: config.trustAnchor.port + portOffset, host: listenHost, quiet })];
  const initial = await discoverFederation(trustAnchor);
  for (const svc of config.services) {
    const common = {
      id: svc.id, port: svc.port + portOffset, host: listenHost, trustList: initial,
      keys: loadKeys(svc.id, paths.keysDir), dataDir: path.join(dataDir, fileNameFor(svc.id)), quiet,
    };
    if (svc.kind === 'registry') handles.push(await startRegistry(common));
    else handles.push(await startRecordKeeper({ ...common, allowTamperSimulation: Boolean(svc.allowTamperSimulation) }));
  }
  await accreditAll({ trustList: initial, paths, config, portOffset });
  const trustList = await discoverFederation(trustAnchor);
  for (const h of handles) if (h.setTrust) h.setTrust(trustList);
  return { trustList, trustAnchor, paths, config, close: () => Promise.all(handles.map((h) => h.close())), handles };
}

/**
 * Each registry accredits the record keepers that applied to it by issuing
 * Trust Marks; the keepers publish them in their Entity Configurations.
 */
export async function accreditAll({ trustList, paths, config, portOffset = 0 }) {
  // Operator calls go to each co-located service directly, never over the
  // internet, so a public deployment can block /admin/* at its proxy.
  const adminUrl = (id) => urlFor(config, config.services.find((s) => s.id === id).port, portOffset);
  const results = [];
  for (const svc of config.services.filter((s) => s.kind === 'record-keeper')) {
    const rk = trustList.recordKeeper(svc.id);
    const marks = [];
    for (const registryId of svc.accreditedBy) {
      const { adminToken } = loadKeys(registryId, paths.keysDir);
      const res = await postJson(`${adminUrl(registryId)}/admin/accreditations`, { rk: rk.id }, { authorization: `Bearer ${adminToken}` });
      marks.push(...res.trust_marks);
      results.push({ registry: registryId, rk: rk.id, already: Boolean(res.already), types: res.trust_marks.map((m) => m.trust_mark_type) });
    }
    const { adminToken } = loadKeys(rk.id, paths.keysDir);
    await postJson(`${adminUrl(rk.id)}/admin/trust-marks`, { trust_marks: marks }, { authorization: `Bearer ${adminToken}` });
  }
  return results;
}

/** True if the trust anchor and every service answer at their Entity Configuration endpoint. */
export async function federationIsRunning({ config, portOffset = 0 }) {
  try {
    const ports = [config.trustAnchor.port, ...config.services.map((s) => s.port)];
    await Promise.all(ports.map((p) => fetch(`${urlFor(config, p, portOffset)}${WELL_KNOWN}`, { signal: AbortSignal.timeout(1500) }).then((r) => {
      if (!r.ok) throw new Error('not ready');
    })));
    return true;
  } catch {
    return false;
  }
}

