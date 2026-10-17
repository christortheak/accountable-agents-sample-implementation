// The other parties around the core: agent providers (who publish provenance
// records), identity verifiers (who do the slow KYC/KYB step), and resolution
// authorities (courts and regulators who can compel identity resolution).
import crypto from 'node:crypto';
import { generateSigningKey, signJws, nowSeconds, randomId } from '../lib/crypto.js';
import { identityVerifiedClaims, attributeVerifiedClaims } from '../lib/ida.js';
import { postJson, getJson, postSigned } from '../lib/http.js';
import { TYP as RK_TYP } from '../recordkeeper/recordkeeper.js';
import { TYP as REGISTRY_TYP } from '../registry/registry.js';

/** The party that builds or operates agent software. */
export class AgentProvider {
  constructor({ name, contact }) {
    this.name = name;
    this.contact = contact;
    this.key = generateSigningKey();
  }

  /**
   * Publish a bill of materials for a build, as a CycloneDX 1.6 document.
   * Shared by every agent running that build. components: [{ type: 'model' |
   * 'framework' | 'tool' | 'library', name, version?, supplier? }]
   */
  async publishProvenance(rk, { build, components, incidentResponse = {} }) {
    const record = signJws(
      { provider: { name: this.name, contact: this.contact }, bom: cycloneDx(this, build, components, incidentResponse), iat: nowSeconds() },
      this.key,
      { typ: RK_TYP.provenance, embedJwk: true },
    );
    const res = await postJson(`${rk.url}/v1/provenance`, { record });
    return { provenanceId: res.provenance_id, receipt: res.receipt };
  }
}

const CDX_TYPES = { model: 'machine-learning-model', framework: 'framework', tool: 'application', library: 'library', data: 'data' };

/** Build a CycloneDX 1.6 BOM for an agent build. */
export function cycloneDx(provider, build, components, incidentResponse) {
  const refs = components.map((c, i) => `component-${i + 1}`);
  const contact = incidentResponse.contact ?? provider.contact;
  return {
    bomFormat: 'CycloneDX',
    specVersion: '1.6',
    serialNumber: `urn:uuid:${crypto.randomUUID()}`,
    version: 1,
    metadata: {
      timestamp: new Date().toISOString(),
      supplier: { name: provider.name, contact: contact ? [{ email: contact }] : [] },
      component: {
        type: 'application',
        'bom-ref': 'agent',
        name: build,
        supplier: { name: provider.name },
        externalReferences: contact ? [{ type: 'security-contact', url: `mailto:${contact}` }] : [],
        // Incident-response instructions (paper §3.1) as CycloneDX properties.
        properties: [
          ...(incidentResponse.constrain_endpoint ? [{ name: 'aaf:incident-response:constrain-endpoint', value: incidentResponse.constrain_endpoint }] : []),
          { name: 'aaf:incident-response:notify-principal-via', value: incidentResponse.notify_principal_via ?? 'registry' },
        ],
      },
    },
    components: components.map((c, i) => ({
      type: CDX_TYPES[c.type] ?? 'library',
      'bom-ref': refs[i],
      name: c.name,
      ...(c.version ? { version: c.version } : {}),
      ...(c.supplier ? { supplier: { name: c.supplier } } : {}),
    })),
    dependencies: [{ ref: 'agent', dependsOn: refs }],
  };
}

/** The model(s) named in a CycloneDX BOM. */
export const modelsIn = (bom) => bom.components.filter((c) => c.type === 'machine-learning-model');

/** A KYC/KYB provider trusted by the federation to verify legal persons. */
export class IdentityVerifier {
  constructor({ id, keys }) {
    this.id = id;
    this.key = keys.signing;
  }

  async verify(principal, { assurance, method, attributes = [], validForDays = 365 }) {
    const started = Date.now();
    const res = await postSigned(
      `${principal.registry.url}/v1/principals/${principal.id}/verification`,
      {
        principal_id: principal.id,
        // OpenID Connect for Identity Assurance: what was verified, how, to what level.
        verified_claims: identityVerifiedClaims({ principalType: principal.type, identity: principal.identity, assurance, method, evidenceRef: randomId('kyc', 8) }),
        expires_at: new Date(Date.now() + validForDays * 86400000).toISOString(),
        attributes: attributes.map((a) => ({ verified_claims: attributeVerifiedClaims(a), expires_at: a.expires_at ?? null })),
      },
      this.key,
      { keyid: `verifier:${this.id}` },
    );
    return { ...res, ms: Date.now() - started };
  }
}

/** A court or regulator able to compel a registry to resolve PPIDs. */
export class ResolutionAuthority {
  constructor({ id, name, keys }) {
    this.id = id;
    this.name = name;
    this.key = keys.signing;
  }

  order({ caseId, ppids, relyingParty, requester, scope = ['root_principal_identity', 'chain'], notifyPrincipal = true, purpose, validForDays = 30 }) {
    const now = nowSeconds();
    return signJws(
      {
        iss: this.id, case: caseId, ppids, relying_party: relyingParty, requester, scope,
        notify_principal: notifyPrincipal, purpose, iat: now, exp: now + validForDays * 86400, jti: randomId('ord', 10),
      },
      this.key,
      { typ: REGISTRY_TYP.order },
    );
  }

  async resolve(registry, { order, ppid, sealedRef }) {
    return postJson(`${registry.url}/v1/resolutions`, { order, ppid, sealed_ref: sealedRef });
  }

  /** Read activity logs covered by an order (and by related PPIDs the registry returned). */
  async readActivity(rk, { order, subjects, resolution }) {
    return postSigned(`${rk.url}/v1/activity/query`, { order, subjects, resolution }, this.key, { embedJwk: true });
  }

  async transparencyHead(registry) {
    return getJson(`${registry.url}/v1/transparency/sth`);
  }
}
