// Scenario 4: the pilot the paper's conclusion (Section 4) calls for. An agent requests paid
// computing resources. The pilot covers disclosed organizational principals,
// privacy-protected human principals, unsupported accountability claims, and
// revoked or compromised credentials.
import { generateSigningKey, nowSeconds, publicOf } from '../../lib/crypto.js';
import { issueSdJwt } from '../../lib/sd-jwt.js';
import { ServiceError } from '../../lib/http.js';
import { whatWasLearned } from '../privacy.js';

const gpu = (units, region = 'us-east') => ({ units, unit: 'gpu-hour', region, instance: 'h200x8' });

export default {
  id: 'compute',
  title: 'Scenario 4 — Paid compute pilot (the pilot the paper calls for)',
  framing:
    'Ampere Cloud rents GPUs to agents. Small jobs need an accountable principal and authority. Large jobs also need a disclosed principal and the agent\'s bill of materials. ' +
    'Success means a timely, justified decision that preserves privacy and leaves usable evidence, not merely returning an identifier.',

  async run(world, n) {
    const { regA, ledgerline } = world;
    const rules = {
      'compute.provision': [
        { label: 'small (≤ 8 GPU-hours)', when: (p) => p.units <= 8, require: { accountability: 'established', authorization: true } },
        { label: 'large (> 8 GPU-hours)', require: { accountability: 'disclosed', authorization: true, provenance: true } },
      ],
    };
    const handlers = { 'compute.provision': async (p) => ({ allocation: `alloc-${Math.floor(Math.random() * 1e6)}`, gpu_hours: p.units, region: p.region }) };
    const ampere = await world.counterparty({ id: 'ampere.example', name: 'Ampere Cloud', requests: { identity: true, provenance: true }, rules, handlers });
    const summary = [];
    const evidenceKept = (ev) => {
      if (!ev?.aaf_id) return 'the rejected request';
      const parts = ['signed presentation'];
      if (ev.status_tokens.length) parts.push(`${ev.status_tokens.length} signed status token(s)`);
      if (ev.sealed_ref) parts.push('sealed reference');
      if (ev.activity_receipt) parts.push('log receipt');
      return parts.join(' + ');
    };
    const record = (label, res, ev) =>
      summary.push([
        label, res.decision, res.classification, res.latencyMs != null ? `${res.latencyMs}ms` : '—',
        ev?.principal ? (ev.principal.identity?.legal_name ?? 'a verified principal, identity protected') : 'nothing verifiable',
        evidenceKept(ev),
      ]);

    n.step('Case 1: a disclosed organizational principal');
    const helix = await world.verifiedPrincipal({
      type: 'legal_person', identity: { legal_name: 'Helix Bio Inc.', jurisdiction: 'US-MA', registration_number: 'MA-001844210' },
      assurance: 'high', method: 'KYB: directory extract + beneficial ownership',
    });
    await helix.setDisclosurePolicy({ identity: { audiences: [ampere.id], claims: ['legal_name', 'registration_number'] } });
    const { provenanceId } = await world.provider('Lattice Agents Ltd.', 'security@lattice.example').publishProvenance(ledgerline, {
      build: 'Lattice Pipeline Agent 3.4',
      components: [{ type: 'model', name: 'claude-opus-5-5', supplier: 'Anthropic' }, { type: 'tool', name: 'slurm-submit', version: '1.2' }],
      incidentResponse: { contact: 'security@lattice.example' },
    });
    const pipeline = world.agent('Helix pipeline agent');
    await helix.registerAgent(pipeline, { label: 'protein-folding pipeline', records: world.records(provenanceId), provider: { name: 'Lattice Agents Ltd.' } });
    await helix.grant(pipeline, { rs: ledgerline, permissions: [{ action: 'compute.provision', constraints: { max_units: { value: 256, unit: 'gpu-hour' }, regions: ['us-east'] } }] });
    const big = await pipeline.act(ampere.url, 'compute.provision', gpu(64));
    n.decision('Ampere Cloud', big);
    n.learned('Ampere', whatWasLearned(ampere.evidence.at(-1)));
    record('disclosed org, 64 GPU-h', big, ampere.evidence.at(-1));
    n.expect(big.decision === 'allow' && big.classification === 'ACCOUNTABLE_DISCLOSED', 'large job granted to a disclosed, accountable organization with a published bill of materials');

    n.step('Case 2: a privacy-protected human principal using single-use IDs');
    const sam = await world.verifiedPrincipal({
      type: 'natural_person', identity: { legal_name: 'Samuel Okafor', jurisdiction: 'US-CA', date_of_birth: '1994-02-03' },
      assurance: 'IAL2', method: 'government ID + liveness check',
    });
    const research = world.agent("Sam's research agent");
    await sam.registerAgent(research, { label: 'thesis experiments', records: world.records() });
    await sam.grant(research, { rs: ledgerline, permissions: [{ action: 'compute.provision', constraints: { max_units: { value: 64, unit: 'gpu-hour' }, regions: ['us-east', 'us-west'] } }] });
    n.act('Samuel Okafor', 'an independent researcher, verified at IAL2, consents to disclose nothing. His agent uses unlinkable IDs: a fresh one for every request.');
    const s1 = await research.act(ampere.url, 'compute.provision', gpu(4), { mode: 'unlinkable' });
    const s2 = await research.act(ampere.url, 'compute.provision', gpu(2), { mode: 'unlinkable' });
    n.decision('Ampere Cloud (4 GPU-h)', s1);
    n.decision('Ampere Cloud (2 GPU-h)', s2);
    const samEvidence = ampere.evidence.at(-2);
    n.learned('Ampere', whatWasLearned(samEvidence));
    record('protected human, 4 GPU-h', s1, samEvidence);
    n.expect(s1.decision === 'allow' && s1.classification === 'ACCOUNTABLE_PROTECTED', 'small job granted while the person stays private');
    n.expect(s1.aaf_id !== s2.aaf_id && Boolean(samEvidence.sealed_ref), 'Ampere cannot even link the two sessions; it keeps a sealed reference only the directory can open');
    const s3 = await research.act(ampere.url, 'compute.provision', gpu(32), { mode: 'unlinkable' });
    n.decision('Ampere Cloud (32 GPU-h)', s3);
    record('protected human, 32 GPU-h', s3, ampere.evidence.at(-1));
    n.expect(s3.decision === 'step_up', 'a large job asks for more (disclosure). Sam can decline and keep using small jobs');

    n.step('Case 3: unsupported accountability claims');
    const claim = await world.rawRequest(ampere.url, 'compute.provision', gpu(4), { 'aaf-claim': 'principal="Helix Bio Inc."; accountable=true' });
    n.decision('Ampere Cloud (self-asserted claim)', claim);
    record('self-asserted claim', claim, ampere.evidence.at(-1));

    const rogueDirectoryKey = generateSigningKey();
    const forgerKey = generateSigningKey();
    const now = nowSeconds();
    const forged = issueSdJwt(
      {
        vct: `${world.trust.trustAnchor.entity_id}/vct/accountability/1`,
        iss: 'https://directory-x.example', sub: 'aaf:directory-x.example:p_00000000000000000000000000', aud: ampere.id, iat: now, exp: now + 300,
        cnf: { jwk: publicOf(forgerKey.publicJwk) }, id_mode: 'pairwise',
        accountability: { status: 'accountable', principal_type: 'legal_person', assurance: { trust_framework: 'aaf_kyb', assurance_level: 'high' }, verification_source: { verifier: 'https://trust-us.example' }, chain_length: 1, attributes: [] },
        records: [],
      },
      rogueDirectoryKey,
      { typ: 'dc+sd-jwt' },
    );
    const rogue = await world.handBuiltRequest({ counterparty: ampere, action: 'compute.provision', params: gpu(4), accountability: forged, proofKey: forgerKey });
    n.decision('Ampere Cloud (attestation from a directory outside the federation)', rogue);
    record('unknown directory', rogue, ampere.evidence.at(-1));

    const intercepted = pipeline.contexts.get(ampere.id);
    const thiefKey = generateSigningKey();
    const replay = await world.handBuiltRequest({ counterparty: ampere, action: 'compute.provision', params: gpu(8), accountability: intercepted.attestation, authorization: intercepted.authorization, proofKey: thiefKey });
    n.decision("Ampere Cloud (Helix's intercepted credentials, replayed)", replay);
    record('replayed credentials', replay, ampere.evidence.at(-1));
    n.expect([claim, rogue, replay].every((r) => r.decision === 'deny' && r.classification === 'UNSUPPORTED'), 'all three are classified UNSUPPORTED, distinct from accountable and from unlabeled');

    const westRegion = await world.counterparty({
      id: ampere.id, name: 'Ampere Cloud us-west (network partition)', requests: { identity: true }, rules, handlers,
      trust: world.trust.withUrlOverrides({ [regA.id]: 'http://127.0.0.1:9' }),
    });
    const partitioned = await research.act(westRegion.url, 'compute.provision', gpu(2, 'us-west'), { mode: 'unlinkable' });
    n.decision('Ampere Cloud us-west (cannot reach the directory)', partitioned);
    record('directory unreachable', partitioned, westRegion.evidence.at(-1));
    n.expect(partitioned.decision === 'deferred' && partitioned.classification === 'LOOKUP_FAILED', 'a failed lookup is reported as a failed lookup, not as a rogue agent; access is deferred');

    n.step('Case 4: revoked or compromised credentials');
    await research.contextFor(ampere.id, { mode: 'pairwise' });
    n.act('Attacker', "compromises Sam's agent host and copies its keys and cached credentials");
    await sam.revokeAgent(research, 'compromised');
    n.act('Samuel Okafor', 'revokes the agent');
    let fresh;
    try {
      await research.act(ampere.url, 'compute.provision', gpu(4), { mode: 'unlinkable' });
    } catch (err) {
      fresh = err;
    }
    n.act('Attacker', `asks the directory for fresh credentials → ${fresh instanceof ServiceError ? `refused (${fresh.message})` : 'unexpectedly issued'}`);
    const cached = await research.act(ampere.url, 'compute.provision', gpu(4), { mode: 'pairwise' });
    n.decision('Ampere Cloud (cached, still-unexpired credentials)', cached);
    record('revoked, cached credentials', cached, ampere.evidence.at(-1));
    n.expect(fresh instanceof ServiceError && cached.decision === 'deny' && cached.classification === 'REVOKED', 'revoked credentials fail both ways: no new attestations, and cached ones fail the live status check');

    n.step('Unlinkable IDs can still be traced, but only with the sealed reference');
    const order = world.court.order({ caseId: 'Ampere Cloud v. Doe (unpaid invoice)', aaf_ids: [s1.aaf_id], counterparty: ampere.id, requester: 'Ampere Cloud' });
    let without;
    try {
      await world.court.trace(regA, { order, aaf_id: s1.aaf_id });
    } catch (err) {
      without = err;
    }
    const withRef = await world.court.trace(regA, { order, aaf_id: s1.aaf_id, sealedRef: samEvidence.sealed_ref });
    n.act('Court', `without the sealed reference → ${without?.message}`);
    n.act('Court', `with the sealed reference Ampere kept → ${withRef.result.principal.identity.legal_name} (${withRef.result.principal.type})`);
    n.expect(without?.code === 'sealed_ref_required' && withRef.result.principal.identity.legal_name === 'Samuel Okafor', 'the directory stores nothing linkable, yet a party holding evidence can still obtain attribution under legal process');

    n.step('Pilot scorecard');
    n.table(['case', 'decision', 'classification', 'latency', 'what Ampere learned about the principal', 'evidence kept'], summary);
  },
};
