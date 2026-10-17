// Scenario 2 (paper §4, Scenario 2): regulatory filing, with a healthcare variant.
import { digestOf } from '../../lib/crypto.js';
import { ServiceError } from '../../lib/http.js';
import { short, payloadOf } from '../world.js';
import { whatWasLearned } from '../privacy.js';

export default {
  id: 'filing',
  title: 'Scenario 2 — Regulatory filing (government services / healthcare)',
  framing:
    'An organization authorizes an agent to prepare a government submission. Only a designated officer may approve submitting it. ' +
    'Shows: identity and authority checked separately, limits on what the agent may do alone, a required human approval, and records that settle a later dispute.',

  async run(world, n) {
    const { ledgerline, tessera } = world;
    const agency = await world.relyingParty({
      id: 'portal.state-health.example', name: 'State Health Agency filing portal',
      requests: { identity: true },
      rules: {
        'filing.validate': [{ label: 'pre-submission validation', require: { accountability: 'established', authorization: true } }],
        'filing.submit': [{ label: 'official submission', require: { accountability: 'disclosed', authorization: true } }],
      },
      handlers: {
        'filing.validate': async (p) => ({ form: p.form, errors: 0, warnings: 1 }),
        'filing.submit': async (p) => ({ confirmation: `SHA-${p.subject_digest.slice(0, 8).toUpperCase()}`, received: new Date().toISOString() }),
      },
    });
    const labApi = await world.relyingParty({
      id: 'results.regional-lab.example', name: 'Regional Lab results API',
      requests: { attributes: ['licensed_healthcare_provider'] },
      rules: { 'labs.read_results': [{ label: 'licensed providers only', require: { accountability: 'established', authorization: true, attributes: ['licensed_healthcare_provider'] } }] },
      handlers: { 'labs.read_results': async () => ({ results: 12 }) },
    });

    n.step('Northwind Health LLC is verified (KYB) with a licensing attribute');
    const northwind = await world.verifiedPrincipal({
      type: 'legal_person',
      identity: { legal_name: 'Northwind Health LLC', jurisdiction: 'US-CA', registration_number: 'CA-LLC-202614427' },
      assurance: 'high',
      method: 'KYB: Secretary of State extract + beneficial ownership',
      attributes: [{ name: 'licensed_healthcare_provider', value: 'CA', source: 'Medical Board of California (simulated)' }],
    });
    await northwind.setDisclosurePolicy({
      identity: { audiences: [agency.id], claims: ['legal_name', 'registration_number', 'jurisdiction'] },
      attributes: ['licensed_healthcare_provider'],
    });
    n.act('VerityCheck', 'verifies Northwind (assurance: high) and attests it is a licensed healthcare provider in California');
    n.act('Northwind', 'consents to disclose its legal name only to the state agency; the licensing attribute may be shown where needed');

    n.step('Northwind registers its filing agent and designates its compliance officer');
    const clerkwise = world.provider('Clerkwise Inc.', 'trust@clerkwise.example');
    const { provenanceId } = await clerkwise.publishProvenance(ledgerline, {
      build: 'Clerkwise Filer 5.0',
      components: [{ type: 'model', name: 'claude-sonnet-5-5', supplier: 'Anthropic', version: '2026-09' }, { type: 'tool', name: 'form-validator', version: '2.1' }],
      incidentResponse: { contact: 'trust@clerkwise.example' },
    });
    const filer = world.agent('FilingAgent');
    await northwind.registerAgent(filer, { label: 'Medi-Cal cost report filer', records: world.records(provenanceId), provider: { name: 'Clerkwise Inc.' } });
    const priya = world.person('Priya Raman');
    await priya.registerPasskey(ledgerline);
    const designation = await northwind.designate(priya, { rk: ledgerline, role: 'designated-officer' });
    n.act('Priya Raman', `registers a passkey with ${ledgerline.name} (WebAuthn; her device keeps the private key)`);
    n.act('Northwind', `designates the holder of that passkey as designated officer (record ${short(designation.grant_id, 14)})`);

    await northwind.grant(filer, {
      rk: ledgerline,
      permissions: [
        { action: 'filing.draft' }, { action: 'filing.assemble' }, { action: 'filing.validate' },
        { action: 'filing.submit', constraints: { requires_approval: { role: 'designated-officer' } } },
        { action: 'labs.read_results' },
      ],
      prohibitions: [{ action: 'filing.withdraw' }],
      purpose: 'Quarterly Medi-Cal cost reporting',
    });
    n.act('Northwind', 'grants: draft, assemble, validate. The agent may not submit on its own; submission needs the designated officer\'s approval of the exact document. Withdrawing filings is prohibited.');

    const q3 = { form: 'MC-COST-Q3', period: '2026-Q3', totals: { inpatient: 1840221, outpatient: 902114 } };
    const q3Digest = digestOf(q3);

    n.step('The agent validates the draft with the agency');
    const val = await filer.act(agency.url, 'filing.validate', { form: q3.form, subject_digest: q3Digest });
    n.say('The agency\'s system performs two separate checks: who is accountable, and whether this authority covers this act.');
    n.checks(agency.evidence.at(-1).checks);
    n.decision('Agency', val);
    n.learned('the agency', whatWasLearned(agency.evidence.at(-1)));
    n.expect(val.decision === 'allow' && val.classification === 'ACCOUNTABLE_DISCLOSED', 'validation accepted; the agency knows it is dealing with Northwind Health LLC');

    n.step('Failure variant: the agent tries to submit on its own');
    const direct = await filer.act(agency.url, 'filing.submit', { form: q3.form, subject_digest: q3Digest });
    n.decision('Agency', direct);
    n.expect(direct.decision === 'deny' && /approval/.test(direct.reasons.join()), 'direct submission refused: it exceeds the agent\'s scope without officer approval');

    n.step('Priya reviews the document and approves it; the agent submits');
    const ppidAtAgency = filer.contexts.get(agency.id).ppid;
    const approval = await priya.approve({ rk: ledgerline, designationId: designation.grant_id, ppid: ppidAtAgency, action: 'filing.submit', subjectDigest: q3Digest, note: 'Reviewed totals against GL' });
    n.act('Priya Raman', `approves document ${short(q3Digest, 12)} with her passkey: Ledgerline's challenge commits to the agent, the action and the document, and her authenticator signs only after verifying her (Face ID / PIN)`);
    n.act('Ledgerline Records', 'verifies the passkey assertion (user verified), confirms her designation is current, and countersigns an approval credential');
    const submit = await filer.act(agency.url, 'filing.submit', { form: q3.form, subject_digest: q3Digest }, { approval: approval.approval });
    n.checks(agency.evidence.at(-1).checks.filter((c) => /approval|authority/.test(c.name)));
    n.decision('Agency', submit);
    n.expect(submit.decision === 'allow', `submission accepted with the officer's approval (confirmation ${submit.result?.confirmation})`);

    n.step('The same approval cannot be reused for a different document');
    const altered = { ...q3, totals: { inpatient: 1940221, outpatient: 902114 } };
    const reuse = await filer.act(agency.url, 'filing.submit', { form: q3.form, subject_digest: digestOf(altered) }, { approval: approval.approval });
    n.decision('Agency', reuse);
    n.expect(reuse.decision === 'deny', 'approval bound to the reviewed document; an altered filing is refused');

    n.step("Failure variant: the officer's approval authority is revoked");
    const amended = { ...q3, amendment: 1, totals: { inpatient: 1841005, outpatient: 902114 } };
    const amendedDigest = digestOf(amended);
    const approval2 = await priya.approve({ rk: ledgerline, designationId: designation.grant_id, ppid: ppidAtAgency, action: 'filing.submit', subjectDigest: amendedDigest });
    n.act('Priya Raman', 'approves an amended filing, then leaves Northwind');
    await northwind.revokeGrant(ledgerline, designation.grant_id, 'role_ended');
    n.act('Northwind', "revokes Priya's designation");
    const late = await filer.act(agency.url, 'filing.submit', { form: q3.form, subject_digest: amendedDigest }, { approval: approval2.approval });
    n.decision('Agency', late);
    let fresh = null;
    try {
      await priya.approve({ rk: ledgerline, designationId: designation.grant_id, ppid: ppidAtAgency, action: 'filing.submit', subjectDigest: amendedDigest });
    } catch (err) {
      fresh = err;
    }
    n.act('Ledgerline Records', `refuses any new approval from Priya: ${fresh instanceof ServiceError ? fresh.message : 'unexpectedly accepted'}`);
    n.expect(late.decision === 'deny' && /designation is revoked/.test(late.reasons.join()), 'approval from a revoked officer refused at the agency');

    n.step('Months later: Northwind disputes that the Q3 filing was authorized');
    const order = world.court.order({ caseId: 'Northwind v. State Health Agency, No. 26-cv-0912', ppids: [ppidAtAgency], relyingParty: agency.id, requester: 'State Health Agency' });
    const log = await world.court.readActivity(tessera, { order, subjects: [ppidAtAgency] });
    const rows = log.entries.map((e) => {
      const p = payloadOf(e.entry.data.jws);
      const ok = world.verifyReceipt(e.receipt, e.entry).ok;
      return [e.index, p.writer_role === 'agent' ? 'agent' : p.writer, p.event, p.details.action, p.details.decision ?? p.details.outcome, ok ? 'verified' : 'FAILED'];
    });
    n.say('Under court order, the activity log for the agent\'s PPID at the agency is produced. Each entry is signed by the party that wrote it and proven to be in the keeper\'s log:');
    n.table(['#', 'written by', 'event', 'action', 'outcome', 'inclusion proof'], rows);
    n.say(`${ledgerline.name} separately holds Northwind's signed grant and the approval record tying Priya's signature to document ${short(q3Digest, 12)}.`);
    const writers = new Set(log.entries.map((e) => e.entry.data.writer_role));
    n.expect(writers.has('agent') && writers.has('relying_party') && rows.every((r) => r[5] === 'verified'), 'both sides\' accounts are present and every entry verifies against a signed tree head');

    n.step('Healthcare variant: proving licensure without naming the provider');
    const lab = await filer.act(labApi.url, 'labs.read_results', { patient_cohort: 'Q3-diabetes-panel' });
    n.decision('Regional Lab', lab);
    n.learned('the lab', whatWasLearned(labApi.evidence.at(-1)));
    n.expect(lab.decision === 'allow' && lab.classification === 'ACCOUNTABLE_PROTECTED' && labApi.evidence.at(-1).attributes.some((a) => a.name === 'licensed_healthcare_provider'),
      'the lab learns "licensed provider in CA" without learning which provider');
  },
};
