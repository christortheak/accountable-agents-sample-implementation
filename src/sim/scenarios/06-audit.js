// Scenario 6: audit and tamper evidence. The paper (Section 3.5) says attribution
// needs independently verifiable activity records beside it; this shows them.
import { getJson, postJson } from '../../lib/http.js';
import { verifyJws, verifySelfSignedJws } from '../../lib/crypto.js';
import { loadKeys } from '../../lib/trust.js';
import { entryLeafHash, STH_TYP } from '../../lib/log.js';
import { verifyConsistency } from '../../lib/merkle.js';
import { money } from '../world.js';

export default {
  id: 'audit',
  title: 'Scenario 6 — Audit: tamper-evident records',
  framing:
    'Records must be attributable to their source, tamper-evident, and reachable through the directory. Here an activity records service is compromised and quietly rewrites a refusal as an approval. ' +
    'The counterparty detects it with the receipt it was given, and the directory\'s own chain of custody is unaffected.',

  async run(world, n) {
    const { regA, ledgerline, tessera } = world;
    const directoryBefore = await world.directorySth(regA);

    n.step('A refused transaction is logged, and the counterparty keeps its receipt');
    const ostrander = await world.verifiedPrincipal({
      type: 'legal_person', identity: { legal_name: 'Ostrander Supply Co.', jurisdiction: 'US-OH', registration_number: 'OH-5521907' },
      assurance: 'high', method: 'KYB: directory extract',
    });
    const courier = world.agent('Courier');
    await ostrander.registerAgent(courier, { label: 'procurement agent', records: world.records() });
    await ostrander.grant(courier, { rs: ledgerline, permissions: [{ action: 'commerce.purchase', constraints: { max_amount: money(1000), categories: ['freight'] } }] });
    const exchange = await world.counterparty({
      id: 'parcel-exchange.example', name: 'Parcel Exchange',
      rules: { 'commerce.purchase': [{ label: 'standard', require: { accountability: 'established', authorization: true } }] },
      handlers: { 'commerce.purchase': async () => ({ booking: 'PX-1' }) },
    });
    const res = await courier.act(exchange.url, 'commerce.purchase', { item: 'Pallet freight, Columbus → Denver', amount: money(4800), category: 'freight' });
    n.decision('Parcel Exchange', res);
    const ev = exchange.evidence.at(-1);
    const receipt = ev.activity_receipt;
    const sthAtReceipt = verifyJws(receipt.sth, world.trust.signingKey(tessera), { typ: STH_TYP }).payload;
    n.act('Tessera Logs', `acknowledges entry #${receipt.index} with an inclusion proof and a signed tree head (size ${sthAtReceipt.tree_size}, root ${sthAtReceipt.root_hash.slice(0, 16)}…)`);
    n.expect(res.decision === 'deny' && world.verifyReceipt(receipt).ok, 'refusal recorded; receipt verifies');

    n.step('The records service is compromised and rewrites history');
    const { adminToken } = loadKeys(tessera.id, world.keysDir);
    await postJson(`${tessera.url}/admin/tamper`, { index: receipt.index, details: { decision: 'allow', reasons: [] } }, { authorization: `Bearer ${adminToken}` });
    n.act('Tessera Logs (compromised)', `rewrites entry #${receipt.index} so the refusal reads as an approval, and recomputes its tree to stay internally consistent`);

    n.step('Parcel Exchange audits its record');
    const mine = await exchange.readActivity(tessera, ev.aaf_id);
    const current = mine.entries.find((e) => e.index === receipt.index);
    const contentMatches = entryLeafHash(current.entry) === receipt.leaf_hash;
    let signatureOk = true;
    try {
      verifySelfSignedJws(current.entry.data.jws);
    } catch {
      signatureOk = false;
    }
    n.act('Parcel Exchange', `entry #${receipt.index} now hashes to ${entryLeafHash(current.entry).slice(0, 16)}…, but the receipt says ${receipt.leaf_hash.slice(0, 16)}… → ${contentMatches ? 'match' : 'MISMATCH'}`);
    n.act('Parcel Exchange', `its own signature on the entry ${signatureOk ? 'still verifies' : 'no longer verifies, so the change was not made by Parcel Exchange'}`);
    const { sth: nowSthJws } = await getJson(`${tessera.url}/v1/log/sth`);
    const nowSth = verifyJws(nowSthJws, world.trust.signingKey(tessera), { typ: STH_TYP }).payload;
    const cons = await getJson(`${tessera.url}/v1/log/consistency?first=${sthAtReceipt.tree_size}&second=${nowSth.tree_size}`);
    const consistent = verifyConsistency({ firstSize: sthAtReceipt.tree_size, secondSize: nowSth.tree_size, firstRoot: sthAtReceipt.root_hash, secondRoot: nowSth.root_hash, proof: cons.proof });
    const proofNow = await getJson(`${tessera.url}/v1/log/proof?index=${receipt.index}&size=${sthAtReceipt.tree_size}`);
    n.act('Parcel Exchange', `asks Tessera to prove its current log extends the tree it signed earlier → ${consistent ? 'proof verifies' : 'proof FAILS'}`);
    n.act('Parcel Exchange', `Tessera now reports root ${proofNow.root_hash.slice(0, 16)}… for size ${sthAtReceipt.tree_size}, but it signed ${sthAtReceipt.root_hash.slice(0, 16)}… for that size`);
    n.note('Two signed statements from the same records service about the same tree size disagree. That is cryptographic proof of misconduct, which can be put to the accrediting directory.');
    n.expect(!contentMatches && !signatureOk && !consistent && proofNow.root_hash !== sthAtReceipt.root_hash, 'tampering detected, with proof that can be shown to others');

    n.step("The directory's chain of custody is intact");
    const directoryNow = await world.directorySth(regA);
    const rc = await getJson(`${regA.url}/v1/transparency/consistency?first=${directoryBefore.tree_size}&second=${directoryNow.tree_size}`);
    const directoryConsistent = verifyConsistency({ firstSize: directoryBefore.tree_size, secondSize: directoryNow.tree_size, firstRoot: directoryBefore.root_hash, secondRoot: directoryNow.root_hash, proof: rc.proof });
    n.act('Auditor', `checks ${regA.name}'s transparency log grew append-only from ${directoryBefore.tree_size} to ${directoryNow.tree_size} entries → ${directoryConsistent ? 'verified' : 'FAILED'}`);
    const order = world.court.order({ caseId: 'In re Tessera Logs (accreditation review)', aaf_ids: [ev.aaf_id], counterparty: exchange.id, requester: 'Directory A accreditation board' });
    const traced = await world.court.trace(regA, { order, aaf_id: ev.aaf_id });
    n.act('Investigators', `still trace the agent through the directory → ${traced.result.principal.identity.legal_name}; the directory's record never depended on Tessera`);
    n.expect(directoryConsistent && traced.result.principal.identity.legal_name === 'Ostrander Supply Co.', 'directory log verified append-only; the investigation proceeds without the compromised records service');
  },
};
