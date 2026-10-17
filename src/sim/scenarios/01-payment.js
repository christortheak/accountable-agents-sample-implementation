// Scenario 1 (paper §4, Scenario 1): agentic payment in the financial sector.
import { money, short } from '../world.js';
import { whatWasLearned, sharedHandles, publicValuesOf } from '../privacy.js';
import { describePermission } from '../../lib/scope.js';
import { describeVerification } from '../../lib/ida.js';

export default {
  id: 'payment',
  title: 'Scenario 1 — Agentic payment (financial sector)',
  framing:
    'A consumer authorizes a shopping agent. Merchants and a bank with Bank Secrecy Act obligations must decide whether to accept its transactions. ' +
    'Shows: PPIDs on first contact, selective disclosure, live status, refusal above the authorized limit, revocation, evidence retention, and identity resolution by a regulator.',

  async run(world, n) {
    const { regA, ledgerline } = world;

    n.step('Onboarding, done once: the slow step');
    const dana = await world.verifiedPrincipal({
      type: 'natural_person',
      identity: { legal_name: 'Dana Whitfield', jurisdiction: 'US-NY', date_of_birth: '1988-04-12' },
      assurance: 'IAL2',
      method: 'government ID + liveness check',
    });
    n.act('Dana Whitfield', `enrolls with ${regA.name} as a natural person`);
    n.act('VerityCheck (identity verifier)', `verifies her identity at IAL2; the registry records it (principal ${short(dana.id, 16)})`);
    n.note('In practice this takes minutes to days. It happens once; every later agent registration reuses it.');
    n.expect(dana.verification.verification === 'verified', 'principal verified before any agent is registered');

    n.step('The agent provider publishes a bill of materials (provenance record)');
    const acme = world.provider('Acme Agents Inc.', 'security@acme-agents.example');
    const { provenanceId } = await acme.publishProvenance(ledgerline, {
      build: 'ShopBot 2.3.1',
      components: [
        { type: 'model', name: 'gpt-5.6-sol', supplier: 'OpenAI', version: '2026-07' },
        { type: 'framework', name: 'acme-agent-runtime', version: '4.2.0' },
        { type: 'tool', name: 'checkout-browser', version: '1.9.3' },
      ],
      incidentResponse: { contact: 'security@acme-agents.example', constrain_endpoint: 'https://acme-agents.example/agents/constrain', notify_principal_via: 'registry' },
    });
    n.act('Acme Agents', `deposits the ShopBot 2.3.1 bill of materials with ${ledgerline.name} → ${provenanceId}`);
    n.note('One provenance record serves every agent running this build, so pointing to it does not single out any one agent.');

    n.step('Dana registers her shopping agent: the fast step');
    const shopbot = world.agent('ShopBot');
    const reg = await dana.registerAgent(shopbot, { label: "Dana's shopping agent", records: world.records(provenanceId), provider: { name: 'Acme Agents Inc.', contact: 'security@acme-agents.example' } });
    n.act('Dana', `registers ShopBot under her verified registration → ${short(reg.registration_id, 16)} in ${reg.issuance_ms} ms`);
    n.expect(reg.issuance_ms < 50, `registration against an already-verified principal is fast (${reg.issuance_ms} ms)`);

    n.step('Dana grants authority; the grant is deposited as an authorization record');
    await dana.grant(shopbot, {
      rk: ledgerline,
      permissions: [
        { action: 'commerce.purchase', constraints: { max_amount: money(500), categories: ['electronics', 'books', 'home'] } },
        { action: 'payments.authorize', constraints: { max_amount: money(500) } },
        { action: 'travel.book', constraints: { max_amount: money(200), categories: ['rail'] } },
      ],
      prohibitions: [{ action: 'commerce.subscribe' }],
      purpose: 'Household purchasing',
      validForDays: 30,
    });
    n.act('Dana', 'signs a grant: purchases ≤ $500 (electronics, books, home), payments ≤ $500, rail tickets ≤ $200; no subscriptions; 30 days; no further delegation');
    n.act('Ledgerline Records', 'verifies her signature against her registration and keeps the grant for her');

    const gadgetBarn = await world.relyingParty({
      id: 'gadgetbarn.example', name: 'Gadget Barn',
      rules: { 'commerce.purchase': [{ label: 'standard', require: { accountability: 'established', authorization: true } }] },
      handlers: { 'commerce.purchase': async (p) => ({ order: `GB-${Math.floor(Math.random() * 1e6)}`, item: p.item }) },
    });
    const bookNook = await world.relyingParty({
      id: 'booknook.example', name: 'Book Nook',
      rules: { 'commerce.purchase': [{ label: 'standard', require: { accountability: 'established', authorization: true } }] },
      handlers: { 'commerce.purchase': async (p) => ({ order: `BN-${Math.floor(Math.random() * 1e6)}`, item: p.item }) },
    });
    const sarCandidates = [];
    const bank = await world.relyingParty({
      id: 'firstledger.bank.example', name: 'First Ledger Bank',
      rules: { 'payments.authorize': [{ label: 'BSA-covered payment', require: { accountability: 'established', authorization: true } }] },
      handlers: { 'payments.authorize': async (p) => ({ payment: `PAY-${Math.floor(Math.random() * 1e6)}`, payee: p.payee }) },
      onDecision: ({ decision, evidence }) => {
        if (decision.decision !== 'allow' && evidence.ppid) {
          const detected = new Date();
          sarCandidates.push({ evidence, detected, fileBy: new Date(detected.getTime() + 30 * 86400000) });
        }
      },
    });

    n.step('First contact: ShopBot buys headphones at Gadget Barn');
    const buy1 = await shopbot.act(gadgetBarn.url, 'commerce.purchase', { item: 'Noise-cancelling headphones', amount: money(129), category: 'electronics' });
    n.act('ShopBot', `presents a PPID created for Gadget Barn, its authority, and a proof of key possession (${buy1.latencyMs} ms round trip)`);
    n.checks(gadgetBarn.evidence.at(-1).checks);
    n.decision('Gadget Barn', buy1);
    n.learned('Gadget Barn', whatWasLearned(gadgetBarn.evidence.at(-1)));
    n.expect(buy1.decision === 'allow' && buy1.classification === 'ACCOUNTABLE_PROTECTED', 'purchase accepted from an accountable agent whose principal stays private');
    n.expect(gadgetBarn.evidence.at(-1).authority_relied_on.length === 1, 'merchant saw only the purchasing permission, not the payment or travel authority');

    n.step('ShopBot asks First Ledger Bank to pay the merchant');
    const pay1 = await shopbot.act(bank.url, 'payments.authorize', { payee: 'gadgetbarn.example', amount: money(129) });
    n.decision('First Ledger Bank', pay1);
    const bankEv = bank.evidence.at(-1);
    n.say('The bank keeps a BSA-ready record of what it relied on:');
    n.detail('PPID presented', short(bankEv.ppid, 48));
    n.detail('chain resolved', `${bankEv.root.type}, ${bankEv.root.assurance}, ${bankEv.chain_length} link(s), via ${bankEv.registry}`);
    n.detail('profile relied upon', bankEv.authority_relied_on.map(describePermission).join('; '));
    n.detail('signed status tokens retained', bankEv.status_tokens.length);
    n.detail('disposition', bankEv.decision);
    const rv = world.verifyReceipt(bankEv.activity_receipt);
    n.detail('activity-log receipt', `${bankEv.activity_receipt.log_id} #${bankEv.activity_receipt.index}, inclusion proof ${rv.ok ? 'verified' : 'FAILED'}`);
    n.expect(pay1.decision === 'allow' && rv.ok, 'payment accepted; the bank holds a verifiable receipt for its log entry');

    n.step('ShopBot shops at a second merchant, Book Nook');
    const buy2 = await shopbot.act(bookNook.url, 'commerce.purchase', { item: 'The Federalist Papers', amount: money(38), category: 'books' });
    n.decision('Book Nook', buy2);
    n.expect(buy2.decision === 'allow', 'second merchant accepts');
    n.expect(buy2.ppid !== buy1.ppid, `different PPID at each merchant (${short(buy1.ppid.split(':').pop(), 10)} vs ${short(buy2.ppid.split(':').pop(), 10)})`);

    n.step('Can the two merchants tell they served the same agent?');
    const publicValues = publicValuesOf(world.trust, [gadgetBarn.id, bookNook.id, bank.id]);
    const shared = sharedHandles(gadgetBarn.received, bookNook.received, publicValues);
    const sharedBank = sharedHandles(gadgetBarn.received, bank.received, publicValues);
    n.say('Each party pools everything it received (identifiers, keys, signatures, salts, digests, timestamps) and compares.');
    n.detail('values shared by Gadget Barn and Book Nook', shared.length ? shared.map((s) => s.whereA).join(', ') : 'none');
    n.detail('values shared by Gadget Barn and the bank', sharedBank.length ? sharedBank.map((s) => s.whereA).join(', ') : 'none');
    n.expect(shared.length === 0 && sharedBank.length === 0, 'nothing presented to one relying party can be matched against another');
    const again = await shopbot.act(gadgetBarn.url, 'commerce.purchase', { item: 'USB-C cable', amount: money(12), category: 'electronics' });
    n.expect(again.ppid === buy1.ppid, 'Gadget Barn recognizes the same agent on a return visit (pairwise PPIDs are stable per relying party)');

    n.step('Failure variant 1: a transaction above the authorized limit');
    const big = await shopbot.act(gadgetBarn.url, 'commerce.purchase', { item: 'Gaming laptop', amount: money(899), category: 'electronics' });
    n.decision('Gadget Barn', big);
    const bigPay = await shopbot.act(bank.url, 'payments.authorize', { payee: 'gadgetbarn.example', amount: money(899) });
    n.decision('First Ledger Bank', bigPay);
    const sar = sarCandidates.at(-1);
    n.act('First Ledger Bank', `flags the refused attempt as a SAR candidate: detected ${sar?.detected.toISOString().slice(0, 10)}, must file by ${sar?.fileBy.toISOString().slice(0, 10)} (30 days)`);
    n.note('Today such a SAR would have no accountable subject. Here the filer holds a PPID, a verified chain, and the profile the agent presented.');
    n.expect(big.decision === 'deny' && bigPay.decision === 'deny' && Boolean(sar), 'over-limit purchase and payment refused; refusal recorded as a SAR candidate');

    n.step('Failure variant 2: Dana revokes the agent');
    const rev = await dana.revokeAgent(shopbot, 'compromised');
    n.act('Dana', `reports her phone stolen and revokes ShopBot (reason: compromised) → ${rev.status}`);
    const after = await shopbot.act(bookNook.url, 'commerce.purchase', { item: 'Paperback', amount: money(15), category: 'books' });
    n.decision('Book Nook', after);
    n.note(`Live status checks see revocation immediately. A relying party that skips them stops accepting the attestation when it expires, within ${world.trust.policies.attestationTtlSeconds}s.`);
    n.expect(after.decision === 'deny' && after.classification === 'REVOKED', 'post-revocation transaction refused');

    n.step('A regulator with legal authority resolves the SAR subject');
    const order = world.regulator.order({
      caseId: 'SAR-2026-10-4471', ppids: [sar.evidence.ppid], relyingParty: bank.id, requester: 'First Ledger Bank (SAR filer)',
      notifyPrincipal: false, purpose: '31 U.S.C. 5318(g) follow-up',
    });
    const resolution = await world.regulator.resolve(regA, { order, ppid: sar.evidence.ppid });
    const rp = resolution.result.root_principal;
    n.act('Regulator', `presents order SAR-2026-10-4471 to ${regA.name}`);
    n.detail('root principal', `${rp.identity.legal_name} (${rp.type}), ${rp.identity.jurisdiction}`);
    n.detail('verification evidence (OpenID verified_claims)', `${rp.verification.verifier}: ${describeVerification(rp.verification)}, process ${rp.verification.verification_process}`);
    n.detail('chain', resolution.result.chain.map((c) => `${c.label} [${c.status}${c.reason ? `: ${c.reason}` : ''}]`).join(' → '));
    const notes = await dana.notifications();
    n.expect(rp.identity.legal_name === 'Dana Whitfield', 'regulator obtains the identity the merchants never saw');
    n.expect(!notes.some((x) => x.kind === 'resolution'), 'principal not notified, because the order forbids tipping off (SAR confidentiality)');
    const sth = await world.registrySth(regA);
    n.note(`The resolution is itself logged in the registry's transparency log (now ${sth.tree_size} entries), so lookups of identity can also be audited.`);
  },
};
