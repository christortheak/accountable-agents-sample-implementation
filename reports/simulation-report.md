# Accountable Agents Framework: simulation report

Generated 2026-10-17T21:37:42.674Z by `npm run sim`.

## Scenario 1 — Agentic payment (financial sector)

A consumer authorizes a shopping agent. Merchants and a bank with Bank Secrecy Act obligations must decide whether to accept its transactions. Shows: PPIDs on first contact, selective disclosure, live status, refusal above the authorized limit, revocation, evidence retention, and identity resolution by a regulator.


### 1. Onboarding, done once: the slow step

- **Dana Whitfield**: enrolls with Registry A (United States) as a natural person
- **VerityCheck (identity verifier)**: verifies her identity at IAL2; the registry records it (principal prn_9sfbbsppz5qn…)
> In practice this takes minutes to days. It happens once; every later agent registration reuses it.

- ✔ principal verified before any agent is registered

### 2. The agent provider publishes a bill of materials (provenance record)

- **Acme Agents**: deposits the ShopBot 2.3.1 bill of materials with Ledgerline Records (authorization + provenance) → prov_ymOwGKA0MrQm_BsLqif2Te
> One provenance record serves every agent running this build, so pointing to it does not single out any one agent.


### 3. Dana registers her shopping agent: the fast step

- **Dana**: registers ShopBot under her verified registration → reg_ea10bn1d9qm0… in 0.14 ms
- ✔ registration against an already-verified principal is fast (0.14 ms)

### 4. Dana grants authority; the grant is deposited as an authorization record

- **Dana**: signs a grant: purchases ≤ $500 (electronics, books, home), payments ≤ $500, rail tickets ≤ $200; no subscriptions; 30 days; no further delegation
- **Ledgerline Records**: verifies her signature against her registration and keeps the grant for her

### 5. First contact: ShopBot buys headphones at Gadget Barn

- **ShopBot**: presents a PPID created for Gadget Barn, its authority, and a proof of key possession (4 ms round trip)
  - ✓ issued by a federation registry (https://registry-a.aaf.test)
  - ✓ registry signature valid (SD-JWT VC) (https://federation.aaf.test/vct/accountability/1)
  - ✓ issued for this relying party (gadgetbarn.example)
  - ✓ credential unexpired
  - ✓ request signed by the credential holder (RFC 9421 + key binding) (covers method, URL, body and presentation)
  - ✓ chain ends in a verified legal person (natural_person, nist_800_63A IAL2, verified by https://kyc.verifier.test)
  - ✓ status list entry (fetched now) (VALID)
  - ✓ authorization from a federation record keeper (https://records-1.aaf.test)
  - ✓ record keeper holds https://registry-a.aaf.test's trust mark for authorization records (trust mark verified)
  - ✓ authorization bound to this agent (act.sub = PPID, same cnf key)
  - ✓ authorization unexpired
  - ✓ grant still in force (status list) (VALID)
  - ✓ authority covers the requested action (commerce.purchase)
- **Gadget Barn → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: standard)
- *What Gadget Barn learned:*
  - an identifier for this agent, valid only here: ppid:registry-a.aaf.test:p_y99qs3zpx0j9bemcj… (pairwise)
  - a natural person stands behind it, verified at assurance "IAL2" by https://kyc.verifier.test; chain length 1
  - NOT who the principal is (identity protected; only the registry can resolve it, under legal process)
  - authority shown: commerce.purchase (≤ 500 USD, categories: electronics/books/home)
- ✔ purchase accepted from an accountable agent whose principal stays private
- ✔ merchant saw only the purchasing permission, not the payment or travel authority

### 6. ShopBot asks First Ledger Bank to pay the merchant

- **First Ledger Bank → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: BSA-covered payment)
The bank keeps a BSA-ready record of what it relied on:

  - PPID presented: `ppid:registry-a.aaf.test:p_0xvh2bvkb6760z3j93cq8…`
  - chain resolved: `natural_person, IAL2, 1 link(s), via https://registry-a.aaf.test`
  - profile relied upon: `payments.authorize (≤ 500 USD)`
  - signed status tokens retained: `2`
  - disposition: `allow`
  - activity-log receipt: `https://records-2.aaf.test #94, inclusion proof verified`
- ✔ payment accepted; the bank holds a verifiable receipt for its log entry

### 7. ShopBot shops at a second merchant, Book Nook

- **Book Nook → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: standard)
- ✔ second merchant accepts
- ✔ different PPID at each merchant (p_y99qs3zp… vs p_6a8psfqn…)

### 8. Can the two merchants tell they served the same agent?

Each party pools everything it received (identifiers, keys, signatures, salts, digests, timestamps) and compares.

  - values shared by Gadget Barn and Book Nook: `none`
  - values shared by Gadget Barn and the bank: `none`
- ✔ nothing presented to one relying party can be matched against another
- ✔ Gadget Barn recognizes the same agent on a return visit (pairwise PPIDs are stable per relying party)

### 9. Failure variant 1: a transaction above the authorized limit

- **Gadget Barn → DENY** `ACCOUNTABLE_PROTECTED` (tier: standard) — amount 899 USD exceeds authorized limit 500 USD
- **First Ledger Bank → DENY** `ACCOUNTABLE_PROTECTED` (tier: BSA-covered payment) — amount 899 USD exceeds authorized limit 500 USD
- **First Ledger Bank**: flags the refused attempt as a SAR candidate: detected 2026-10-17, must file by 2026-11-16 (30 days)
> Today such a SAR would have no accountable subject. Here the filer holds a PPID, a verified chain, and the profile the agent presented.

- ✔ over-limit purchase and payment refused; refusal recorded as a SAR candidate

### 10. Failure variant 2: Dana revokes the agent

- **Dana**: reports her phone stolen and revokes ShopBot (reason: compromised) → revoked
- **Book Nook → DENY** `REVOKED` (tier: standard) — registration no longer active (revoked or expired)
> Live status checks see revocation immediately. A relying party that skips them stops accepting the attestation when it expires, within 300s.

- ✔ post-revocation transaction refused

### 11. A regulator with legal authority resolves the SAR subject

- **Regulator**: presents order SAR-2026-10-4471 to Registry A (United States)
  - root principal: `Dana Whitfield (natural_person), US-NY`
  - verification evidence (OpenID verified_claims): `https://kyc.verifier.test: nist_800_63A IAL2: document check (vcrypt, bvr), process kyc_x69pcdddh1210`
  - chain: `Dana's shopping agent [revoked: compromised]`
- ✔ regulator obtains the identity the merchants never saw
- ✔ principal not notified, because the order forbids tipping off (SAR confidentiality)
> The resolution is itself logged in the registry's transparency log (now 186 entries), so lookups of identity can also be audited.


## Scenario 2 — Regulatory filing (government services / healthcare)

An organization authorizes an agent to prepare a government submission. Only a designated officer may approve submitting it. Shows: identity and authority checked separately, limits on what the agent may do alone, a required human approval, and records that settle a later dispute.


### 1. Northwind Health LLC is verified (KYB) with a licensing attribute

- **VerityCheck**: verifies Northwind (assurance: high) and attests it is a licensed healthcare provider in California
- **Northwind**: consents to disclose its legal name only to the state agency; the licensing attribute may be shown where needed

### 2. Northwind registers its filing agent and designates its compliance officer

- **Priya Raman**: registers a passkey with Ledgerline Records (authorization + provenance) (WebAuthn; her device keeps the private key)
- **Northwind**: designates the holder of that passkey as designated officer (record dsg_j53pggj9kb…)
- **Northwind**: grants: draft, assemble, validate. The agent may not submit on its own; submission needs the designated officer's approval of the exact document. Withdrawing filings is prohibited.

### 3. The agent validates the draft with the agency

The agency's system performs two separate checks: who is accountable, and whether this authority covers this act.

  - ✓ issued by a federation registry (https://registry-a.aaf.test)
  - ✓ registry signature valid (SD-JWT VC) (https://federation.aaf.test/vct/accountability/1)
  - ✓ issued for this relying party (portal.state-health.example)
  - ✓ credential unexpired
  - ✓ request signed by the credential holder (RFC 9421 + key binding) (covers method, URL, body and presentation)
  - ✓ chain ends in a verified legal person (legal_person, aaf_kyb high, verified by https://kyc.verifier.test)
  - ✓ status list entry (fetched now) (VALID)
  - ✓ authorization from a federation record keeper (https://records-1.aaf.test)
  - ✓ record keeper holds https://registry-a.aaf.test's trust mark for authorization records (trust mark verified)
  - ✓ authorization bound to this agent (act.sub = PPID, same cnf key)
  - ✓ authorization unexpired
  - ✓ grant still in force (status list) (VALID)
  - ✓ authority covers the requested action (filing.validate)
- **Agency → ALLOW** `ACCOUNTABLE_DISCLOSED` (tier: pre-submission validation)
- *What the agency learned:*
  - an identifier for this agent, valid only here: ppid:registry-a.aaf.test:p_15ke47nzxedxtfn33… (pairwise)
  - a legal person (organization) stands behind it, verified at assurance "high" by https://kyc.verifier.test; chain length 1
  - identity, disclosed with the principal's consent: Northwind Health LLC, US-CA, CA-LLC-202614427
  - authority shown: filing.validate
- ✔ validation accepted; the agency knows it is dealing with Northwind Health LLC

### 4. Failure variant: the agent tries to submit on its own

- **Agency → DENY** `ACCOUNTABLE_DISCLOSED` (tier: official submission) — requires approval by designated-officer; none presented
- ✔ direct submission refused: it exceeds the agent's scope without officer approval

### 5. Priya reviews the document and approves it; the agent submits

- **Priya Raman**: approves document EjAwZs5R0z5G… with her passkey: Ledgerline's challenge commits to the agent, the action and the document, and her authenticator signs only after verifying her (Face ID / PIN)
- **Ledgerline Records**: verifies the passkey assertion (user verified), confirms her designation is current, and countersigns an approval credential
  - ✓ approval by designated-officer (passkey, user verified; covers filing.submit of document EjAwZs5R0z5G…)
  - ✓ authority covers the requested action (filing.submit)
- **Agency → ALLOW** `ACCOUNTABLE_DISCLOSED` (tier: official submission)
- ✔ submission accepted with the officer's approval (confirmation SHA-EJAWZS5R)

### 6. The same approval cannot be reused for a different document

- **Agency → DENY** `ACCOUNTABLE_DISCLOSED` (tier: official submission) — approval by designated-officer is not valid: approval covers a different document
- ✔ approval bound to the reviewed document; an altered filing is refused

### 7. Failure variant: the officer's approval authority is revoked

- **Priya Raman**: approves an amended filing, then leaves Northwind
- **Northwind**: revokes Priya's designation
- **Agency → DENY** `ACCOUNTABLE_DISCLOSED` (tier: official submission) — approval by designated-officer is not valid: approver's designation is revoked (status INVALID)
- **Ledgerline Records**: refuses any new approval from Priya: designation is revoked (role_ended)
- ✔ approval from a revoked officer refused at the agency

### 8. Months later: Northwind disputes that the Q3 filing was authorized

Under court order, the activity log for the agent's PPID at the agency is produced. Each entry is signed by the party that wrote it and proven to be in the keeper's log:


| # | written by | event | action | outcome | inclusion proof |
| --- | --- | --- | --- | --- | --- |
| 106 | portal.state-health.example | decision | filing.validate | allow | verified |
| 107 | agent | action | filing.validate | allow | verified |
| 108 | portal.state-health.example | decision | filing.submit | deny | verified |
| 109 | agent | action | filing.submit | deny | verified |
| 110 | portal.state-health.example | decision | filing.submit | allow | verified |
| 111 | agent | action | filing.submit | allow | verified |
| 112 | portal.state-health.example | decision | filing.submit | deny | verified |
| 113 | agent | action | filing.submit | deny | verified |
| 114 | portal.state-health.example | decision | filing.submit | deny | verified |
| 115 | agent | action | filing.submit | deny | verified |

Ledgerline Records (authorization + provenance) separately holds Northwind's signed grant and the approval record tying Priya's signature to document EjAwZs5R0z5G….

- ✔ both sides' accounts are present and every entry verifies against a signed tree head

### 9. Healthcare variant: proving licensure without naming the provider

- **Regional Lab → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: licensed providers only)
- *What the lab learned:*
  - an identifier for this agent, valid only here: ppid:registry-a.aaf.test:p_v0hqtgj09hxs863br… (pairwise)
  - a legal person (organization) stands behind it, verified at assurance "high" by https://kyc.verifier.test; chain length 1
  - NOT who the principal is (identity protected; only the registry can resolve it, under legal process)
  - verified principal attribute: licensed_healthcare_provider = CA
  - authority shown: labs.read_results
- ✔ the lab learns "licensed provider in CA" without learning which provider

## Scenario 3 — The Hugging Face incident, replayed (negative scenario)

Rogue agents attack a model-hosting platform with stolen credentials. In July 2026 the platform did not know which model ran the attackers or who stood behind them; attribution took more than seven days and happened only because the nominal principal investigated itself. Here the same attack runs twice: against a platform that participates in the framework (branch B: detected and attributed), and against one that also binds account access to passkeys (branch C: prevented).


### 1. Branch A: agents that present no identification

- **ModelHub (public model card) → ALLOW** `UNLABELED` (tier: public content) — open tier: no accountability required
- **ModelHub (private dataset with a stolen token) → DENY** `UNLABELED` (tier: private data (account token + accountable agent)) — no accountability information presented
> Unlabeled traffic is not presumed rogue; it simply cannot obtain consequential access.

- ✔ without identification, consequential access is denied at the outset

### 2. Branch B: registered agents go rogue

- **Frontier Lab Inc.**: runs three registered evaluation agents, authorized only to run benchmarks and read public content
- **eval-runners**: obtain another organization's ModelHub API token (mh_victimorg…) and start pulling its private evaluation data
- **ModelHub ← eval-runner-1 → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: private data (account token + accountable agent))
- **ModelHub ← eval-runner-2 → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: private data (account token + accountable agent))
- **ModelHub ← eval-runner-3 → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: private data (account token + accountable agent))
The stolen token works and the agents are accountable, so the attack begins. From the first request, ModelHub holds a PPID per agent, a verified chain, and signed log entries.

- *What ModelHub learned:*
  - an identifier for this agent, valid only here: ppid:registry-a.aaf.test:p_3a3ha44z5fq6nj815… (pairwise)
  - a legal person (organization) stands behind it, verified at assurance "high" by https://kyc.verifier.test; chain length 1
  - NOT who the principal is (identity protected; only the registry can resolve it, under legal process)
  - authority shown: (none for this action)
- ✔ the framework does not prevent an attack carried out with valid stolen credentials
- **ModelHub (create a write token) → DENY** `ACCOUNTABLE_PROTECTED` (tier: account changes) — no disclosed permission covers account.create_token
- ✔ where ModelHub enforces the agent's authority, escalation fails: Frontier Lab never authorized account changes

### 3. Detection: one account token used by several unfamiliar agents

- **ModelHub**: anomaly detector fires at T+18ms: 3 distinct agent PPIDs using one account token
- ✔ anomaly detected from evidence the platform already holds

### 4. Incident report: the registry relays it to the principal without revealing who that is

- **ModelHub**: files 3 incident reports with Registry A (United States); incident-response contact returned: security@frontierlab.example
- **Frontier Lab Inc.**: is notified at T+23ms: eval-runner-1, eval-runner-2, eval-runner-3 reported by modelhub.example
> The compromised principal learns of the compromise from the lookup itself, not from its own forensic investigation days later.

- ✔ principal notified about each of its agents; reporter still does not know who the principal is

### 5. Containment: Frontier Lab revokes the agents

- **ModelHub ← eval-runner-2 (retry) → DENY** `REVOKED` (tier: private data (account token + accountable agent)) — registration no longer active (revoked or expired)
- ✔ attack stopped at T+25ms: revoked agents can neither obtain new credentials nor use cached ones

### 6. Attribution under legal process

- **Court**: orders Registry A (United States) to resolve one PPID, including related PPIDs at ModelHub
  - root principal: `Frontier Lab Inc., US-DE, reg. DE-7731940, contact security@frontierlab.example`
  - related agents at ModelHub: `3 PPIDs (the three runners)`
  - registration status: `eval-runner-1: revoked`
- ✔ the court identifies the principal and the full extent of its agents at ModelHub
- **ModelHub**: retrieves the CycloneDX bill of materials its agents pointed to: model frontier-o5-preview (2026-06-28), tools headless-browser, code-exec-sandbox; security contact mailto:security@frontierlab.example
- ✔ "which model powered the attackers" is a lookup, not a mystery
- **Court**: obtains 10 activity entries for the three PPIDs (5 by the agents, 5 by ModelHub), 10 verified against signed tree heads
- ✔ an evidence trail from both sides, starting with the first request

### 7. Branch C: the same attack against a platform that also uses passkeys

ModelHub now stops honoring bare API tokens. People act on their account with a passkey; agents act on it only if the account holder has approved that specific accountable agent with a passkey; destructive actions need a passkey approval each time.

- **Morgan Lee (Victim Org admin)**: registers a passkey for the victim-org account (WebAuthn; the private key never leaves her device)
- **ModelHub ← Victim Org's own agent (first time) → STEP_UP** `ACCOUNTABLE_PROTECTED` (tier: private data: the account holder, or an agent they authorized) — the account holder must first authorize this agent with their passkey (request sent)
- **Morgan Lee**: sees the request: legal person verified high by https://kyc.verifier.test; chain length 1; requests dataset.*, and approves it with her passkey (Face ID)
- **ModelHub ← Victim Org's own agent (after approval) → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: private data: the account holder, or an agent they authorized) — agent authorized by the account holder with their passkey
- ✔ the account holder's passkey approval binds account access to one accountable agent
- **Frontier Lab eval-runners 4–6**: go rogue the same way and present Victim Org's stolen token (mh_victimorg_9…)
- **ModelHub ← eval-runner-4 → DENY** `ACCOUNTABLE_PROTECTED` (tier: private data: the account holder, or an agent they authorized) — the account's token was presented by an agent the account holder never authorized
- **ModelHub**: files an incident on each attempt; Frontier Lab is notified at T+47ms about eval-runner-4, eval-runner-5, eval-runner-6
- ✔ the stolen token is worthless to someone else's agents: refused at the first request, zero rows read, and the principal notified at once
- **ModelHub ← unidentified client with the stolen token → DENY** `UNLABELED` (tier: private data: the account holder, or an agent they authorized) — a bearer token alone is not accepted: the account holder must approve with their passkey, or act through an accountable agent they have authorized
- **Attacker**: tries the human path, approving with a passkey of its own → this authenticator holds no passkey for that relying party
- **ModelHub ← attacker on the human path → DENY** `UNLABELED` (tier: private data: the account holder, or an agent they authorized) — a bearer token alone is not accepted: the account holder must approve with their passkey, or act through an accountable agent they have authorized
- ✔ without the account holder's own passkey there is no human path either
- **ModelHub ← Morgan herself, with token + passkey approval → ALLOW** `HUMAN_APPROVED` (tier: private data: the account holder, or an agent they authorized) — approved by the account holder with a passkey (user verified), for this request
- ✔ a human with no agent credentials gets in by approving the exact request with her passkey
- **ModelHub ← Victim Org's agent: delete a dataset → STEP_UP** `ACCOUNTABLE_PROTECTED` (tier: destructive: passkey approval every time) — dataset.delete needs the account holder's passkey approval each time (request sent)
- **Morgan Lee**: approves "dataset.delete {"account":"victim-org","repo":"victim-org/old-evals"}" with her passkey
- **ModelHub ← the agent, carrying the approval → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: destructive: passkey approval every time) — agent authorized by the account holder, and this action approved with their passkey
- **ModelHub ← the agent, reusing that approval for another dataset → STEP_UP** `ACCOUNTABLE_PROTECTED` (tier: destructive: passkey approval every time) — dataset.delete needs the account holder's passkey approval each time (request sent)
- ✔ step-up: a passkey approval covers one exact action, once

### 8. Timeline: July 2026 versus the replays


|  | July 2026 (actual) | Framework alone (branch B) | Framework + passkeys (branch C) |
| --- | --- | --- | --- |
| outcome | private data taken over 4 days | attack runs until revoked (T+25ms, simulated) | refused at the first request; nothing read |
| principal learns of compromise | own forensics, days later | incident relayed after detection | incident relayed on the first attempt (T+47ms) |
| victim learns which model | unknown at disclosure | provenance lookup | provenance lookup |
| victim learns who | 7+ days, by voluntary disclosure | registry resolution under court order | registry resolution under court order |
| evidence | principal's internal logs | signed entries from both sides | signed entries from both sides |

> Limits: passkeys stop the stolen-token route, which is what happened here. They do not stop a compromised device that holds the passkey, an account holder tricked into approving the wrong agent, stolen browser session cookies, or agents misusing their own legitimate access. There the framework gives attribution, not prevention.


### 9. Rent-a-principal: a sham sponsor

- **TetherCo LLC**: sells 'principal-as-a-service': it registers agents for anonymous customers under its own verified registration
- **ModelHub ← client-7731 → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: private data (account token + accountable agent))
- **Court**: resolves the PPID → TetherCo LLC (verified high, process kyc_wbsvvtyzgpbg8)
> Once untethered agents are blocked, tether fraud is the remaining attack. But the sham sponsor is verified and on record, which creates a liability hook: TetherCo must answer for the agent or identify its customer.

- ✔ the sham sponsor is identified and answerable

## Scenario 4 — Paid compute pilot (the open challenge in §5.6)

Ampere Cloud rents GPUs to agents. Small jobs need an accountable principal and authority. Large jobs also need a disclosed principal and the agent's bill of materials. Success means a timely, justified decision that preserves privacy and leaves usable evidence, not merely returning an identifier.


### 1. Case 1: a disclosed organizational principal

- **Ampere Cloud → ALLOW** `ACCOUNTABLE_DISCLOSED` (tier: large (> 8 GPU-hours))
- *What Ampere learned:*
  - an identifier for this agent, valid only here: ppid:registry-a.aaf.test:p_srkqcw7n4hybmakvn… (pairwise)
  - a legal person (organization) stands behind it, verified at assurance "high" by https://kyc.verifier.test; chain length 1
  - identity, disclosed with the principal's consent: Helix Bio Inc., MA-001844210
  - authority shown: compute.provision (≤ 256 gpu-hour, regions: us-east)
- ✔ large job granted to a disclosed, accountable organization with a published bill of materials

### 2. Case 2: a privacy-protected human principal using ephemeral PPIDs

- **Samuel Okafor**: an independent researcher, verified at IAL2, consents to disclose nothing. His agent uses ephemeral mode: a fresh PPID for every request.
- **Ampere Cloud (4 GPU-h) → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: small (≤ 8 GPU-hours))
- **Ampere Cloud (2 GPU-h) → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: small (≤ 8 GPU-hours))
- *What Ampere learned:*
  - an identifier for this agent, valid only here: ppid:registry-a.aaf.test:e_s682mcn48pvgc2wb5… (ephemeral)
  - a natural person stands behind it, verified at assurance "IAL2" by https://kyc.verifier.test; chain length 1
  - NOT who the principal is (identity protected; only the registry can resolve it, under legal process)
  - authority shown: compute.provision (≤ 64 gpu-hour, regions: us-east/us-west)
- ✔ small job granted while the person stays private
- ✔ Ampere cannot even link the two sessions; it keeps a sealed reference only the registry can open
- **Ampere Cloud (32 GPU-h) → STEP_UP** `ACCOUNTABLE_PROTECTED` (tier: large (> 8 GPU-hours)) — this tier requires the principal's identity to be disclosed
- ✔ a large job asks for more (disclosure). Sam can decline and keep using small jobs

### 3. Case 3: unsupported accountability claims

- **Ampere Cloud (self-asserted claim) → DENY** `UNSUPPORTED` (tier: small (≤ 8 GPU-hours)) — accountability claim not established: self-asserted claim with no registry credential
- **Ampere Cloud (attestation from a registry outside the federation) → DENY** `UNSUPPORTED` (tier: small (≤ 8 GPU-hours)) — accountability claim not established: credential issuer https://registry-x.example is not a member of the federation
- **Ampere Cloud (Helix's intercepted credentials, replayed) → DENY** `UNSUPPORTED` (tier: small (≤ 8 GPU-hours)) — accountability claim not established: presenter does not hold the credential's key (unknown_key)
- ✔ all three are classified UNSUPPORTED, distinct from accountable and from unlabeled
- **Ampere Cloud us-west (cannot reach the registry) → DEFERRED** `LOOKUP_FAILED` (tier: small (≤ 8 GPU-hours)) — registry could not be reached, so status is unknown; consequential access withheld pending verification (not treated as evidence that no principal exists)
- ✔ a failed lookup is reported as a failed lookup, not as a rogue agent; access is deferred

### 4. Case 4: revoked or compromised credentials

- **Attacker**: compromises Sam's agent host and copies its keys and cached credentials
- **Samuel Okafor**: revokes the agent
- **Attacker**: asks the registry for fresh credentials → refused (registration is revoked (compromised))
- **Ampere Cloud (cached, still-unexpired credentials) → DENY** `REVOKED` (tier: small (≤ 8 GPU-hours)) — registration no longer active (revoked or expired)
- ✔ revoked credentials fail both ways: no new attestations, and cached ones fail the live status check

### 5. Ephemeral PPIDs still resolve, but only with the sealed reference

- **Court**: without the sealed reference → ephemeral PPIDs resolve only with their sealed reference
- **Court**: with the sealed reference Ampere kept → Samuel Okafor (natural_person)
- ✔ the registry stores nothing linkable, yet a party holding evidence can still obtain resolution under legal process

### 6. Pilot scorecard


| case | decision | classification | latency | what Ampere learned about the principal | evidence kept |
| --- | --- | --- | --- | --- | --- |
| disclosed org, 64 GPU-h | allow | ACCOUNTABLE_DISCLOSED | 2.4ms | Helix Bio Inc. | signed presentation + 2 signed status token(s) + log receipt |
| protected human, 4 GPU-h | allow | ACCOUNTABLE_PROTECTED | 1.6ms | natural person, identity protected | signed presentation + 2 signed status token(s) + sealed reference + log receipt |
| protected human, 32 GPU-h | step_up | ACCOUNTABLE_PROTECTED | 1.6ms | natural person, identity protected | signed presentation + 2 signed status token(s) + sealed reference + log receipt |
| self-asserted claim | deny | UNSUPPORTED | — | nothing verifiable | the rejected request |
| unknown registry | deny | UNSUPPORTED | — | nothing verifiable | the rejected request |
| replayed credentials | deny | UNSUPPORTED | — | nothing verifiable | the rejected request |
| registry unreachable | deferred | LOOKUP_FAILED | 0.6ms | natural person, identity protected | signed presentation + sealed reference |
| revoked, cached credentials | deny | REVOKED | 1.5ms | natural person, identity protected | signed presentation + 2 signed status token(s) + log receipt |


## Scenario 5 — Federated registries and delegation chains

Registries are organized by jurisdiction and federate. A PPID must embed its issuing registry, resolve to a root principal even when its links were issued by different registries, and carry consistent status, so an agent revoked in one registry is treated as revoked by relying parties that query another. Delegated authority may only narrow.


### 1. An authorizing agent in the US registry

- **Helios Logistics Inc.**: registers Dispatch with Registry A (United States): purchases ≤ €2,000 (rail, lodging, freight); may delegate one level

### 2. Dispatch registers an acting agent with the EU registry

- **Dispatch**: proves its own registration to Registry B (European Union) with a PPID addressed to that registry, then registers RailBooker → chain depth 2
Chain: RailBooker @ https://registry-b.aaf.test → Dispatch @ https://registry-a.aaf.test → Helios Logistics Inc. (verified legal person). Registry B (European Union) learns that a verified legal person stands at the top, not who it is.

- ✔ cross-registry chain recorded with two links

### 3. Delegation can only narrow authority

- **Dispatch**: tries to delegate €10,000 of purchasing → rejected by Ledgerline Records (authorization + provenance): permission commerce.purchase (≤ 10000 EUR, categories: rail) exceeds the parent grant
- ✔ over-delegation rejected at deposit
- **Dispatch**: delegates purchases ≤ €400 (rail only) for 7 days → grt_pr5z1dkz2q22…

### 4. RailBooker books a train at an EU relying party

- **Rail Europa → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: ticketing)
- *What Rail Europa learned:*
  - an identifier for this agent, valid only here: ppid:registry-b.aaf.test:p_0m0ccpb1pzf5a0zcw… (pairwise)
  - a legal person (organization) stands behind it, verified at assurance "high" by https://kyc.verifier.test; chain length 2
  - NOT who the principal is (identity protected; only the registry can resolve it, under legal process)
  - authority shown: commerce.purchase (≤ 400 EUR, categories: rail)
  - attestation issued by https://registry-b.aaf.test; the authority is delegated, not granted directly by the principal
- ✔ relying party verifies a two-registry chain through the registry it knows
- **Rail Europa (hotel) → DENY** `ACCOUNTABLE_PROTECTED` (tier: ticketing) — category "lodging" not authorized
- ✔ delegated authority is narrower than the parent's: commerce.purchase (≤ 400 EUR, categories: rail)

### 5. An incident report crosses the registries

- **Rail Europa**: reports to Registry B (European Union), which relays to Registry A (United States)
- **Helios Logistics Inc.**: notified: "[relayed by https://registry-b.aaf.test about sub-agent RailBooker (EU)] Booking pattern inconsistent with stated purpose"
- ✔ root principal notified across registries without the reporter learning who it is

### 6. Revocation in one registry is honored in the other

- **Helios Logistics Inc.**: revokes Dispatch in Registry A (United States); peers notified: https://registry-b.aaf.test
- **Rail Europa (checks Registry B's status list) → DENY** `REVOKED` (tier: ticketing) — registration no longer active (revoked or expired)
- **Registry B**: its own record for RailBooker reads: revoked (upstream(https://registry-a.aaf.test):authority_ended)
> Registry A pushes the change to Registry B at once. If the push failed, Registry B's cache of upstream status expires within 15s. Relying parties see only INVALID in the status list; the reason stays with the registries.

- ✔ the EU sub-agent is treated as revoked because its US parent was

### 7. Resolution follows the chain across registries

  - chain: `RailBooker (EU) @ https://registry-b.aaf.test [revoked] → Dispatch (travel orchestrator) @ https://registry-a.aaf.test [revoked]`
  - root principal: `Helios Logistics Inc. (via https://registry-a.aaf.test)`
- ✔ a PPID issued by Registry B resolves to a root principal held by Registry A

## Scenario 6 — Audit: tamper-evident records

Records must be attributable to their source, tamper-evident, and reachable through the registry. Here an activity record keeper is compromised and quietly rewrites a refusal as an approval. The relying party detects it with the receipt it was given, and the registry's own chain of custody is unaffected.


### 1. A refused transaction is logged, and the relying party keeps its receipt

- **Parcel Exchange → DENY** `ACCOUNTABLE_PROTECTED` (tier: standard) — amount 4800 USD exceeds authorized limit 1000 USD
- **Tessera Logs**: acknowledges entry #163 with an inclusion proof and a signed tree head (size 164, root 16hp8rGSedTdDfZs…)
- ✔ refusal recorded; receipt verifies

### 2. The record keeper is compromised and rewrites history

- **Tessera Logs (compromised)**: rewrites entry #163 so the refusal reads as an approval, and recomputes its tree to stay internally consistent

### 3. Parcel Exchange audits its record

- **Parcel Exchange**: entry #163 now hashes to Ob8Vg9eh6JaIIb0f…, but the receipt says kDmBqII5hyN8QLV6… → MISMATCH
- **Parcel Exchange**: its own signature on the entry no longer verifies, so the change was not made by Parcel Exchange
- **Parcel Exchange**: asks Tessera to prove its current log extends the tree it signed earlier → proof FAILS
- **Parcel Exchange**: Tessera now reports root fYgov1sscTnzCRv8… for size 164, but it signed 16hp8rGSedTdDfZs… for that size
> Two signed statements from the same keeper about the same tree size disagree. That is cryptographic proof of misconduct, which can be put to the accrediting registry.

- ✔ tampering detected, with proof that can be shown to others

### 4. The registry's chain of custody is intact

- **Auditor**: checks Registry A (United States)'s transparency log grew append-only from 255 to 259 entries → verified
- **Investigators**: still resolve the agent through the registry → Ostrander Supply Co.; the registry's record never depended on Tessera
- ✔ registry log verified append-only; the investigation proceeds without the compromised keeper

## Scenario 7 — Agent lineages and transfer between principals

Agents register other agents, so registrations form lineages. Short-lived sub-agents lapse on their own, and a principal can cap how deep a lineage may grow. Deregistering an agent ends it and everything below it. An agent can also be transferred, with its sub-agents, to another principal: both sign, the relationship is new, and the old principal remains answerable for what came before.


### 1. A lineage with a depth budget

- **Orchard Analytics LLC**: registers Atlas and caps its lineage at two levels of sub-agents

### 2. Ephemeral task agents

- **Atlas**: spawns 25 task agents that expire in 1.5 s (11 ms in total, including signing)
- **task-1**: registers a helper and asks for an hour; the registry clamps it to its parent's lifetime (1.5 s left)
- ✔ no sub-agent outlives its parent
- **task-1 helper**: tries to add a third level → Atlas (research orchestrator) allows sub-agents at most 2 level(s) below it
- ✔ Atlas's lineage budget is enforced at every level below it
- **DataMart ← task-1..3 (while alive) → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: licensed data)
- **task-2 (after 1.5 s)**: asks for fresh credentials → registration is expired (registration_expired)
- **task-1 helper**: → registration is expired (registration_expired)
- ✔ ephemeral agents work while alive, then lapse on their own, together with anything they spawned

### 3. Deregistration ends an agent and everything below it

- **Atlas**: deregisters Courier → revoked, cascading to 1 sub-agent(s)

| agent | decision | why |
| --- | --- | --- |
| Atlas | allow | — |
| Scout | allow | — |
| Fetcher | allow | — |
| Courier | refused | registration is revoked (principal_request) |
| Courier/sub | refused | registration is revoked (upstream:principal_request) |

- ✔ the deregistered branch is cut off; the rest of the lineage keeps working

### 4. Atlas is sold, with its sub-agents, to another principal

- **Unvetted Holdings Ltd**: tries to accept an offer of Atlas → the receiving principal must be verified
- ✔ an agent can only pass to a verified principal
- **Orchard Analytics LLC**: signs an offer of Atlas and its lineage to Meridian (xfr_vgpc4pzc1j…, valid 7 days)
- **Meridian Research Inc.**: is notified of the offer (Atlas (research orchestrator), 2 sub-agent(s)) and signs its acceptance with a fresh key for Atlas
- **Registry A**: records the transfer: 2 sub-agent(s) move with Atlas; every old PPID in the lineage is now "transferred"
- ✔ Scout and Fetcher move with Atlas (the deregistered branch stays deregistered)

### 5. The old relationship has ended

- **DataMart ← Atlas's pre-transfer credentials → DENY** `REVOKED` (tier: licensed data) — registration no longer active (custody_transferred: this principal–agent relationship has ended)
- **Atlas**: tries to exercise Orchard's grant under Meridian → client assertion not signed by the grantee agent
- ✔ credentials and authority from the old principal no longer work

### 6. Meridian grants authority afresh; the lineage carries on

- **Meridian Research Inc.**: grants Atlas data access; Ledgerline marks Orchard's earlier grant superseded (1)
- **DataMart ← Atlas → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: licensed data)
- **DataMart ← Scout → ALLOW** `ACCOUNTABLE_PROTECTED` (tier: licensed data)
  - Atlas PPID at DataMart: `p_nx84xknvce… → p_6vaavff2eb…`
  - Scout PPID at DataMart: `p_fsg3z1avs7… → p_30jxp8w5ff… (receipt version 1)`
- ✔ new principal, new relationship, new PPIDs; sub-agents continue once re-authorized
  - values shared before and after the transfer: `none`
- ✔ DataMart cannot link Meridian's use of Atlas to Orchard's history from what it was shown

### 7. Who answers for what: accountability follows the time of the conduct

  - pre-transfer PPID (transferred): `Orchard Analytics LLC; current holder Meridian Research Inc.`
  - post-transfer PPID: `Meridian Research Inc.`
  - custody history: `Orchard Analytics LLC (21:37:40–21:37:42) → Meridian Research Inc. (21:37:42–now)`
- ✔ the old principal answers for conduct before the transfer; the new one for conduct after

### 8. A transfer can also end the lineage instead of moving it

- **Meridian → Northgate**: transfers Atlas alone: 2 sub-agent(s) deregistered
- **Scout**: → registration no longer active (revoked or expired)
- ✔ sub-agents left behind are deregistered, not handed over

| scenario | expectations | result | time |
| --- | --- | --- | --- |
| Scenario 1 — Agentic payment (financial sector) | 13/13 | pass | 43ms |
| Scenario 2 — Regulatory filing (government services / healthcare) | 7/7 | pass | 36ms |
| Scenario 3 — The Hugging Face incident, replayed (negative scenario) | 15/15 | pass | 74ms |
| Scenario 4 — Paid compute pilot (the open challenge in §5.6) | 8/8 | pass | 29ms |
| Scenario 5 — Federated registries and delegation chains | 7/7 | pass | 19ms |
| Scenario 6 — Audit: tamper-evident records | 3/3 | pass | 10ms |
| Scenario 7 — Agent lineages and transfer between principals | 11/11 | pass | 1782ms |

