# Accountable Agents Framework: Reference Profile 0.3

**Status:** draft for discussion · **Date:** 21 November 2026
**Companion to:** *The Accountable Agents Framework (AAF): A Blueprint for AI Agent IDs* (draft of 21 November 2026; "the paper")
**Reference implementation:** this repository (`src/`), exercised by the simulator (`npm run sim`)

**Changes since 0.2:** the profile is aligned with the paper's Appendix A requirements (§3 maps each one).
- **Only the ID is required.** Every other claim in the accountability credential is selectively disclosable (PR-1, PR-5, PR-6), padded with decoy digests; relying parties ask for what their policy needs (PR-10) and may set acceptance criteria and choose which registries to accept.
- **One principal record per verified identity** (PV-3).
- **Agents prove possession of their key** at registration, key replacement and transfer (AG-2, AG-5).
- **Revocation under a legal order**, and by the registry under its published practices (RV-1).
- **Published practices** in each registry's metadata (DR-1).
- **IDs** are written `aaf:<directory>:…`; "PPID" now means only the reusable, pairwise kind, as in the paper.

**Changes from 0.1 to 0.2:** agent lineages with expiring sub-agents and depth budgets; transfer of agents between principals; passkeys (WebAuthn) for human approvals, for a service's human path, and for binding account access to specific accountable agents; and the profile now uses existing specifications wherever one fits. These are OpenID Federation, OpenID Connect for Identity Assurance, SD-JWT VC with Key Binding, the IETF Token Status List, RFC 9421 HTTP Message Signatures, RFC 9396 Rich Authorization Requests, RFC 8693 Token Exchange, CycloneDX 1.6 and RFC 8785. Its own designs are confined to what no existing specification covers (§15).

---

## 0. About this document

The paper is protocol-agnostic: its Appendix A lists the properties a system must have, and its conclusion invites "a reference implementation of a realistic workflow". This document is one such implementation, written as a specification. It turns each requirement into concrete formats, protocols and checks, and comes with running services and a transaction simulator that show the requirements are met.

Where the paper leaves a choice open, this profile makes one and marks it **Profile choice**. Section 3 maps the paper's requirements to this profile. Section 14 states what an implementation of this profile must do. Section 15 sets out which existing specifications are reused, and which of the paper's implementation options (its Appendix C) were chosen.

The profile also does things the paper leaves out of scope or mentions only as complementary infrastructure: accredited record keepers, transfer of agents between principals, incident relay, bills of materials, activity logs, and passkey-bound account access. Section 3.2 lists them. They are extensions, not requirements of the paper.

The key words MUST, MUST NOT, SHOULD, SHOULD NOT and MAY are used as in RFC 2119 and RFC 8174.

### 0.1 Standards at a glance

| Concern | Specification used |
|---|---|
| Federation, trust anchor, accreditation | OpenID Federation 1.0 (entity statements, subordinate statements, trust marks) |
| KYC/KYB results, principal attributes | OpenID Connect for Identity Assurance 1.0 (`verified_claims`) |
| Credentials an agent presents | IETF SD-JWT VC (`typ: dc+sd-jwt`, `vct`, `cnf`) with SD-JWT Key Binding (`kb+jwt`) |
| Revocation status | IETF OAuth Token Status List (`status.status_list`, `statuslist+jwt`) |
| Signed HTTP requests (all parties) | RFC 9421 HTTP Message Signatures (Ed25519), RFC 9530 Content-Digest; agent requests follow the Web Bot Auth pattern |
| Authority | RFC 9396 Rich Authorization Requests (`authorization_details`) |
| Exchanging a grant for an audience-specific credential; delegation chains | RFC 8693 OAuth 2.0 Token Exchange (`act`); client authentication by RFC 7523 JWT assertion |
| Human approvals; services' human path; agent-bound account access | W3C Web Authentication (passkeys), Level 3 |
| Bills of materials | CycloneDX 1.6 |
| Signatures, keys, encryption | JWS/JWK/JWE (RFC 7515–7518), EdDSA/X25519 (RFC 8037), JWK thumbprints (RFC 7638) |
| Canonical JSON | RFC 8785 (JCS) |
| Tamper-evident logs | RFC 9162 Merkle trees (CT 2.0) |

### 0.2 Contents

1. Terminology
2. Architecture
3. Requirements traceability
4. Formats and conventions
5. Identifiers
6. Trust framework (OpenID Federation)
7. Registry
8. Record keepers
9. Presentation protocol
10. Relying-party verification and policy
11. Authority (RAR) and delegation
12. Privacy considerations
13. Security considerations
14. Conformance
15. Reuse of existing specifications
16. Limitations and open questions
- Appendix A: HTTP API reference
- Appendix B: Example artifacts

---

## 1. Terminology

### 1.1 The paper's terms and this profile's

The code and its APIs keep their earlier names. This table maps them to the paper's.

| The paper says | This profile says | Notes |
|---|---|---|
| **Directory** | **Registry**, together with the **identity verifiers** it relies on and the **record keepers** it accredits | The paper lets a directory be "several entities acting together" and suggests dividing verification, issuance and record-keeping (its §3.1). Here the registry holds identities and issues IDs; record keepers hold authorizations, bills of materials and activity. |
| **Counterparty** | **Relying party (RP)** | |
| **Presentation**, **claims** | The `AAF-Presentation` header: an **accountability credential** (the ID and directory-attested claims), an optional **authorization credential**, an optional **approval** | Authorizations are attested by an accredited record keeper, which is part of the directory in the paper's sense. |
| **ID** | The `sub` of the accountability credential, written `aaf:<directory host>:…` | API fields that carry it are still named `ppid`. |
| **PPID** (reusable, one per agent and counterparty) | An ID in **pairwise** mode (`aaf:…:p_…`) | |
| Unlinkable, single-use ID | An ID in **ephemeral** mode (`aaf:…:e_…`) | Earlier versions called this an "ephemeral PPID". |
| **Identity escrow**, **attribution** | **Resolution** under a legal order (§7.11) | |
| **Delegating agent**, sub-agent | **Parent agent**, sub-agent | |
| **Principal record**, **agent record** | Principal record, **registration** | |
| **Designated authority** | **Resolution authority** | |
| Group of directories under one trust list | **Federation** under a **trust anchor** | The paper's Appendix C §9, option 1. |

### 1.2 Terms

| Term | Meaning in this profile |
|---|---|
| **Principal** | A natural or legal person responsible for an agent. It registers agents, grants them authority, and can revoke or transfer them. |
| **Root principal** | The verified principal at the top of an agent's chain. Every chain MUST end in one. **Profile choice:** these registries verify natural and legal persons (the paper's PV-2); the paper also allows other verified identities, such as control of a domain. |
| **Parent agent** (the paper's *delegating agent*) | An agent acting as principal of another agent. It registers sub-agents and delegates authority to them. |
| **Acting agent** | The agent that deals with a relying party. |
| **Lineage** | An agent and every sub-agent below it. A **depth budget** caps how deep a lineage may grow. An **ephemeral** sub-agent has an expiry and lapses on its own. |
| **Custody / transfer** | Which principal an agent answers to. A transfer moves an agent (and, by default, its lineage) to another principal. It is a new principal–agent relationship. |
| **Chain version** | A counter that changes whenever the registration or any local ancestor changes hands. IDs, bindings and grants are scoped to it. |
| **Agent provider** | The party that builds or operates the agent software. |
| **Relying party (RP)** | Whoever the agent deals with (the paper's *counterparty*). |
| **Trust anchor** | The federation's governance body, in OpenID Federation terms. It publishes its Entity Configuration and signs a Subordinate Statement about each member. |
| **Registry** | Verifies principals (through identity verifiers), registers agents into chains, issues IDs in accountability credentials, publishes status and its practices, points to record keepers, accredits record keepers (trust marks), and resolves IDs under consent or legal process. |
| **Record keeper (RK)** | Holds authorization, provenance and activity records. The authorization role also runs the token-exchange endpoint. |
| **ID** | The identifier an agent presents. It reveals nothing by itself, names one principal–agent relationship, and is resolvable only by its registry. It is either **pairwise** (a **PPID**: the same at every visit to one relying party, and at most one per agent and relying party) or **ephemeral** (single-use: a new one for each presentation). |
| **Accountability credential** | Registry-issued SD-JWT VC that carries an ID and states that it resolves to a principal the registry verified. Every further claim in it is optional (§7.6). |
| **Grant** | Principal-signed (or parent-agent-signed) statement of authority, expressed as `authorization_details`, deposited as an authorization record (§8.2). |
| **Authorization credential** | RK-issued SD-JWT VC obtained by token exchange: audience-specific, selectively disclosable, bound to the same key as the accountability credential (§8.3). |
| **Designation / approval** | A principal designates a human to a role. That person's approval of a specific act, countersigned by the RK, is an approval credential (§8.4). |
| **Sealed reference** | Encrypted registration reference attached to a single-use ID that only the issuing registry can open (§5.3). |
| **Passkey** | A WebAuthn credential: a key pair whose private key stays on the person's device and signs only after a local check (user presence; user verification by biometric or PIN). |
| **Passkey approval** | A WebAuthn assertion over a challenge that commits to exactly what is being approved (§10.5). |
| **Agent-bound account access** | A service's rule that an agent may act on an account only if the account holder approved that specific accountable agent (its PPID at the service) with a passkey (§10.5). |
| **Published practices** | What a registry states about how it verifies, authenticates, issues, revokes, retains and discloses (§7.14; the paper's DR-1). |
| **Resolution** | Disclosure of the root principal behind an ID to a resolution authority, under a legal order (§7.11). The paper calls this attribution, through identity escrow. |

---

## 2. Architecture

### 2.1 Layers

```
 ACCOUNTABILITY   Principal ──(grant: RAR)──▶ Parent agent ──(delegated grant)──▶ …
      │              │ enroll + KYC/KYB (OIDC Identity Assurance; slow, once)
      ▼              ▼
 IDENTITY         Trust anchor (OpenID Federation) ── subordinate statements ──┐
                    ▼                                                           ▼
                  Registry A ◀── federation: peer status, push, forwarding ──▶ Registry B
                  · verified principals · lineages → root · status lists · record pointers
                  · IDs in accountability credentials (SD-JWT VC) · trust marks · transparency log
      │                            ▲  "still valid? who, exactly?"
      ▼                            │  (status list; resolution under legal process)
 TRANSACTION      Acting agent ── RFC 9421-signed request + SD-JWT VCs with key binding ──▶ Relying party
                    · accountability credential (registry)
                    · authorization credential (record keeper, via RFC 8693 token exchange)
                    · optional approval credential, provenance pointer
      │                                                         │
      ▼                                                         ▼
 RECORDS          Record keepers (trust marks from registries): authorization · provenance · activity
                  every record signed by its source, appended to a Merkle log, receipted
```

### 2.2 Life cycle

| Phase | Step | Who | Speed |
|---|---|---|---|
| Setup | Principal enrolls; an identity verifier submits `verified_claims` | principal, verifier, registry | slow (days), once |
| | Provider publishes a CycloneDX bill of materials | provider → provenance RK | once per build |
| | Principal registers an agent (optionally with a depth budget or expiry); receives a receipt | principal → registry | under 1 ms in the reference implementation |
| | Agents register sub-agents (persistent or ephemeral) | parent agent → registry | under 1 ms each |
| | Principal grants authority (RAR); grant deposited | principal → authorization RK | fast |
| Transaction | Agent obtains an accountability credential for the RP | agent → registry | fast, cached per RP |
| | Agent exchanges grant + credential for an authorization credential (RFC 8693) | agent → authorization RK | fast, cached per RP |
| | Agent sends a signed request with key-bound credentials | agent → RP | per request |
| | RP verifies with published keys, status lists and trust marks; applies policy; logs | RP (no call about any one ID) | ~2–5 ms locally |
| | Agent and RP each write their account to the activity log | both → activity RK | per request |
| After | Incident report relayed to the principal | RP → registry → principal | immediate |
| | Revocation or expiry, cascading down the lineage and across registries | registry → status lists, peers | immediate (push), bounded (pull) |
| | Transfer to another principal (both sign) | principals → registry | immediate |
| | Resolution under legal order; audit of records | authority → registry, RK | as fast as legal process |

### 2.3 Who knows what

| Party | Knows | Does not know |
|---|---|---|
| Trust anchor | the federation's members and their keys | anything about principals or agents |
| Registry | principals' verified identities; every registration, lineage, custody history and status; the PPIDs it issued and their audiences; which RP each credential is requested for, and when (issuance is on demand, §16) | grants, activity, provenance contents; which credential an RP checks (status lists are fetched whole); what the agent discloses or does at the RP |
| Authorization RK | grants and their grantors; which ID (per audience) each grant was exchanged for | principal's verified identity beyond its registry handle; what happened at the RP |
| Provenance RK | bills of materials per build | which agents use a build |
| Activity RK | signed entries per ID | who the principal is |
| Relying party | an ID valid only at that RP, and that its registry verified a principal who answers for it. Beyond that, only what it asks for and the agent discloses: the kind of principal, its assurance level, who verified it, the chain length; attributes and identity *only with the principal's consent*; only the permissions relevant to the request (and, with those, the delegation depth) | identity (unless disclosed); anything it did not ask for; anything linking the agent to its activity at another RP, or to an earlier owner's activity |
| Resolution authority | the principal accountable at the time, the chain, custody history, related IDs at the requesting RP, all within the order's scope | nothing beyond the order's scope |

---

## 3. Requirements traceability

### 3.1 The paper's Appendix A

"Test" names a file in `test/` or a simulator scenario that exercises the requirement.

| Requirement | Status | Mechanism in this profile | Test |
|---|---|---|---|
| **PV-1** Identity proofing | met | An identity verifier submits OpenID Identity Assurance `verified_claims`; agents can be registered only while the verification is valid; a lapse suspends them (§6.3, §7.2, §7.7) | `services`; all scenarios |
| **PV-2** Human and legal entity proofing (optional) | met | The only kinds these registries accept. Each ID can show the trust framework and assurance level (§7.6) | scenarios 1, 4 |
| **PV-3** Sybil resistance | met | One principal record per verified identity; a second is refused at verification (§7.2) | `paper-requirements`, `pilot` |
| **PV-4** Sybil resistance across directories (optional) | not implemented | | |
| **PV-5** Principal authentication | met | Every principal request is signed with the key enrolled in its record (§4.3) | `services` |
| **AG-1** Agent authentication | met | To the registry: requests signed with the agent's long-term key. To relying parties: a per-RP or per-presentation key bound into the ID's credential (§7.6, §9.2) | `rp-cnf-key-binding` |
| **AG-2** Registration | met | Only a verified principal or a parent agent can register an agent, and the agent proves it holds the key bound to its record (§7.4) | `paper-requirements` |
| **AG-3** Delegation (optional) | met | Parent agents register and revoke sub-agents; authority only narrows; revocation cascades (§7.5, §11.3) | scenarios 5, 7 |
| **AG-4** Multiple principals (optional) | not implemented | | |
| **AG-5** Re-registration (optional) | met | The principal, or an agent above, replaces an agent's key; the new key proves possession; the change is logged and earlier IDs still resolve (§7.5) | `paper-requirements`; scenario 7 |
| **PR-1** ID | met | Every presentation carries an ID naming its registry; no other claim is required (§5.3, §7.6) | `paper-requirements` |
| **PR-2** Holder binding | met | The request is signed with the credential's `cnf` key, with a Key Binding JWT (§9.2, §10.1) | `rp-cnf-key-binding`, `rp-key-binding-controls` |
| **PR-3** Validity | met | Expiry in each credential; published status lists (§7.7, §8.7) | `status-list`; scenarios 1, 4 |
| **PR-4** Claims and their issuers | met | Each credential names its issuer: the registry for the ID and claims about the principal, an accredited record keeper for authority and approvals. A claim with no issuer behind it is classified `UNSUPPORTED` (§10.2) | scenario 4 |
| **PR-5** Selective disclosure | met | SD-JWT; the principal's disclosure policy decides what may be shown, and the agent what is shown; decoy digests hide how much is withheld (§4.2, §7.3, §7.6) | `paper-requirements` |
| **PR-6** Anonymity toward counterparties | met | A presentation of the ID alone tells the RP only that the registry verified a principal (§2.3) | `paper-requirements` |
| **PR-7** Unlinkability | met toward RPs | Single-use IDs with per-presentation keys; nothing two RPs receive matches (§12.1). The registry itself can link them (§16) | scenarios 1, 4, 7 |
| **PR-8** PPIDs (optional) | agent PPIDs met | Pairwise mode: one stable ID per agent and RP, marked `id_mode: "pairwise"` by the registry (§5.3). Principal PPIDs and PPIDs shared by a group of RPs are not implemented | scenario 1 |
| **PR-9** No directory contact | met | An RP verifies with the registry's published keys and its whole status list; it never asks about one ID (§7.7, §10.1) | all scenarios |
| **PR-10** Presentation requests | met | RP metadata states what each action needs; a missing claim gets `step_up` with `missing_claims`, and the agent presents again (§9.1, §10.3) | `paper-requirements`; scenarios 2, 4 |
| **RV-1** Revocation | met, with one gap | By the principal, a parent agent, the registry under its published practices, or a legal order; the record is kept (§7.8, §7.11). A principal revokes a single grant (§8.2). A registry cannot yet withdraw one attribute before it expires (§16) | `paper-requirements`; scenarios 1, 3, 4 |
| **RV-2** Revocation latency | met | Published in the registry's practices and enforced by credential lifetime and status-list refresh (§7.8, §7.14) | scenario 1 |
| **ES-1** Identity escrow | met | A legal order resolves an ID to the principal accountable when it was issued, across registries, after revocation and after a transfer (§7.11) | scenarios 1, 3–7 |
| **ES-2** Multi-party control (optional) | not implemented | | |
| **DR-1** Published practices | met | In each registry's Entity Configuration and at `/v1/practices` (§7.14) | `paper-requirements` |
| **DR-2** Adherence | met for what is stated | The practices statement is generated from the running configuration. Nothing is deleted, so retention holds trivially (§16) | |
| **DR-3** Conformity assessment (optional) | not implemented | Admission by the trust anchor and the public transparency log are the nearest things here (§6.1, §7.13) | |

### 3.2 Beyond the paper

The paper leaves these out of scope, or names them as complementary. They are this profile's extensions.

| Extension | Where | Relation to the paper |
|---|---|---|
| Accredited record keepers for authorizations, bills of materials and activity | §6.4, §8 | One way to divide record-keeping across organizations (paper §3.1). Activity records are the "independently verifiable activity records" of paper §3.5 |
| Transfer of an agent between principals | §7.9 | Not in the paper. AG-5 covers only replacing an agent's key |
| Incident relay to a principal the reporter cannot identify | §7.10 | The paper's §3.3 says a counterparty can report an incident; the relay is this profile's design |
| Classifications, including "unlabeled" and "lookup failed" | §10.2 | The paper's conclusion asks a pilot to cover unsupported claims and revoked credentials |
| Passkey approvals, the human path, agent-bound account access | §8.4, §10.5 | The paper's §3.5 mentions a step-up proof of human authorization |
| Sub-agents registered at another registry | §7.12 | The paper leaves multi-directory chains to implementations |

---

## 4. Formats and conventions

### 4.1 Signatures and types

All signed artifacts are JWS compact serializations (RFC 7515) with `alg: "EdDSA"` over Ed25519 (RFC 8037). `kid` is the RFC 7638 thumbprint. Verifiers MUST check `typ`, and for SD-JWT VCs also `vct`:

| `typ` | Artifact | Signer | Defined by |
|---|---|---|---|
| `entity-statement+jwt` | Entity Configuration, Subordinate Statement | each member; trust anchor | OpenID Federation |
| `trust-mark+jwt` | accreditation of a record keeper for a role | registry | OpenID Federation |
| `dc+sd-jwt` | accountability, authorization and approval credentials (`vct` distinguishes) | registry; record keeper | SD-JWT VC |
| `kb+jwt` | key binding of a presentation | agent's presentation key | SD-JWT |
| `statuslist+jwt` | status list token | registry; record keeper | Token Status List |
| `JWT` | client assertion at the token endpoint | agent's long-term key | RFC 7523 |
| `aaf-registration+jwt` | registration receipt | registry | this profile |
| `aaf-status+jwt` | live status with reasons (between registries; investigators) | registry | this profile |
| `aaf-resolution+jwt`, `aaf-resolution-forward+jwt` | resolution result; forwarding between registries | registry | this profile |
| `aaf-legal-order+jwt` | legal order | resolution authority | this profile |
| `aaf-agent-proof+jwt` | an agent's proof that it holds a key (§7.4) | the agent key | this profile |
| `aaf-grant+jwt` | grant or role designation | principal or parent agent | this profile (body is RAR) |
| `aaf-provenance+jwt` | provenance record | provider | this profile (body is CycloneDX 1.6) |
| `aaf-activity+jwt` | activity log entry | agent or relying party | this profile |
| `aaf-sth+jwt` | signed tree head | log operator | this profile (RFC 9162 tree) |

Credential types are named under the trust anchor: `https://federation.aaf.test/vct/{accountability|authorization|approval}/1`.

### 4.2 Selective disclosure and key binding

Credentials use IETF SD-JWT. Each selectively disclosable value is replaced by the digest of a salted disclosure. Holders drop disclosures they do not want to reveal and append a Key Binding JWT `{iat, aud, nonce, sd_hash}` signed with the credential's `cnf` key. Verifiers MUST reject unreferenced or duplicate disclosures, and MUST require a valid KB-JWT for holder-bound credentials. Issuers pad disclosable sets with **decoy digests** to a fixed count, so the number of digests does not show how many values a holder could disclose; verifiers ignore digests with no disclosure. The KB-JWT `iat` MUST be a NumericDate (a finite JSON number, possibly fractional) within the verifier's freshness window; a missing or non-numeric `iat` is invalid.

**Rule (non-negotiable):** only grants of capability may be selectively disclosable. Hiding a permission can only understate what an agent may do. Prohibitions and every constraint inside an `authorization_details` entry MUST always be visible whenever the entry is visible.

### 4.3 Signed HTTP requests

Every authenticated call is signed with RFC 9421 HTTP Message Signatures (`alg="ed25519"`) and carries an RFC 9530 `Content-Digest`:

| Calls | Covered components | `tag` | `keyid` |
|---|---|---|---|
| principal/agent/verifier/registry/RP → registry or RK | `@method` `@target-uri` `content-digest` `content-type` | `aaf-request` | `principal:<id>`, `registration:<id>`, `verifier:<entity>`, `registry:<entity>`, or `jkt:<thumbprint>` with the key in the body as `signer_jwk` |
| agent → relying party | the above plus `aaf-presentation` | `aaf-agent` | `cnf:<thumbprint of the credential's cnf key>` |

`created` MUST be within ±120 s (60 s for agent requests). `nonce` MUST be unique per key (services keep replay caches). The replay identity is the thumbprint of the key that verified the signature, not the `keyid` spelling, and a request consumes its nonce only once it is authenticated. For agent requests that means the signature, the `cnf` binding and the accountability KB-JWT have been verified; a later authorization, status or policy denial may still consume it. The covered `@target-uri` binds a signature to one service and endpoint. For agent requests, the signature `nonce` is also the KB-JWT `nonce`.

### 4.4 Encryption

Sealed references are JWE compact (RFC 7516) with `alg: "ECDH-ES"`, `enc: "A256GCM"`, X25519, encrypted to the registry's `use: "enc"` key.

### 4.5 Logs, receipts and canonical JSON

Registries and record keepers keep append-only logs hashed as RFC 9162 Merkle trees. Entries are serialized with the JSON Canonicalization Scheme (RFC 8785). Operators sign tree heads `{log_id, tree_size, root_hash, timestamp}` and return a **receipt** `{log_id, index, leaf_hash, tree_size, inclusion_proof, sth}` for every append. They MUST serve inclusion and consistency proofs. **Profile choice:** the log is the service's database; state is rebuilt by replay. IETF SCITT is the natural production substrate (§16).

### 4.6 Coarsened time

A precise timestamp that describes a long-lived fact and is repeated across relying parties is a correlation handle. It MUST be coarsened in anything an RP sees. This profile uses months for verification and attribute times, and calendar days for `granted_on` / `valid_until`. Per-presentation `iat`/`exp` are not coarsened (§12.3).

---

## 5. Identifiers

### 5.1 Entity identifiers

Every federation member has an https URL as its OpenID Federation entity identifier (`https://registry-a.aaf.test`). **Profile choice:** in the local federation the trust anchor publishes each member's actual base URL as `endpoint_base` in its metadata; in production that equals the entity identifier.

### 5.2 Internal identifiers

Principal ids (`prn_…`) and registration ids (`reg_…`) are 128-bit random values known only to the registry, the principal, the agent and record keepers. They MUST NOT appear in anything presented to a relying party.

### 5.3 IDs and PPIDs

```
aaf:<registry host>:p_<26 base32>      pairwise (a PPID):   HMAC-SHA256(registry secret, registration ‖ chain version ‖ audience)
aaf:<registry host>:e_<26 base32>      ephemeral (single-use): random; with sealed_ref = JWE{id, registration, audience, version, root, iat}
```

The credential's `id_mode` claim says which kind an ID is, so an RP that needs a stable identifier (for an account, rate limits or reputation) can require a PPID. Earlier versions wrote `ppid:` for both kinds; registries still read that prefix. API fields that carry an ID are still named `ppid`.

| Property | How it is met |
|---|---|
| The ID resolves to its registry (PR-1) | the host component |
| At most one PPID per agent and RP; no two agents share one (PR-8) | the pairwise value is a keyed hash of the registration, its chain version and the audience |
| One ID, one principal–agent relationship | the relationship is (registration, chain version). A transfer bumps the version, which yields new IDs |
| RPs cannot link an agent by comparing presentations (PR-7) | a different value per audience (pairwise) or per presentation (ephemeral), plus a per-audience or per-presentation key |
| Only the registry can resolve it (ES-1) | pairwise: the registry's own mapping; ephemeral: only the registry can open `sealed_ref`, which the RP retains |

At issuance the registry records, for each ID, **which root principal was accountable**. Resolution of that ID always returns that principal, even after a later transfer (§7.11).

**Profile choice:** IDs are issued on demand, one credential per RP or per presentation (the paper's Appendix C §3, option 1). The registry therefore learns which RP each credential is for, and could link a single-use ID's issuance to its use. Batch issuance or anonymous credentials (options 2 and 3) would remove that (§16).

### 5.4 Registration binding

`reg_binding = base64url(SHA-256("aaf-binding|" ‖ registration ‖ "|" ‖ chain version ‖ "|" ‖ ppid))` appears in every accountability credential. A record keeper that knows a grant's registration and version can confirm, offline, that an ID belongs to that agent under that principal relationship. RPs cannot invert it, and it differs for every ID.

---

## 6. Trust framework (OpenID Federation 1.0)

### 6.1 Trust anchor and discovery

The federation's governance body is the **trust anchor**. Each party is configured out of band with only the trust anchor's entity identifier, URL and keys (`trust-anchor.json`), in the way a browser ships root certificates. Discovery then proceeds:

1. Fetch the trust anchor's Entity Configuration (`/.well-known/openid-federation`), verified with the configured keys. Its metadata contains `federation_entity` (fetch and list endpoints), `aaf_trust_anchor.policies` (federation-wide policies), and `trust_mark_issuers`.
2. List subordinates (`/list`) and fetch a Subordinate Statement for each (`/fetch?sub=`), signed by the trust anchor. It carries the subordinate's keys and metadata.
3. For each online subordinate, fetch its own Entity Configuration and verify it with the keys from the Subordinate Statement. Its `authority_hints` MUST name the trust anchor.

Services refresh this every 30 s. The result is each party's view of the federation.

### 6.2 Entity types

| Metadata type | Members | Key fields |
|---|---|---|
| `aaf_trust_anchor` | the governance body | `policies` (revocation interval, credential TTL, status cache and list TTL, max chain depth, retention) |
| `aaf_registry` | registries | `organization_name`, `jurisdiction`, `endpoint_base`, `jwks` (signing + encryption), `id_modes`, `practices` (§7.14), `endpoints`, `policies` |
| `aaf_record_keeper` | record keepers | `organization_name`, `roles`, `endpoint_base`, `jwks`, `endpoints` |
| `aaf_identity_verifier` | KYC/KYB providers | `organization_name`, `jwks` |
| `aaf_resolution_authority` | courts, regulators | `organization_name`, `jwks` |

Verifiers and authorities need not run endpoints: the trust anchor's Subordinate Statement vouches for their keys.

### 6.3 Identity verification (OpenID Connect for Identity Assurance)

Verifiers submit an IDA `verified_claims` object to the registry (`POST /v1/principals/{id}/verification`, signed `keyid="verifier:<entity>"`):

```json
{ "verification": { "trust_framework": "nist_800_63A" | "aaf_kyb", "assurance_level": "IAL2" | "high",
                    "time": "…", "verification_process": "kyc_…",
                    "evidence": [{ "type": "document", "check_details": [{ "check_method": "vcrypt" }, { "check_method": "bvr" }] }
                               | { "type": "electronic_record", "record": { "type": "company_register_extract", "source": {…} } }] },
  "claims": { …exactly the enrolled identity claims… } }
```

The registry MUST reject a submission whose `claims` differ from the enrolled identity (compared with JCS). **Principal attributes** (licensure, insurance, charter) are also `verified_claims`, one claim each, with the record `source`, so an RP can tell who attested each claim and how (the paper's PR-4).

### 6.4 Accreditation of record keepers: trust marks

A registry accredits a record keeper by issuing one OpenID Federation **trust mark** per role:

```json
{ "iss": "https://registry-a.aaf.test", "sub": "https://records-1.aaf.test",
  "trust_mark_type": "https://federation.aaf.test/trust-marks/record-keeper/authorization", "iat": …, "exp": … }
```

The trust anchor's `trust_mark_issuers` states which registries may issue which types. That is the governance decision about who may accredit. Record keepers publish their trust marks in their Entity Configurations. Registries serve current marks at `GET /federation/trust-mark?trust_mark_type&sub` and stop serving withdrawn ones. Registries MUST refuse record pointers to keepers without their trust mark for that role. RPs MUST check, live or cached for at most 60 s, that the registry which issued the accountability credential has issued a current trust mark to any keeper whose credential or log they rely on. They MUST also check that the trust anchor lists that registry as an issuer of that type.

---

## 7. Registry

### 7.1 Data held

| Record | Fields |
|---|---|
| Principal | `id`, `type`, `identity`, `contact`, `keys`, `verification` (IDA), `identity_key` (§7.2), `attributes` (IDA), `disclosure` policy, `closed` |
| Registration | `id`, `agent_jwk` (long-term key), `parent`, `root_principal` or `root_summary` (remote), `depth`, `epoch`, `custody` history, `expires_at`, `lineage_max_depth`, `provider`, `records`, `label`, `status` |
| ID | pairwise: `{registration, audience, version, root at issuance, status index}`; ephemeral: a status-list entry kept only until the credential expires |
| Transfer offers, accreditations, incidents, notifications, resolutions | as below |

The registry stores no authorizations, bills of materials or activity: accredited record keepers hold those (§8), so the party that knows identities does not also hold what agents are allowed to do or did.

### 7.2 Enrollment and verification (the slow step)

`POST /v1/principals` (signed, `keyid="jkt:…"`) creates a pending principal. `POST /v1/principals/{id}/verification` from a trusted verifier (§6.3) verifies it. This happens once.

**One record per verified identity (PV-3).** When a verification arrives, the registry derives an identity key from the verified claims and refuses a second record for the same identity (`409 duplicate_identity`). **Profile choice:** a legal entity is keyed by its LEI, else its jurisdiction and registration number; a natural person by name, jurisdiction and date of birth where given. A real registry would key on the evidence its proofing produced; names alone are weak.

A person who loses their key cannot simply enroll again. The operator closes the old record (`POST /admin/principals/{id}/close`): its agents are suspended, the record and its history are kept so earlier IDs can still be resolved, and the identity may then enroll and be verified afresh.

### 7.3 Disclosure policy (consent)

`PUT /v1/principals/{id}/disclosure-policy`:
`{ "identity": { "audiences": [...], "claims": ["legal_name","registration_number"] }, "attributes": ["licensed_healthcare_provider"] }`. Only `legal_name`, `jurisdiction`, `registration_number` and `lei` can be disclosed by consent. Identity claims are offered, selectively disclosable, only to audiences the policy names. The agent still decides per request.

### 7.4 Registration (the fast step)

`POST /v1/registrations` with `{agent_jwk, agent_proof, parent, records, provider, label, expires_in?, lineage?: {max_depth}}`:

| `parent.type` | Signed by | Checks |
|---|---|---|
| `principal` | principal key | principal verification valid, else `403 principal_not_verified` |
| `agent` | parent agent's long-term key | parent `active`; depth ≤ `maxChainDepth` (federation policy, 8); **every ancestor's depth budget** respected (`403 lineage_depth_exceeded`) |
| `remote_agent` | the parent's presentation key for this registry (`jkt:`) | `parent.attestation` is an accountability credential from a peer registry, `aud` = this registry, unexpired, `cnf` = signing key, peer reports it `active` |

The agent key MUST be new to the registry, and the agent MUST prove it holds it (AG-2): `agent_proof` is an `aaf-agent-proof+jwt` signed with `agent_jwk`, with claims `{aud: <registry>, purpose: "aaf-agent-registration", binding: <the registrant's keyid>, agent_key: <thumbprint>, iat}`. The registry rejects a proof that is older than 120 s or was made for another registry, purpose or registrant. A principal therefore cannot register a key that no agent of its holds, and a proof cannot be reused by a different registrant.

Every `records` pointer MUST name a keeper holding this registry's trust mark for that role. The **registration receipt** (`aaf-registration+jwt`) carries `{iss, sub, agent_key, principal (current parent link), depth, version, records, expires_at}`. Record keepers use it to verify grants. `POST /v1/registrations/{id}/receipt` re-issues it, for example after the lineage changes hands.

### 7.5 Lineages, expiry and depth budgets

- **Expiry.** `expires_in` makes a registration lapse on its own (status `expired`). No sub-agent outlives its parent: the registry clamps a child's expiry to the earliest expiry along its chain. Credentials never outlive the registration (`exp` ≤ effective expiry).
- **Depth budgets.** `lineage.max_depth` on any registration caps how many levels of sub-agents may exist below it. The federation's `maxChainDepth` caps every chain.
- **Cascade.** A registration's status is computed along its chain (§7.7). Revocation, expiry or suspension of any ancestor applies at once to every descendant, including those registered with peer registries.
- **Key rotation (AG-5).** `POST /v1/registrations/{id}/rotate-key {agent_jwk, agent_proof}`, signed by the root principal or an ancestor agent, replaces an agent's long-term key without changing its PPIDs. The proof (purpose `aaf-agent-key-rotation`, bound to the registration) is signed with the new key. The change is logged, so IDs presented under the old key still resolve.

### 7.6 Accountability credentials (SD-JWT VC)

`POST /v1/attestations` (signed `keyid="registration:<id>"`) with `{audience, mode, cnf_jwk}`. The `cnf_jwk` MUST differ from the long-term key, and status MUST be `active` (`503` if an upstream peer cannot be reached):

| Claim | Always visible | Notes |
|---|---|---|
| `vct` | ✓ | `…/vct/accountability/1` |
| `iss`, `sub` (the ID), `aud`, `iat`, `exp`, `jti` | ✓ | `exp` = min(iat + TTL, registration expiry) |
| `cnf.jwk` | ✓ | per-audience or per-presentation key |
| `status.status_list` | ✓ | `{idx, uri}` in the registry's Token Status List; random index |
| `id_mode`, `reg_binding` | ✓ | `pairwise` (a PPID) or `ephemeral` (single-use) |
| `accountability.status` | ✓ | always `"accountable"`: the registry's statement that the ID resolves to a principal it verified under its published practices |
| `accountability.principal_type` | SD | `natural_person` or `legal_person` |
| `accountability.assurance` | SD | `{trust_framework, assurance_level}` from the IDA verification |
| `accountability.verification_source` | SD | `{verifier, time (month)}` |
| `accountability.principal_directory` | SD | the registry holding the principal's record (differs from `iss` for a sub-agent registered elsewhere, §7.12) |
| `accountability.chain_length` | SD | the number of agents in the chain, counting this one |
| `accountability.{legal_name, jurisdiction, registration_number, lei}` | SD (each) | present only for audiences named in the principal's disclosure policy |
| `accountability.attributes[]` | SD (each) | IDA `verified_claims` per attribute, with `valid_until` (month) |
| `records[]` (`{role, rk, ref?}`) | SD (each) | pointers to authorization, provenance and activity keepers |
| `sealed_ref` | ✓ | ephemeral mode only |

**The ID alone is a valid presentation** (PR-1). With every disclosure withheld, an RP learns the ID, its registry and that the registry verified a principal who answers for the agent; nothing about what kind of principal, how it was verified or how long the chain is (PR-6). `accountability` and the two arrays are padded with decoy digests to fixed counts, so two principals' credentials have the same shape whatever each could disclose.

### 7.7 Status

A registration's status is computed along its chain: revoked → `revoked`; past expiry → `expired`; parent principal's verification lapsed, or its record closed → `suspended`; local parent not active → the parent's status (`upstream:<reason>`); remote parent → the peer's status (cached ≤ `statusCacheSeconds`; a peer that cannot be reached gives `unknown`; a transferred remote parent gives `revoked`, reason `parent_transferred`). An ID whose chain version is no longer current is `transferred`.

The status is published two ways:

- **Token Status List** (`GET /status-lists/1`, `statuslist+jwt`, 2 bits per entry, 65,536 entries, zlib): `VALID` (active), `INVALID` (revoked, expired), `SUSPENDED` (suspended, unknown), `TRANSFERRED` (0x03, application-specific). The token's `ttl` is `statusListTtlSeconds` (10 s). RPs fetch the whole list, so the registry does not learn which credential is being checked. Reasons are not published.
- **Live status** (`POST /v1/status {ppid, sealed_ref?}` → `aaf-status+jwt` with reasons), used between federation peers and by investigators. RPs MUST NOT use it to verify presentations: asking about one ID would tell the registry which RP is dealing with which agent (the paper's PR-9).

### 7.8 Revocation

A registration can be revoked by four parties (RV-1):

| By | How |
|---|---|
| the root principal, or any agent above it in its chain | `POST /v1/registrations/{id}/revoke {reason}`, signed; a remote parent signs with its presentation key |
| the registry, under its published practices (for example fraud) | the operator's `POST /admin/registrations/{id}/revoke` |
| a recognized authority | a legal order with the `revoke_registration` scope (§7.11) |

Reasons: `principal_request`, `compromised`, `authority_ended`, `fraud`, `legal_order`, `superseded`, `parent_transferred`. Revocation cascades (§7.5), is pushed to peers (§7.12), and stops only **future** reliance. The record is kept, so earlier presentations can still be attributed. Revoking a registration does not link its single-use IDs to one another for RPs.

**Revocation latency (RV-2).** The bound is published in the registry's practices (§7.14). An RP that fetches the status list for a consequential action sees revocation within one list generation, which is immediate in this implementation. An RP using a cached list sees it within the list's `ttl`. One that skips status entirely stops accepting a credential within `attestationTtlSeconds` (300 s). Peer registries see it immediately by push, or within `statusCacheSeconds` (15 s) by pull.

### 7.9 Transfer between principals

A transfer is a new principal–agent relationship. The old principal remains answerable for what happened before it.

1. **Offer.** The principal an agent is *directly* registered under signs `POST /v1/registrations/{id}/transfer-offers {to_principal, subtree: "move" | "end", expires_in}`. The recipient is notified. The offerer may cancel.
2. **Acceptance.** The named recipient signs `POST /v1/transfer-offers/{offer}/accept {agent_jwk, agent_proof}`. The recipient MUST be a verified principal, the offer unexpired, the agent active and still in the offered custody, and `agent_jwk` a **fresh** key, because the previous owner may hold the old one. The proof (purpose `aaf-agent-transfer`, bound to the offer) is signed with the new key.
3. **Effect.** The registration's epoch, and so the chain version of the agent and every local descendant, increments. Custody history records both periods. The agent's key is replaced.
   - Every ID issued under the old version becomes `TRANSFERRED`; new presentations get new IDs.
   - With `subtree: "move"`, descendants stay attached under the new principal. They fetch fresh receipts and need fresh delegations. With `subtree: "end"`, they are revoked (`parent_transferred`).
   - Sub-agents registered with peer registries are ended either way; the new owner re-attaches them.
   - Peer registries are notified; both principals are notified.
4. **Authority does not transfer.** Grants are bound to the chain version through `reg_binding` (§5.4), so the old principal's grants cannot be exercised under the new relationship. When the new principal deposits a grant with a newer receipt, the record keeper marks the older grants `superseded`, and it rejects deposits that carry a receipt older than one it has seen (`stale_receipt`).

### 7.10 Incidents

`POST /v1/incidents {ppid, sealed_ref?, reporter, summary, evidence}`, signed by the RP. The registry notifies the principal accountable for that ID and, if the agent has since changed hands, the current principal too. It returns the provider's incident-response contact. If the root is registered with a peer, the report is relayed there. The reporter never learns who the principal is.

### 7.11 Legal orders: resolution and revocation

The paper calls this attribution through identity escrow (ES-1): the registry holds the link from an ID to its principal and releases it only under an established process. In this profile the process is a legal order (`aaf-legal-order+jwt`) from a recognized authority, naming `{case, ppids, relying_party, requester, scope, notify_principal, purpose}`.

**Resolution.** `POST /v1/resolutions {order, ppid, sealed_ref?, forward?}`:

1. Verify the order and that it covers the ID.
2. Locate the registration, chain version and **the root principal recorded at issuance** (sealed reference for single-use IDs).
3. Walk the chain. If its top is a remote parent, forward to the peer with a registry-signed `aaf-resolution-forward+jwt`.
4. Return the accountable principal (identity, contact, IDA verification), the ID's status (for example `transferred`), the current principal if different, the chain with custody history, and (if in scope) related PPIDs at the order's relying party under the same accountable principal.
5. Log `resolution.performed`; notify the principal unless the order forbids it.

**Revocation.** `POST /v1/revocations {order, ppid, sealed_ref?}`. The order MUST name the ID and carry the scope `revoke_registration`; an order that only authorizes resolution is refused (`403 not_in_scope`). The registry revokes the registration behind the ID with reason `legal_order`, which cascades to its sub-agents, records the authority and case in its log, and notifies the principal unless the order forbids it. If the agent has changed hands since the ID was issued, the relationship the ID names has already ended and the request is refused (`409 custody_changed`): the order would otherwise fall on a different principal.

**Profile choice:** a legal order is the only route to resolution. The paper also allows release with the principal's consent, for example in dispute resolution; here a principal consents in advance by naming RPs in its disclosure policy (§7.3).

### 7.12 Federation

| Property | How it is met |
|---|---|
| IDs name the issuing registry | the ID's host component |
| An ID resolves to a root principal across registries | `remote_agent` links recorded by the parent's PPID at the child's registry (the parent discloses its chain summary to that registry and nothing else); resolution forwarding |
| Status is consistent across registries | Child status depends on the peer's status for the parent. On revocation or transfer the parent's registry **pushes** `POST /v1/federation/status-changed {ppids}` (signed `keyid="registry:<entity>"`) to every peer it issued a PPID to. Pull with a bounded cache is the backstop. |

### 7.13 Transparency log

Every state change is a log entry: principal enrollment, verification, attributes, disclosure, closure; registration created, revoked, transferred, key rotated; transfer offered or cancelled; PPID issued; accreditation granted or withdrawn; incident; notification; resolution. The public view shows only `{index, type, at, leaf_hash}`. STHs and consistency proofs are public.

### 7.14 Published practices

Each registry publishes what a principal or relying party needs to decide whether to rely on it (the paper's DR-1), as `practices` in its `aaf_registry` metadata and at `GET /v1/practices`:

| Section | States |
|---|---|
| `identity_proofing` | the kinds of verified identity, the method, the recognized verifiers, the Sybil rule, what happens when a verification lapses |
| `authentication` | how principals and agents authenticate |
| `ids` | the two modes, how long a credential is valid, that every claim but the ID is optional |
| `revocation` | who may revoke, that it cascades, the latency bound, how status is published |
| `records` | what is held and not held, the retention period, that records survive revocation, the log |
| `disclosure` | what RPs can learn, the attribution process and the recognized authorities, logging and notice, incident relay |
| `signing_keys`, `security` | how keys are held; the operating standard |

The statement is generated from the running service's configuration, so it cannot drift from what the code does (DR-2). Relying parties use it, with the claims in each credential, to set their own acceptance criteria (§10.3).

---

## 8. Record keepers

### 8.1 Common requirements

Every record MUST be **attributable** (signed by its source), **tamper-evident** (in the keeper's Merkle log, receipted) and **reachable** (named by a registry pointer or a credential reference). Keepers MUST serve STHs and inclusion and consistency proofs. One operator may fill several roles.

### 8.2 Grants (authorization records)

A grant (`aaf-grant+jwt`, signer's key embedded):

```json
{ "iss": "principal:<prn>@<registry>" | "agent:<reg>@<registry>",
  "sub": "<grantee registration>", "registry": "<registry entity>", "agent_key": "<grantee long-term key thumbprint>",
  "iat", "nbf", "exp", "jti": "grt_…",
  "authorization_details": [ { "type": "commerce", "actions": ["purchase"], "max_amount": { "value": 500, "currency": "USD" } } ],
  "prohibitions": [ { "type": "commerce", "actions": ["subscribe"] } ],
  "delegation": { "allowed": false, "max_depth": 0 }, "purpose": "…", "context": { … },
  "parent_grant": "<grant id>" }            // delegated grants only
```

`POST /v1/grants {grant, registration_receipt}`. The keeper verifies:

- the receipt (trusted registry) and that `sub`, `registry` and `agent_key` match it;
- the receipt is not older than any it has seen for that registration;
- a principal grant is signed by one of the receipt's principal keys;
- a delegated grant: the parent grant is held and active, the signer is its agent, the receipt's chain runs through that agent, and attenuation holds (§11.3).

The grant records the receipt's chain version. Role designations use `grantee: {kind: "person", key_thumbprint, role}`. Grants are revoked by their grantor. Status cascades through parent grants.

### 8.3 Authorization credentials: RFC 8693 Token Exchange

An RP cannot verify a principal-signed grant without learning the principal's key, which would identify the principal and link every presentation. The keeper therefore runs a token endpoint, `POST /token` (form-encoded):

| Parameter | Value |
|---|---|
| `grant_type` | `urn:ietf:params:oauth:grant-type:token-exchange` |
| `subject_token` / `_type` | the grant JWS / `urn:ietf:params:oauth:token-type:jwt` |
| `actor_token` / `_type` | the accountability credential for this audience / `urn:aaf:params:oauth:token-type:accountability` |
| `audience` | the relying party |
| `requested_token_type` | `urn:aaf:params:oauth:token-type:authorization` |
| `client_assertion_type` / `client_assertion` | RFC 7523 JWT bearer; `iss = sub = urn:aaf:registration:<id>`, `aud = <keeper>/token`, signed by the grantee's long-term key |

The keeper checks the client assertion against the grant's `agent_key`, then that the grant is active, the actor token is valid, from the grant's registry, for this audience and unexpired, and that `reg_binding` matches the grant's registration **and chain version**. Errors follow RFC 6749 §5.2. The response `{access_token, issued_token_type, token_type: "N_A", expires_in}` carries an SD-JWT VC:

| Claim | Visible | Notes |
|---|---|---|
| `vct`, `iss`, `aud`, `iat`, `exp`, `jti` | ✓ | `exp` ≤ grant `exp` and the actor token's `exp` |
| `sub` | ✓ | the principal, as a per-token pseudonym (`urn:aaf:pseudonym:…`) |
| `act` | ✓ | RFC 8693: `act.sub` = the acting agent's ID; nested `act` = delegating agents, as per-token pseudonyms. Depth shows delegation without identifying anyone. An agent that presents its authority therefore shows how deep the delegation runs. |
| `cnf` | ✓ | copied from the actor token: the same key, so the RP can check both credentials belong to one holder |
| `authorization_details[]` | SD (each) | RFC 9396 entries; the agent reveals only those covering the request |
| `prohibitions`, `delegation`, `granted_on`, `valid_until` | ✓ always | dates coarsened |
| `purpose`, `context` | SD | |
| `grant_commitment` | ✓ | `SHA-256(salt ‖ "." ‖ grant)`; salt kept by the keeper for audit |
| `status.status_list` | ✓ | the keeper's Token Status List |

### 8.4 Approvals by designated humans (passkeys)

A grant can make a power conditional: `requires_approval: {role}` on an `authorization_details` entry. The agent may exercise it only with an approval from a person the principal designated to that role. Designated people approve with **passkeys**, and the authorization record keeper is the WebAuthn relying party (`rpId` = its host, origin = its entity identifier):

1. **Registration.** `POST /v1/webauthn/registration-options` then `POST /v1/webauthn/register` (attestation `none`, user verification required). The keeper records the credential.
2. **Designation.** The principal's role designation names the person by that credential: `grantee: {kind: "person", passkey: <credential id>, role}`. The keeper refuses designations naming unknown passkeys.
3. **Approval request.** `POST /v1/approvals/options {designation_id, ppid, action, subject_digest}`. The keeper checks that the designation is active, that it issued an authorization credential for this ID, and that the designee and the agent answer to the same principal. It then returns WebAuthn request options whose `challenge` = SHA-256(JCS({purpose, details, nonce})). The challenge therefore commits to the agent, action and document. Ceremonies are single-use and expire after 5 minutes.
4. **Approval.** `POST /v1/approvals {request_id, credential}`. The keeper verifies the assertion: `webauthn.get`, challenge, origin, `rpIdHash`, the UP and UV flags, the signature with the designee's public key, and the counter. Only then does it issue an approval SD-JWT VC `{vct …/approval/1, sub: ppid, role, action, subject_digest, approver_ref, approval_method: {type: "webauthn", user_verified: true}, status, exp}`.

RPs MUST reject approvals whose `approval_method` is not a user-verified passkey. An approval is valid only for that agent, action and document, and only while the designation is in force.

### 8.5 Provenance records (CycloneDX 1.6)

The provider signs `{provider, bom: <CycloneDX 1.6 document>, iat}`. The BOM's `metadata.component` is the agent build, with a `security-contact` external reference and incident-response `properties` (`aaf:incident-response:constrain-endpoint`, `…:notify-principal-via`). Its `components` are typed (`machine-learning-model`, `framework`, `application`, `library`), and `dependencies` link them to the build. Records are content-addressed (`prov_<digest>`), and one is shared by every agent on a build.

### 8.6 Activity logs

Entries (`aaf-activity+jwt`): `{subject: <ppid>, txn, writer_role: "agent" | "relying_party", writer, event, details, at}`, signed by the agent's presentation key or the RP's key. Read access is limited to parties that wrote to that subject's log, and to holders of a legal order (optionally widened by a registry resolution listing related PPIDs). An agent discloses its activity-log pointer by default so both sides can write to the log; it can withhold it.

### 8.7 Status

`GET /status-lists/1` publishes the keeper's Token Status List over authorization and approval credentials (`VALID`; `SUSPENDED` if not yet valid; `INVALID` if revoked, superseded or expired). `POST /v1/status {ref}` remains available for live checks.

---

## 9. Presentation protocol

### 9.1 Relying-party metadata

`GET /.well-known/aaf-relying-party` → `{id, name, jwks, accepted_registries, requests, actions}`. `id` is the audience agents address. `accepted_registries` lists the registries whose IDs this RP accepts: all of the federation's by default, or the RP's own choice. `requests` names what the RP asks to see on every action: any of `identity`, `attributes: [names]`, `provenance`, `principal_type`, `assurance`, `verification_source`, `chain_length`, `principal_directory`. `actions` publishes each action's policy tiers, from which an agent can tell what else that action needs (§10.3). This is the paper's presentation request (PR-10): the RP asks the agent, never the registry or the principal.

### 9.2 Request

```
POST /actions/commerce.purchase
Content-Type: application/json
Content-Digest: sha-256=:…:
AAF-Presentation: <base64url JSON { "v": 2,
                    "accountability": <SD-JWT VC ~ disclosures ~ KB-JWT>,
                    "authorization":  <SD-JWT VC ~ disclosures ~ KB-JWT>,      (optional)
                    "approval":       <SD-JWT VC>                              (optional) }>
Signature-Input: sig1=("@method" "@target-uri" "content-digest" "content-type" "aaf-presentation");
                 created=…;nonce="n_…";alg="ed25519";keyid="cnf:<thumbprint>";tag="aaf-agent"
Signature: sig1=:…:
```

Both KB-JWTs use `aud` = the RP's id and `nonce` = the signature's `nonce`. This is the Web Bot Auth pattern (RFC 9421 request signing by an agent), with the key taken from the presented credential rather than from a key directory.

### 9.3 Agent obligations

An agent MUST use a presentation key that differs from its long-term key: one per audience in pairwise mode, one per presentation in ephemeral mode. It MUST present credentials issued for the RP's `id`, and by default reveal only the ID, the activity-log pointer and the `authorization_details` matching the request. It reveals claims about the principal or the chain, identity claims, attributes or provenance only when the RP asks, and identity claims and attributes only if the principal's policy made them available. It MUST log its own account of each action.

### 9.4 Responses

`200` (allow) or `403` with `{txn, decision, reasons, tier, classification, result, missing_claims?}`. `decision` ∈ `allow | deny | step_up | deferred`. With `step_up`, `missing_claims` names what the agent should add to its next presentation.

---

## 10. Relying-party verification and policy

### 10.1 Verification algorithm

0. **Nothing presented** → `UNLABELED`. A bare `AAF-Claim` header → `UNSUPPORTED`.
1. **Accountability credential**: issuer is a federation registry (§6.1) that this RP accepts (§9.1); SD-JWT VC signature valid; `vct` = accountability; `aud` = RP; unexpired; `accountability.status` = `accountable`. Failure → `UNSUPPORTED`. Nothing else in the credential is required.
2. **Holder**: RFC 9421 signature valid with `keyid` = the credential's `cnf` thumbprint, covering the required components; fresh; nonce unseen. The `keyid` only selects the key: the key that verifies the signature MUST be the `cnf` key, so a self-presented `jkt:` key is never accepted here. KB-JWT valid with `aud` = RP and `nonce` = signature nonce. Failure → `UNSUPPORTED` (intercepted or replayed credentials).
3. **Status**: fetch the registry's status list (fresh when the policy tier requires live status, otherwise within `ttl`). `INVALID`, `SUSPENDED` or `TRANSFERRED` → `REVOKED`. List unavailable → `LOOKUP_FAILED`.
4. **Authorization credential**: issuer is a federation record keeper holding the issuing registry's trust mark for `authorization` (§6.4); SD-JWT VC + KB-JWT valid; `vct` = authorization; `act.sub` = the ID; same `cnf`; `aud` = RP; unexpired; status list `VALID`.
5. **Approval** (if carried): keeper accredited; `vct` = approval; `sub` = the ID; `action` and `subject_digest` match; unexpired; status list `VALID`.
6. **Authority**: evaluate the request against the disclosed `authorization_details` and the always-visible prohibitions (§11.2).

Otherwise the classification is `ACCOUNTABLE_DISCLOSED` if `legal_name` was disclosed, else `ACCOUNTABLE_PROTECTED`.

Every step uses only the presentation and what registries and record keepers publish for everyone: federation metadata and keys, status lists, trust marks. The RP never asks a registry about a particular ID (the paper's PR-9).

### 10.2 Classifications

| Classification | Meaning |
|---|---|
| `ACCOUNTABLE_DISCLOSED` | a verified principal stands behind the agent; identity disclosed by consent |
| `ACCOUNTABLE_PROTECTED` | a verified principal stands behind the agent; identity protected but recoverable by the registry |
| `UNSUPPORTED` | a claim was made but could not be established (self-asserted, from an unaccepted issuer, or presented without the holder's key) |
| `UNLABELED` | nothing was presented |
| `REVOKED` | established, but no longer active (revoked, expired, suspended, transferred) |
| `LOOKUP_FAILED` | status could not be checked; **not** evidence that no principal exists |
| `HUMAN_APPROVED` | no agent credentials, but the account holder approved this exact request with a passkey (services with accounts only, §10.5) |

The paper's conclusion asks a pilot to cover disclosed and protected principals, unsupported claims and revoked credentials; Scenario 4 runs all of them. Keeping `UNLABELED` and `LOOKUP_FAILED` apart from the rest is this profile's addition: an RP should not read either as proof that no principal exists.

### 10.3 Policy tiers and decisions

What an agent must show is set by the context (the paper's "Proportionate"). Per action, ordered tiers `{label, when?, require}`, where `require` may hold:

| Member | Meaning |
|---|---|
| `accountability` | `none`, `established` (a valid ID), `disclosed` (identity shown), or `agent_or_human` (§10.5) |
| `principalType`, `assurance`, `trustFramework`, `maxChainLength` | acceptance criteria: the kinds of principal, assurance levels and proofing frameworks the RP accepts, and how long a chain may be. A bank might require a legal or natural person proofed to a stated level; another service might accept any valid ID |
| `authorization`, `attributes`, `provenance` | authority covering the action; named verified attributes; the bill of materials |
| `liveStatus` | fetch a fresh status list (default) or accept a cached one |
| `account: 'owner'`, `humanApproval` | passkey rules for services with accounts (§10.5) |

Because claims about the principal and the chain are optional (§7.6), a tier that needs one asks for it and judges it only once it is shown:

| Situation | Decision |
|---|---|
| `UNLABELED` / `UNSUPPORTED` and accountability required | `deny` (open tiers allow) |
| `REVOKED` | `deny` |
| `LOOKUP_FAILED` and accountability required | **`deferred`** |
| `ACCOUNTABLE_PROTECTED` and the tier requires `disclosed` | `step_up` |
| a claim an acceptance criterion needs was not shown | `step_up`, naming it in `missing_claims` |
| a shown claim does not meet the criterion | `deny` with reasons |
| required attribute or provenance missing | `step_up` |
| authorization missing, invalid or not covering the action | `deny` with reasons |
| otherwise | `allow` |

### 10.4 Evidence retention

For every decision the RP keeps: transaction id, time, action and parameters, decision and reasons, classification, the ID and its mode, issuing registry, `sealed_ref` (single-use IDs), whatever claims about the principal and chain were disclosed, disclosed identity and attributes, authority relied on, approval, the **status list tokens** it checked, a presentation digest, each verification check, and its activity-log receipt. It also writes a signed `decision` entry to the agent's activity log at an accredited keeper. Under the Bank Secrecy Act this record supports a SAR filing (Scenario 1).

### 10.5 Passkeys at services: the human path, agent-bound access, step-up

A service with its own accounts uses passkeys in three ways. The first two answer the question of agents posing as humans; the third adds a human check to consequential steps. All three run the same WebAuthn ceremony: the challenge commits to the approval request's details, user verification is required, and the request is single-use.

| Use | When | Rule |
|---|---|---|
| **Human path** (`accountability: 'agent_or_human'`) | a request names an account and carries **no** agent credentials | honored only with a passkey approval by the account holder of *this exact request* (account, action, parameters), passed as `AAF-Human-Approval: <request id>`; classification `HUMAN_APPROVED`. A bearer token alone is refused. |
| **Agent-bound access** (`account: 'owner'`) | an accountable agent acts on an account | the agent's PPID at the service must hold a delegation the account holder approved with a passkey. The first request opens an approval request; the holder sees what the service asked the agent to show about who stands behind it (kind of principal, assurance, verifier, chain; identity only if disclosed) and approves or declines. |
| **Step-up** (`humanApproval: true`) | sensitive actions, even by authorized agents | each action needs a passkey approval of that exact action and parameters (`AAF-Approval-Ref: <request id>`), usable once. |

**Stolen tokens.** In passkey mode a bearer API token identifies an account but carries no authority. An agent that presents an account's token without the holder's authorization is refused. Such a presentation is itself evidence of credential theft, so the service SHOULD file an incident (§7.10) at once. The agent's principal is then notified on the first attempt (Scenario 3, branch C).

Service endpoints (reference implementation): `POST /accounts/{account}/passkeys/options` and `/passkeys` (registration), `GET /accounts/{account}/requests` (pending approvals), `POST /accounts/{account}/human-requests` (open a human-path request), `POST /approval-requests/{id}/options` · `/approve` · `/decline`. RP metadata publishes `webauthn: {rpId, origin}`.

**What a passkey approval proves.** "The holder of this registered authenticator approved this, just now, on this site." The service never sees the biometric, only the authenticator's user-verification flag. Software authenticators can set that flag without a person present. A service that needs hardware-backed assurance MUST require attestation at registration and check authenticator models, at some cost to consumer usability, since synced passkeys usually provide none. Approvals SHOULD be shown to the person in trusted UI, as W3C Secure Payment Confirmation does for payments, so a page cannot misrepresent what is being approved.

---

## 11. Authority (RAR) and delegation

### 11.1 Representation

Authority is a list of RFC 9396 `authorization_details` entries. `type` names an area (`commerce`, `filing`, `compute`), and `actions` lists verbs (omitted means every action of the type). A request names `type.action` (`commerce.purchase`). The remaining members are constraints.

### 11.2 Constraints and evaluation

| Constraint | Request parameter | Satisfied when |
|---|---|---|
| `max_amount {value, currency}` | `amount` | same currency and `value ≤ limit` |
| `categories [..]` | `category` | listed |
| `max_units {value, unit}` | `units`, `unit?` | `units ≤ value` |
| `regions [..]` | `region` | listed |
| `requires_approval {role}` | approval carried | approval valid and role matches |
| *anything else* | | **never** (fail closed) |

If a prohibition matches → not permitted. Otherwise the request is permitted if any matching entry has all its constraints satisfied.

### 11.3 Attenuation

A delegated grant is accepted only if the parent allows delegation with depth remaining, the child expires no later, every child entry is covered by a parent entry (same type, actions a subset, constraints at least as strict), no child entry falls under a parent prohibition, and every constraint is a known type. Prohibitions are inherited. RPs see the delegation depth through nested `act`.

A delegating agent SHOULD choose the child's expiry so that this holds. With no requested length, the default (seven days in the reference implementation) is cut to the parent grant's expiry, as a sub-agent's registration is cut to its parent's lifetime (§7.5). A requested length that would outlive the parent grant is refused before the grant is sent.

---

## 12. Privacy considerations

### 12.1 Unlinkability across relying parties

The simulator tests this directly (Scenario 1, step 8, and Scenario 7 across a transfer). It pools everything two RPs received (credentials, disclosures, KB-JWTs, signature `keyid`s, nonces and signatures) and finds no shared value of 16 or more characters and no shared timestamp, apart from public constants such as issuer keys, `vct`s and status-list URIs. The mechanisms are: pairwise or single-use IDs; per-audience or per-presentation keys; fresh salts and decoy digests; a `reg_binding` that differs for every ID; token exchange (the RP never sees the principal's signature); per-token pseudonyms in `sub` and `act`; random status-list indices; coarsened long-lived times; and per-build provenance records.

### 12.2 Status privacy

Status lists are fetched whole, so the registry and record keepers do not learn which credential an RP is checking. Indices are random, so they reveal nothing about issuance order. Reasons for invalidity stay with the registries.

### 12.3 Residual linkability (out of scope, noted)

- **Timing and network:** per-presentation `iat`, IP addresses, TLS fingerprints.
- **Structural leakage:** decoy digests fix the number of digests in the accountability credential (§7.6), but not in the authorization credential, where the count of `authorization_details` entries is visible.
- **What is disclosed:** claims an RP asks for narrow the set of principals an agent could belong to. A verifier's name and a verification month identify fewer principals than an assurance level does; RPs SHOULD ask for the least that their decision needs.
- **Content of disclosures:** for example a free-text `purpose` shown to two RPs.
- **Behavior.**
- **Trusted parties:** the registry issues each credential for a named RP, so it learns which RPs an agent deals with and roughly when, and could link a single-use ID's issuance to its use; the authorization RK sees which audiences a grant was exchanged for. Neither sees requests, disclosed claims or outcomes. The paper's design goal of minimal directory knowledge is met for status checks (§12.2) but not for issuance (§16).

### 12.4 Identity disclosure

Identity reaches an RP only by consent, or reaches an authority by legal order. Each resolution is logged. Principals are notified unless the order forbids it.

---

## 13. Security considerations

| Threat | Mitigation | Residual |
|---|---|---|
| Stolen credential replayed | RFC 9421 signature and KB-JWT by the `cnf` key, bound to method, URL, body, presentation, audience and nonce | key theft; hence revocation |
| Stolen agent keys | revocation; the registry refuses new credentials; status lists reject cached ones; TTL bounds RPs that skip status | window ≤ TTL for RPs skipping status |
| Previous owner keeps keys after a transfer | acceptance requires a fresh agent key, proven by the new holder; old IDs `TRANSFERRED`; old grants unbindable and superseded; stale receipts refused; `rotate-key` for moved sub-agents | sub-agents moved without rotation keep their keys until rotated |
| Mix-and-match of credentials | `reg_binding` (with version) checked at exchange; `act.sub` and `cnf` must match at the RP | — |
| Hiding limitations | prohibitions and constraints never selectively disclosable | — |
| Obsolete authority | expiry; status lists; approvals tied to designations | RPs using cached lists: bounded by `ttl` |
| Over-delegation; runaway lineages | attenuation at deposit; depth budgets; federation max depth; ephemeral expiry | — |
| Self-asserted or rogue-registry claims | OpenID Federation trust chain to the trust anchor; the RP's own list of accepted registries; classified `UNSUPPORTED` | — |
| Unaccredited or de-accredited record keeper | live trust-mark check; trust anchor's `trust_mark_issuers` | ≤ 60 s RP cache |
| Rogue agents (paper §3.3) | authority enforced by resource holders; incident relay; revocation by the principal, the registry or a legal order, which ends every ID and sub-agent at once | does not prevent the compromise |
| A principal registers a key no agent of its holds, or someone else's | the agent's proof of possession, bound to the registrant (§7.4) | — |
| One identity enrolling many principals to evade revocation or limits | one principal record per verified identity (§7.2) | only as strong as the identity key; not checked across registries |
| Malicious principals; sham sponsorship | verified identity on record; resolution; liability hook | depends on law reaching the sponsor |
| Malicious provider | signed, content-addressed CycloneDX | claims rest on the provider's word |
| Compromised record keeper | receipts, inclusion and consistency proofs; writers' signatures; registry unaffected (Scenario 6) | withholding data |
| Compromised registry | transparency log; resolutions logged; federation peers | mis-resolution; needs audits and witnesses (§16) |
| Registry outage | `LOOKUP_FAILED` → `deferred` | availability engineering |
| Stolen bearer API tokens (the Hugging Face route) | agent-bound account access: tokens carry no authority for agents the holder did not approve with a passkey; human path needs a passkey approval; misuse reported at once | tokens on platforms that have not adopted this |
| Agents posing as humans | human path requires the account holder's passkey for the exact request | a compromised device holding the passkey; stolen session cookies |
| Consent phishing (holder tricked into approving an agent) | approval request shows who stands behind the agent; challenge commits to the details | trusted approval UI (SPC-style) not yet defined |
| Software authenticators faking user verification | attestation at registration (optional) | consumer synced passkeys rarely attest |

---

## 14. Conformance

An implementation claims the classes it implements. The simulator's expectations and the tests are an executable test suite for this profile (`npm test`). Each point names the paper requirement it carries out; points with none are this profile's extensions (§3.2).

### 14.1 Registry

A conforming registry MUST:

- **R1** register agents only into chains ending in a principal verified by a federation verifier, and record the chain (PV-1, AG-2, AG-3);
- **R2** issue IDs that name it, carry exactly one principal–agent relationship (new on transfer), and cannot be correlated across RPs by anything presented; mark PPIDs as such and issue at most one per agent and RP (PR-1, PR-7, PR-8);
- **R3** resolve IDs to the principal accountable at the time, only under consent or a valid legal order, and log every resolution (ES-1);
- **R4** publish machine-readable status computed along the whole chain (including expiry and peers), and propagate revocation within a published interval (PR-3, RV-2);
- **R5** retain records after revocation, expiry or transfer (RV-1, ES-1);
- **R6** accredit record keepers by withdrawable trust marks and point only to accredited keepers;
- **R7** keep its state in an append-only, publicly checkable log;
- **R8** relay incident reports without revealing the principal;
- **R9** require both principals' signatures and a fresh agent key for a transfer, and enforce depth budgets and expiry along lineages;
- **R10** keep one principal record per verified identity (PV-3);
- **R11** bind an agent's record to a key only on the agent's own proof of possession, at registration, key replacement and transfer (AG-2, AG-5);
- **R12** make every claim but the ID selectively disclosable, and offer identity claims only to RPs the principal's policy names (PR-1, PR-5, PR-6);
- **R13** revoke on a legal order that carries the revocation scope, and otherwise only as its published practices state (RV-1);
- **R14** publish its practices and keep to them (DR-1, DR-2).

### 14.2 Record keeper

A conforming record keeper MUST:

- **K1** accept only records signed by their source, verifying entitlement;
- **K2** append every record to a Merkle log, return receipts, and serve proofs;
- **K3** (authorization) enforce attenuation, cascading status and chain-version binding; issue only audience-bound, key-bound credentials that never hide limitations (AG-3, PR-4);
- **K4** restrict read access to writers and holders of legal process.

### 14.3 Agent

A conforming agent MUST:

- **A1** present credentials issued for the RP, with key binding and a signed request, using a key used for no other RP (AG-1, PR-2);
- **A2** disclose no more than the request and the principal's policy require (PR-5);
- **A3** log its own account of its actions;
- **A4** prove possession of its key to the registry when it is registered or its key is replaced (AG-2).

### 14.4 Relying party

A conforming RP MUST:

- **P1** verify against the federation (trust chain, trust marks) and check holder binding, using only the presentation and published information, without asking a registry about any one ID (PR-2, PR-9);
- **P2** distinguish the classifications of §10.2 and never treat `UNLABELED` or `LOOKUP_FAILED` as proof that no principal exists;
- **P3** evaluate disclosed authority, including prohibitions, before acting;
- **P4** retain the evidence in §10.4;
- **P5** (services with accounts) SHOULD NOT accept bearer tokens as sufficient authority for agents, and SHOULD bind account access to passkey-approved accountable agents (§10.5);
- **P6** ask the agent, not the registry or the principal, for any further claim its policy needs, and judge a claim only once it is shown (PR-10).

### 14.5 Scenario coverage

| Scenario | Conformance points exercised |
|---|---|
| 1 Payment | R1–R5, R12, K1–K3, A1–A3, P1–P4, P6 (a bank's acceptance criteria) |
| 2 Regulatory filing | K3 (passkey approvals), K4, P3, consent disclosure |
| 3 Hugging Face replay | R3, R8, R13 (revocation under a legal order), K4, P2, P5 (branch C: passkeys prevent the stolen-token attack) |
| 4 Compute pilot | P2 (all six classes), R2 (single-use IDs), R3 (sealed reference) |
| 5 Federation | R2, R4 (cross-registry), K3 (attenuation), R8, P6 (chain-length limit) |
| 6 Audit | R7, K2, R6 |
| 7 Lineages and transfer | R3 (accountability by time), R4 (cascade, expiry), R9, R11, K3 (version binding) |
| `test/paper-requirements.test.js` | R10–R14, A4, P1, P6 |

---

## 15. Reuse of existing specifications

The goal was not to reinvent working wheels. §15.1 accounts for every part. §15.2 says which of the options in the paper's Appendix C this profile chose.

### 15.1 Specifications reused

| Part | Specification | How it is used | Profile-specific additions |
|---|---|---|---|
| Federation membership, trust chains | OpenID Federation 1.0 | trust anchor, Subordinate Statements, Entity Configurations, `authority_hints`, list and fetch endpoints | entity types `aaf_*`; `endpoint_base` for local hosting |
| Accreditation | OpenID Federation trust marks | one trust mark type per record-keeper role; `trust_mark_issuers` in the trust anchor; trust-mark endpoint at registries | trust-mark type names |
| KYC/KYB and attributes | OpenID Connect for Identity Assurance 1.0 | `verified_claims` with `trust_framework`, `assurance_level`, `evidence` | `aaf_kyb`, `aaf_attributes` framework names |
| Credentials | SD-JWT VC; SD-JWT | `dc+sd-jwt`, `vct`, `cnf`, selective disclosure, `kb+jwt` | the claim sets; the rule that limitations are never selectively disclosable |
| Revocation status | IETF Token Status List | `status.status_list`, `statuslist+jwt`, 2-bit entries | status 0x03 = TRANSFERRED |
| Request signing | RFC 9421, RFC 9530; Web Bot Auth pattern | every signed call; agent requests cover the presentation header | `keyid` conventions; `tag` values |
| Authority | RFC 9396 | `authorization_details` with `type` and `actions` | constraint member names; prohibitions in RAR shape |
| Authority exchange, delegation chains | RFC 8693; RFC 7523 | token endpoint; subject and actor tokens; nested `act`; JWT client assertion | token type URIs; pseudonymous `sub` and `act` |
| Human approvals; human path; agent-bound access | W3C WebAuthn Level 3 (passkeys) | registration (`none` attestation), assertions with user verification, challenges committing to the approved details | approval request purposes; `approval_method` claim |
| Bills of materials | CycloneDX 1.6 | full BOM document | incident-response `properties` |
| Encryption, keys, signatures | RFC 7515–7518, 8037, 7638 | throughout | `typ` values for profile artifacts |
| Canonical JSON | RFC 8785 | log leaves, digests | — |
| Logs | RFC 9162 | Merkle trees, inclusion and consistency proofs | receipt and STH JSON |
| **The chain from an agent to a verified principal; IDs and their resolution under escrow; lineages and transfer; legal orders; incident relay** | **none exists** | — | **specified in §§5, 7, 8.2** |

**Not adopted, deliberately:** IETF SCITT for logs (CBOR/COSE; recommended for production) and BBS or other blind credentials for single-use IDs (needs a pairing-cryptography library). See §16.

### 15.2 Options chosen from the paper's Appendix C

| Appendix C section | Option chosen here | Consequence |
|---|---|---|
| 1 Identity proofing | 2 and 3: human and legal-entity proofing, expressed with OpenID Identity Assurance `verified_claims` | no domain- or email-verified principals |
| 2 Authentication | 1: proof of possession of a key (HTTP Message Signatures, SD-JWT key binding) | no hardware-held keys |
| 3 IDs and unlinkable presentations | 1: on-demand issuance, as SD-JWT VCs with selective disclosure by salted hash | the registry learns each credential's RP and time; unlinkable to RPs, not to the registry |
| 4 Authorizations | between 1 and 2: the principal signs a standing grant; an accredited record keeper attests it per RP by token exchange | the record keeper, not the registry, learns the RP; the RP never sees the principal's signature; revoked by the principal |
| 5 Validity and revocation | 1 and 3: short-lived credentials plus a published Token Status List | no per-ID queries; each single-use ID has its own list position |
| 6 Identity escrow | 1 for PPIDs (a map kept by the registry); 2 for single-use IDs (a pointer only the registry can decrypt) | the registry alone can recover identities; no multi-party control |
| 7 Agent PPIDs | 1: derived by the registry from the agent record and the RP's name | the registry learns the RP; no group or principal PPIDs |
| 8 Directory key management | none of the options | keys in files, no hierarchy, no scheduled retirement |
| 9 Arrangements among directories | 1: a trust list (OpenID Federation 1.0) | one trust anchor; no cross-directory duplicate check or audits |

---

## 16. Limitations and open questions

**Not production.** Plain HTTP on localhost (entity identifiers are https URLs mapped to local ports), keys in files, per-process replay caches, an operator bearer token for admin calls, simulated KYC, no rate limiting, and no rotation of service keys. The pilot kit (`docs/DEPLOYING.md`) serves the same services over HTTPS behind a reverse proxy. There, each service verifies request signatures against its published `publicUrl` and blocks `/admin` paths at the proxy. It is meant for a small invited group.

**Design limits to revisit:**

1. **What the registry learns at issuance.** Each credential is issued on demand for a named RP, so the registry learns which RPs an agent deals with and when, and could link a single-use ID's issuance to its use. Status lists already hide checks. Batch issuance of single-use IDs, or anonymous credentials such as BBS, would hide the rest (the paper's Appendix C §3, options 2 and 3; §7, option 2).
2. **SCITT.** Logs use RFC 9162 trees with JSON receipts. A production profile should use SCITT signed statements and COSE receipts, with log witnesses.
3. **One trust anchor.** The paper has principals and counterparties each choosing which directories to trust. Here an RP can restrict which registries it accepts, but every party is configured with a single trust anchor, and credential and trust-mark types are named after it. There is one level of subordinates. Intermediate authorities, metadata policies and trust-mark status endpoints are not implemented. The trust anchor's own statements are not yet rolled over.
4. **Web Bot Auth key directories.** Agent signing keys come from the presented credential, not a published directory. That is right for unlinkability, but a profile of Web Bot Auth should say so.
5. **KB-JWT nonce.** It is agent-generated (with replay caches), not issued by the RP. An RP nonce endpoint would strengthen freshness at the cost of a round trip.
6. **Registry integrity.** Resolution relies on the registry's honesty. This needs audits, witnesses, and possibly threshold resolution keys.
7. **Bidirectional verification.** The protocol can run in reverse, with the merchant's agent presenting to the consumer's agent, but a mutual handshake is not defined.
8. **Clients that do not say they are agents.** Services with accounts now have a passkey human path (§10.5). Services without accounts (anonymous browsing) would need anonymous signals instead: Privacy Pass tokens or personhood credentials (arXiv:2408.07892). These are stronger and more accessible than writing tests or AI-text detection.
9. **Cross-registry transfer** and transfer of a sub-agent out of its lineage are not supported. Moved sub-agents keep their keys unless rotated.
10. **Retention and deletion** (`recordRetentionYears`) are declared but not enforced.
11. **Optional requirements not implemented:** Sybil resistance across directories (PV-4), agents with several principals (AG-4), principal PPIDs and PPIDs shared by a group of RPs (PR-8), multi-party control of escrow (ES-2), conformity assessment (DR-3). Release of identity on the principal's consent for one dispute is also not implemented; consent is given in advance by policy (§7.3).
12. **Kinds of verified identity.** Only natural and legal persons. The paper also describes lower-barrier identities (a domain, an email address) so that verification need not exclude people; this profile does not show them.
13. **The identity key** (§7.2) is weak for natural persons: two people with the same name, jurisdiction and date of birth would collide, and a person can vary their name. It shows where the rule sits, not how a registry should compute it.
14. **Withdrawing one attribute.** A registry cannot withdraw a single attested attribute before it expires; a verifier can only replace it. RV-1 expects single claims to be revocable.
15. **Legal orders are not authenticated as requests.** Anyone holding a valid order can submit it. Orders have an expiry but are not single-use or bound to a registry.
16. **Passkeys in the simulator** come from a software authenticator that produces the browser's wire format but sets "user verified" without a person. The browser demo (`npm run demo`) uses real passkeys. Attestation is not required, and account passkey registration in the demo is open while an account has none (a real service would require a signed-in session).

**Questions for the authors.** Who operates registries and the trust anchor? What assurance levels should sectors require? How long should records be kept, and by whom? Should a transfer's buyer inherit any obligations for pre-transfer conduct? How can costs stay proportionate for individuals and small firms (paper §3.5)? Should a registry be able to compute a PPID that is the same for all of one principal's agents at an RP, so the RP can limit use per principal?

---

## Appendix A: HTTP API reference

### Trust anchor

| Method & path | Purpose |
|---|---|
| `GET /.well-known/openid-federation` | Entity Configuration (policies, `trust_mark_issuers`) |
| `GET /list[?entity_type]` | subordinate entity identifiers |
| `GET /fetch?sub=` | Subordinate Statement |
| `GET /` | dashboard |

### Registry

| Method & path | Auth (RFC 9421 `keyid`) | Purpose |
|---|---|---|
| `GET /.well-known/openid-federation` | — | Entity Configuration |
| `GET /federation/trust-mark?trust_mark_type&sub` | — | current trust mark |
| `GET /status-lists/1` | — | Token Status List |
| `POST /v1/principals` | `jkt:` | enroll |
| `POST /v1/principals/{id}/verification` · `/attributes` | `verifier:` | IDA `verified_claims` |
| `PUT /v1/principals/{id}/disclosure-policy` | `principal:` | consent policy |
| `POST /v1/principals/{id}/notifications` | `principal:` | incidents, resolutions, transfers |
| `POST /v1/registrations` | `principal:` / `registration:` / `jkt:` (remote) | register (with `agent_proof`, `expires_in`, `lineage`) |
| `POST /v1/registrations/{id}/revoke` · `/receipt` · `/rotate-key` | chain above (receipt: also the agent) | revoke; current receipt; new agent key |
| `POST /v1/registrations/{id}/transfer-offers` | `principal:` (direct principal) | offer a transfer |
| `POST /v1/transfer-offers/{id}/accept` · `/cancel` | `principal:` (recipient / offerer) | accept (fresh key) / cancel |
| `POST /v1/attestations` | `registration:` | accountability credential |
| `POST /v1/status` | — | live status with reasons (peers and investigators; not for verifying presentations) |
| `POST /v1/incidents` | `jkt:` (RP) or `registry:` (relay) | incident report |
| `POST /v1/resolutions` | legal order (+ peer forward) | resolution |
| `POST /v1/revocations` | legal order with `revoke_registration` scope | revocation under the order |
| `GET /v1/practices` | — | published practices (§7.14) |
| `POST /v1/federation/status-changed` | `registry:` | peer push |
| `GET /v1/accreditations`, `/v1/transparency/{sth,entries,consistency}`, `/v1/stats`, `/` | — | operations, transparency, dashboard |
| `POST /admin/accreditations` · `/admin/accreditations/{rk}/withdraw` · `/admin/registrations/{id}/revoke` · `/admin/principals/{id}/close` | operator token | issue/withdraw trust marks; operator revocation; close a principal record |

### Record keeper

| Method & path | Auth | Purpose |
|---|---|---|
| `GET /.well-known/openid-federation` · `GET /` | — | Entity Configuration (with trust marks), dashboard |
| `POST /admin/trust-marks` | operator token | install trust marks received |
| `POST /v1/grants` | grant JWS + receipt | deposit grant or designation |
| `POST /v1/grants/{id}/revoke` | `jkt:` (grantor) | revoke |
| `POST /token` | RFC 7523 client assertion | RFC 8693 token exchange |
| `POST /v1/webauthn/registration-options` · `/v1/webauthn/register` | — (WebAuthn ceremony) | register a designee's passkey |
| `POST /v1/approvals/options` · `POST /v1/approvals` | WebAuthn assertion by the designee | passkey approval → approval credential |
| `GET /status-lists/1` · `POST /v1/status` | — | Token Status List; live status |
| `POST /v1/provenance` · `GET /v1/provenance/{id}` | provider-signed · — | CycloneDX provenance |
| `POST /v1/activity` · `POST /v1/activity/query` | writer-signed · `jkt:` (writer or legal order) | activity log |
| `GET /v1/log/{sth,proof,consistency}` | — | log proofs |
| `POST /admin/tamper` | operator token, dev only | simulate a compromised keeper |

### Relying party (generic, simulator)

| Method & path | Purpose |
|---|---|
| `GET /.well-known/aaf-relying-party` | audience id, accepted registries, requests, policy tiers, `webauthn` (if accounts) |
| `POST /actions/{action}` | the transaction (§9.2); optional `AAF-Human-Approval` / `AAF-Approval-Ref` |
| `POST /accounts/{a}/passkeys/options` · `/passkeys` · `GET /accounts/{a}/requests` · `POST /accounts/{a}/human-requests` | account holders' passkeys and pending approvals (§10.5) |
| `POST /approval-requests/{id}/options` · `/approve` · `/decline` | passkey approval ceremonies |

## Appendix B: Example artifacts

`spec/examples/` holds decoded artifacts from a real run (regenerate with `node scripts/examples.js`):

| File | Shows |
|---|---|
| `openid-federation.*` | trust anchor, Subordinate Statement, registry and record-keeper Entity Configurations, trust mark (§6) |
| `oidc-ida.verified-claims.json` | IDA verification of a legal person (§6.3) |
| `registration-receipt.json`, `grant.json` | §7.4, §8.2 (RAR) |
| `accountability-credential.issued.json` / `.as-seen-by-agent.json` | §7.6 |
| `token-exchange.request.json`, `authorization-credential.issued.json` | §8.3 (`act`, pseudonymous `sub`, RAR) |
| `presentation.as-received-by-relying-party.json` | §9.2: RFC 9421 headers, KB-JWTs, what the RP received |
| `status-list-token.registry.json`, `status-list-token.record-keeper.json` | §7.7, §8.7 |
| `activity-receipt.json`, `relying-party-evidence-record.json`, `relying-party-response.json` | §4.5, §10.4, §9.4 |
| `legal-order.json`, `resolution-result.json` | §7.11 |
| `registry-practices.json`, `agent-key-proof.json` | §7.14, §7.4 |
| `provenance-record.cyclonedx.json` | §8.5 |
| `transfer.json` | §7.9 |
| `webauthn.approval-ceremony.json`, `approval-credential.issued.json` | §8.4: options, decoded assertion (flags UP/UV), resulting approval credential |
