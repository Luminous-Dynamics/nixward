# Witness Trust-Domain Independence and Common-Cause Analysis v0.1

**Status:** Research and protocol design. This document specifies an evidence model and deterministic analysis target. It does not establish that any deployed witness operators are independent, and it does not change the current 3-of-4 admission implementation.

**Related:** Nixward issue [#173](https://github.com/Luminous-Dynamics/nixward/issues/173), cross-client gossip [#171](https://github.com/Luminous-Dynamics/nixward/issues/171), receipt-v2 binding [#172](https://github.com/Luminous-Dynamics/nixward/issues/172), and Platform evaluator-owned runner [#540](https://github.com/Luminous-Dynamics/luminous-platform/issues/540).

## 1. Problem statement

The high-assurance witness profile requires three endorsements from four provisioned trust domains. Its quorum-intersection argument is:

\[
|Q_1 \cap Q_2| \ge 3 + 3 - 4 = 2
\]

If at most one witness is Byzantine, at least one member of the intersection is honest. That honest witness must durably refuse to endorse conflicting checkpoint digests for the same observer parent and sequence.

The mathematical result is sound under its stated assumptions. The operational question is whether four configured witness identities actually represent four independent failure domains.

The current `TrustedOciWitnessKey.trust_domain_id` is an operator-assigned assertion. The verifier rejects duplicate witness IDs and duplicate trust-domain strings, but different labels do not prove independent control of:
- privileged administration and recovery credentials;
- identity providers and root authorization;
- cloud accounts, control planes and regions;
- KMS/HSM key custody and signing services;
- append-only storage, backup and restore;
- build, deployment, update and software supply chain;
- monitoring and network dependencies.

Two witnesses with different IDs, keys and trust-domain labels can still be compromised by one shared administrator, signing service, recovery principal or release pipeline. In that case, the assumed one-Byzantine-witness bound is not justified.

**Research thesis:** qualify witness independence as an explicit, freshness-bounded, evidence-carrying dependency model. A quorum may be cryptographically valid while its operational independence remains unknown or unqualified.

## 2. Separate integrity compromise from availability

Do not conflate every shared dependency with Byzantine control.

| Dependency class | Example | Primary consequence |
|---|---|---|
| Integrity authority | Privileged operator, root identity provider, KMS/HSM administrator, signing service, trust-registry administrator | May control or forge multiple witness decisions |
| Log integrity / rollback | Shared database administrator, backup/restore principal, append-only storage controller | May rewrite, roll back or suppress multiple witness histories |
| Software integrity | Shared build, release, deployment or update authority | May install malicious code across witnesses |
| Availability | Shared region, network transit, DNS resolver, power or hosting service | May make multiple witnesses unavailable without being able to forge their signatures |
| Observation | Shared collector, relay or monitoring plane | May hide or delay evidence without necessarily controlling witness signing |

A shared availability dependency is a correlated outage, not automatically a Byzantine signer. It must affect availability analysis, but must not be counted as a cryptographic integrity compromise unless its authority also reaches a signing, log-integrity or trust-registry asset.

The reverse distinction matters too: separate cloud regions do not establish signing independence when one operator or root account administers all regions.

## 3. Evidence model

Introduce a versioned, canonical witness-dependency manifest. The manifest is authorized by a trust root outside the four counted witnesses and is bound to the exact roster used for quorum verification.

The manifest should contain:

### 3.1 Roster binding

For every witness:
- `witness_id`;
- `trust_domain_id`;
- `key_id` and key generation;
- exact public-key fingerprint;
- witness protocol profile and validity interval.

The roster digest must commit to the sorted canonical entries. A manifest for a prior key generation, a different public key, or a different witness set must not qualify the current quorum.

### 3.2 Dependency nodes and control edges

Represent the dependency model as a directed graph:
- nodes are stable, privacy-minimal dependency identities or protected assets;
- edges mean that control of one node can control, administer, replace, recover or suppress another;
- witness assets include key custody/signing authority, log integrity, trust-registry authority, deployment/update authority, and recovery/rollback authority;
- root dependencies are the independently controlled principals or systems at which the declared control graph terminates.

Dependency categories are typed, not inferred from free-form labels. The initial vocabulary should include:
- administrative/operator root;
- cloud account and control plane;
- identity provider and recovery authority;
- KMS/HSM and signing service;
- log storage and backup/restore;
- build provenance, deployment and update authority;
- network transit and DNS;
- monitor and gossip relay.

For public fixtures, use synthetic IDs. Real operator identities, account numbers, key handles and topology are private deployment data and must not be published.

### 3.3 Evidence provenance

Each node/edge assertion carries:
- a domain-separated stable dependency digest;
- category and compromise effect;
- exact scope and affected witness/assets;
- evidence digest and evidence version;
- issuer/assurance class;
- issued-at and expiry;
- supersession or revocation reference where applicable.

Use explicit assurance classes:
1. `owner_asserted`: a configuration declaration, useful for inventory but not independent evidence;
2. `provider_attested`: supported by a provider-controlled identity or service attestation;
3. `independently_audited`: reviewed by an independent authority under a documented scope and validity period.

The verifier must never silently promote a self-declared relationship to independently audited evidence. The assurance class and issuer must be visible in the resulting report.

### 3.4 Completeness

A manifest must declare which critical dependency categories are in scope and which are unavailable or unknown. Absence of a dependency record is not evidence that the dependency does not exist.

Missing, expired, unverified, contradictory or out-of-scope evidence produces `INDEPENDENCE_UNKNOWN` or `INDEPENDENCE_UNQUALIFIED`. It must never produce a positive independence result by default.

## 4. Deterministic common-cause analysis

Let the counted witness set be \(W = \{w_1,w_2,w_3,w_4\}\).

Let \(R_I\) be the set of declared root dependencies whose compromise can affect witness signing, log integrity, trust-registry integrity, deployment/update integrity, or recovery/rollback authority.

For each root \(r \in R_I\), compute the set of witnesses whose critical assets are reachable from that root in the declared control graph:

\[
C(r) = \{w \in W : r \leadsto A_I(w)\}
\]

where \(A_I(w)\) is the set of integrity-critical assets belonging to witness \(w\), and \(\leadsto\) is transitive control reachability.

The primary one-fault independence gate is:

\[
\forall r \in R_I, \quad |C(r)| \le 1
\]

Any single integrity root that can control two or more counted witnesses invalidates the claimed at-most-one-Byzantine profile.

Also report the minimum root-fault cut size:

\[
k^* = \min_{F \subseteq R_I}
\left\{
|F| : \left|\bigcup_{r \in F} C(r)\right| \ge 2
\right\}
\]

For a complete model in which each witness has an individually compromisable root, \(k^*=1\) means one common-cause event can control at least two witnesses; \(k^*=2\) means at least two distinct root compromises are required to control two witnesses under this model. If the graph is incomplete, do not interpret a large or infinite result as safety: report UNKNOWN.

This cut size is a model result, not a probability. Do not multiply vendor failure probabilities as if they were independent without evidence supporting that assumption.

Compute availability roots separately. Report:
- the number of witnesses affected by each availability root;
- whether at least three witnesses remain available;
- whether read-only operation can continue;
- the expected safe-denial/reconciliation behavior when fewer than three witnesses are available.

A common transit network may reduce availability while leaving cryptographic independence intact. A shared root administrator that can export or replace two signing keys is an integrity common cause, regardless of network separation.

## 5. Admission semantics

Use explicit outcomes:

- `INDEPENDENCE_QUALIFIED_WITHIN_DECLARED_MODEL`: current roster and required dependency evidence are complete, authorized, fresh, and no single declared integrity root reaches more than one witness's critical assets.
- `INDEPENDENCE_UNQUALIFIED`: evidence positively identifies a shared integrity root affecting two or more witnesses, or a declared policy requirement is violated.
- `INDEPENDENCE_UNKNOWN`: required dependencies, evidence, issuer trust, graph closure or freshness cannot be established.

Only the first state may satisfy the independence prerequisite for the high-assurance profile, and only at the assurance level required by the deployment policy. An owner-asserted manifest can qualify the structure of a *declared model* but cannot be reported as an independently audited operational fact.

The 3-of-4 threshold remains unchanged. The analyzer must not:
- silently lower the threshold;
- count two labels for one common control plane as independent witnesses;
- mark a missing dependency as independent;
- clear historical equivocation or common-cause evidence after key rotation;
- transform a signed checkpoint, tree-head or receipt into proof of kernel truth or runtime enforcement.

### 5.1 Bind the analyzed model to the quorum evidence

The verified independence result must carry the exact manifest digest, policy version, roster digest and evidence-set digest. The finalizer must check that the result refers to the exact witness identities, public-key bytes and generations used by the 3-of-4 receipt/branch quorum.

Persist the manifest and analysis digests with the exact receipt and branch-endorsement bytes. This preserves the answer to: "Under which independence model was this checkpoint admitted?"

A refreshed manifest does not retroactively change the model used for historical admission. New admissions use the current authorized manifest; historical audit retains the exact old manifest and its status.

## 6. Synthetic negative-control matrix

| ID | Fixture | Required result |
|---|---|---|
| WIA-01 | Four unique labels; one KMS root controls two signing keys | Unqualified |
| WIA-02 | Distinct KMS keys; one privileged operator/recovery root controls both | Unqualified |
| WIA-03 | Shared cloud provider, distinct accounts; isolation evidence incomplete | Unknown, not assumed independent |
| WIA-04 | Shared transit network only; no integrity edge | Integrity independence may pass; availability risk is reported |
| WIA-05 | Shared build/deploy/update root reaches multiple witnesses | Unqualified |
| WIA-06 | Dependency manifest omits a required category | Unknown |
| WIA-07 | Expired or revoked independent-audit evidence | Unknown |
| WIA-08 | Manifest roster uses the right key ID/generation but substituted public-key bytes | Reject |
| WIA-09 | Manifest digest, root identity or issuer is substituted | Reject |
| WIA-10 | Transitive control edge reaches a second witness through an intermediate service | Unqualified |
| WIA-11 | Dependency graph contains a cycle or ambiguous alias | Reject as malformed/unknown |
| WIA-12 | Reordering entries or duplicating an identical assertion | Canonical result remains deterministic; duplicates are handled explicitly |
| WIA-13 | Key rotation changes fingerprint but manifest is not refreshed | Unknown/unqualified for new admission |
| WIA-14 | Historical manifest is restored after a newer revocation/rotation | Reject for new admission; retain for audit |
| WIA-15 | Two witnesses unavailable, while read-only authority remains valid | Read-only may continue; consequential mutation waits |
| WIA-16 | One witness unavailable and a common root compromises two of the remaining three | Independence profile fails; do not admit merely because three signatures exist |

## 7. Integration plan

1. Define the manifest schema, canonical encoding and owner/auditor trust-root contract.
2. Implement a pure deterministic dependency-closure and common-cause analyzer using bounded graph input and explicit resource limits.
3. Return an opaque verified independence token bound to the roster, exact public-key fingerprints, manifest digest and analysis policy.
4. Add an explicit high-assurance quorum-verification path that requires the independence token. Keep any lower-assurance/legacy verifier clearly labelled and unable to reach the 3-of-4 consequential finalizer.
5. Bind and persist the exact manifest/analysis digests with final receipt-v2 and branch-endorsement evidence.
6. Add unit, property, malformed-graph and substitution tests, then exact-head Rust/Nix qualification.
7. Add synthetic WIA cases to ATR only after the evaluator-owned episode runner in Platform issue #540 can execute fixtures and retain independent outcome receipts.
8. Qualify actual operational independence separately through deployment evidence and independent review. A passing graph unit test is not an audit of real operators.

## 8. Benchmarks and reporting

Report, per exact roster and manifest:
- witness count and required threshold;
- distinct identity and trust-domain-label counts;
- critical dependency coverage and evidence assurance level;
- integrity root count and maximum witnesses affected by one root;
- minimum root-fault cut size \(k^*\);
- availability root overlap and reachable quorum under each outage;
- manifest age, evidence expiry and revocation propagation latency;
- analysis runtime, graph size, and deterministic output digest;
- false-qualified and false-unqualified rates against evaluator-private synthetic ground truth.

Hard gates:
- zero high-assurance qualifications when a manifested integrity root controls two or more counted witnesses;
- zero positive qualifications with incomplete/stale required evidence;
- 100% detection of the enumerated synthetic shared-root and transitive-control fixtures;
- zero conflation of availability-only faults with signing compromise;
- zero silent threshold downgrade;
- exact manifest/analysis digest reproducibility.

Do not claim independence from a source-level test count or schema pass. Report source implementation, compiled/tested analysis, independently reviewed deployment evidence, and production operation as separate stages.

## 9. Research references

- RFC 9162 §11.3 describes clients comparing signed tree heads ("gossip") to detect conflicting log views, while noting that gossip itself is not specified by the RFC: https://www.rfc-editor.org/rfc/rfc9162.html
- Google Trillian documents Merkle-log personalities and inclusion/consistency proofs: https://google.github.io/trillian/
- Sigstore transparency architecture and threat model provide relevant monitor and log-trust precedents: https://github.com/sigstore/architecture-docs
- IETF RFC 9334 defines the Attester / Verifier / Relying Party separation; trust appraisal remains distinct from signature verification: https://www.rfc-editor.org/rfc/rfc9334.html

These references motivate the trust separation; none proves the independence of a particular Nixward witness deployment.
