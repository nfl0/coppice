# Proposal: Narrow, Application-Blind Generalization of Coppice

- **Status:** Design proposal; no implementation is authorized by this document
- **Date:** 2026-08-29
- **Scope:** Coppice Core and optional application-support utilities
- **Primary constraint:** The corrected Names v2 architecture and its release artifacts remain unchanged

## 1. Executive summary

Coppice already has a useful application boundary: Zcash consensus determines the canonical Ironwood history, while Coppice Core exposes ordered, validated context to an application without interpreting that application's state machine. Names v2 demonstrates several implementation patterns that may eventually be useful to another application, but it does not justify moving Names semantics into Core or creating a second consensus layer.

This proposal recommends a deliberately narrow generalization strategy:

1. Keep Coppice Core application-blind, proof-system agnostic, and responsible only for canonical source handling, replay composition, acquisition, routing, and lifecycle mechanics.
2. Keep Names-specific policy, state transitions, proof meaning, and historical applicability in `coppice-names`.
3. Extract a small, optional application-support layer only when a second independent application demonstrates the same need.
4. Make any extraction additive and prove parity with the existing Names fresh-resolution and full-replay paths before adopting it.

The intended result is reusable infrastructure without moving application authority into the wrong layer.

## 2. Motivation and problem statement

Names v2 contains reusable mechanics around authenticated producer positions, hidden state-note lineages, canonical-spend observation, bounded replay, and the distinction between an untrusted claim and a corrupted canonical source. Those mechanics are valuable, but their surrounding rules are not generic:

- a Names `COMMIT` and `REVEAL` have a protocol-specific relationship;
- lease, schedule, claimability, abandonment, reset, and terminal status are Names policy;
- UPDATE, RENEW, RELEASE, and replacement legality are proved by Names circuits;
- FreshResolver decides historical Names applicability, not proof validity alone.

Moving those rules into Core would make Core a second application consensus engine and would blur the accepted proof boundary. Conversely, duplicating generic canonical-history handling in every application would create inconsistent reorg, source-integrity, and replay behavior.

The design question is therefore not “How do we put Names into Core?” It is:

> Which proof-independent mechanics can be shared without making Coppice Core understand application payloads or application semantics?

## 3. Goals

This proposal aims to:

- identify a small set of reusable, proof-independent runtime mechanics;
- preserve Zcash consensus as the sole authority for canonical ordering and fork choice;
- preserve the current Names ZK/runtime boundary;
- provide a path for a future second application without speculative APIs;
- make source-integrity failures and untrusted application claims observably distinct;
- preserve equivalence between bounded fresh resolution and complete replay;
- reduce duplicated canonical-history code only where the abstraction is demonstrated by independent use.

## 4. Non-goals and explicit prohibitions

This proposal does **not** authorize:

- moving UPDATE, RENEW, RELEASE, registration, lease, schedule, replacement, reset, abandonment, or terminal semantics into Coppice Core;
- moving historical applicability into Names ZK or removing it from the runtime;
- a global Names index, global state root, sequencer, trusted snapshot, provider, gateway, or custom-node assumption;
- recursive history proofs, transparent state outputs, or a second consensus mechanism;
- TRANSFER or another new v2 operation;
- a universal proof verifier, proof registry, WASM/contract runtime, gas model, or parallel-execution model;
- changing frozen v1 behavior, corrected Names v2 circuit semantics, protocol bytes, verification-key identities, or wire vectors as part of this design exercise;
- a migration or re-registration requirement for existing Names state;
- extracting an abstraction merely because two functions have similar names.

The corrected Names v2 implementation remains the immediate release baseline. Any future generalization must be evaluated after, and independently of, final VK/wire regeneration and live qualification.

## 5. Authority and trust boundaries

The following ownership is normative for this proposal.

| Layer | Owns | Must not own |
| --- | --- | --- |
| **Zcash consensus** | Ironwood Action validity, spend authorization, canonical transaction/block ordering, and fork choice | Names applicability or Names state transitions |
| **Coppice Core** | Canonical source validation, ordered replay context, transaction/action effects, application routing and activation, acquisition/composition, retention, and rewind mechanics | Application payload parsing, Names state, proof meaning, lease policy, or a second fork-choice rule |
| **Optional application-support layer** | Reusable data types and helpers for canonical producer positions, bounded lineage traversal, authenticated spend observation, and source-vs-claim result handling | Consensus, proof verification, application policy, global application state, or canonical applicability |
| **Application (`coppice-names`, or a future peer)** | Application identifiers and encoding, proof verification and public-input construction, state transitions, head applicability, replacement/claimability/reset history, abandonment interpretation, and application persistence | Reimplementing consensus ordering or silently treating a proof-valid object as canonically applicable |

Core already exposes generic application contexts and ordered canonical Ironwood effects. A proposed helper must reuse those APIs or fill a demonstrated gap; it must not create a parallel source of canonical truth.

## 6. Candidate reusable abstractions

These are candidates for future extraction, not committed APIs. Each one requires an independent consumer and parity evidence before implementation.

### 6.1 Canonical producer/action provenance

Applications often need to identify the exact canonical producer of an action. A proof-independent representation could contain:

- block height and, where available, canonical block identity;
- transaction index and canonical transaction identifier;
- Ironwood action index.

The representation must compare the complete canonical position, not just a commitment, nullifier, or transaction identifier. It must use the repository's canonical transaction-id byte order and checked integer conversions.

The application may additionally need an `operation_index` inside its own payload. That field belongs to the application-facing layer unless Core can expose it without parsing application bytes. A Core action reference must not accidentally become a Names operation reference.

Names `StateRef` and `CommitRef` remain application-level wrappers. In particular, exact accepted-COMMIT authentication still requires the claimed position to identify the accepted COMMIT operation at its canonical producer position; matching commitment bytes elsewhere are insufficient.

### 6.2 Canonical spend observation

Core already exposes ordered authenticated effects. An optional helper could provide a deterministic way to observe whether a canonical action spends a supplied nullifier (or set of nullifiers), including the relevant action position.

The helper must not decide what the spend means. The application decides whether the observed spend replaces a head, abandons a lineage, consumes a claim, or is unrelated. There must be no global nullifier index or application-independent “current object” authority introduced by this utility.

### 6.3 Bounded lineage traversal and replay support

A generic traversal engine could walk application-provided predecessor references over a bounded canonical range while providing:

- explicit lower and upper bounds;
- cycle detection and depth/step limits;
- canonical source continuity checks;
- deterministic handling of cache hits and misses;
- reorg- or snapshot-scoped cache invalidation.

The application supplies reference extraction, accepted-operation predicates, and the meaning of a valid head. The engine may report that a claim is unauthenticated or that a canonical source is unavailable/corrupt, but it must not choose the application's current head or applicability policy.

This utility must not become recursive history proof verification or a trusted checkpoint mechanism. A bounded bootstrap is an optimization over canonical history, not a new authority.

### 6.4 Claim-versus-source result taxonomy

Reference-heavy applications need a stable distinction between adversarial bytes and canonical-source failures. A future shared result type may use names such as:

- `Authenticated` — the claim identifies the expected accepted canonical operation;
- `UnauthenticatedClaim` — the operation's reference is forged, out of range, mismatched, or otherwise not an accepted operation;
- `SourceFailure` — a block or transaction genuinely required within the canonical authentication range is missing, malformed, or chain-inconsistent.

The exact Rust names are open. The semantic rule is not:

- an untrusted claim is an ordinary rejected operation and must not poison resolution;
- a canonical source failure is a fatal resolver/replay error and must not be silently downgraded to rejection.

Core should not adopt the Names `ResolveError` hierarchy. It may expose a proof-independent source/claim outcome only if doing so does not force Core to understand application references.

### 6.5 Replay, retention, and cache mechanics

If a second application needs them, small helpers may centralize deterministic replay-window calculation, retention bounds, and cache scoping. Cache keys and lifetimes must include the canonical snapshot/branch context needed to prevent cross-reorg contamination. A cache is an acceleration layer, never evidence of canonical applicability.

## 7. Deliberate non-generalization: Names remains the authority

The following stay in `coppice-names`:

- name normalization, name identifiers, and application encoding;
- `RegistrationIntent` and the COMMIT → REVEAL protocol;
- lease, schedule, maturity, TTL, claimability, reuse, reset, and terminal-status rules;
- UPDATE, RENEW, RELEASE, and replacement legality;
- owner/recipient continuity and application state-note contents;
- Names proof circuits, public-input construction, schedule predicates, successor CMX/opening binding, successor owner/recipient binding, successor future-nullifier binding, and hidden-bond policy;
- `StateRef`, `CommitRef`, exact operation authentication, and Names-specific error interpretation;
- FreshResolver anchor selection, bounded discovery policy, abandonment interpretation, competing-child handling, stale recovery, and application persistence;
- record/state digests, wallet/prover policy, and Names vectors.

These rules may use generic Core context and effects, but their meaning remains application authority. A generic type must not be allowed to smuggle any of them back into Core.

## 8. Proposed package and API placement

The preferred near-term action is to reuse the existing `coppice-core` APIs and make no new package. If a second application independently requires shared helpers, evaluate a narrowly scoped package such as `coppice-app-support` (name provisional) with these properties:

- depends on `coppice-core`, not on `coppice-names`, Orchard, or a particular proof system;
- contains data types and deterministic mechanics only;
- has no global mutable application registry or hidden network dependency;
- does not duplicate `ApplicationTransactionContext`, ordered effect types, or other existing Core APIs;
- documents which results are ordinary claim rejection and which are fatal source failures;
- remains optional for applications whose state model does not need it.

The package boundary is less important than preserving the authority boundary. A helper belongs in Core only when it is genuinely consensus-context plumbing. A helper belongs above Core when it interprets application references or state.

## 9. Migration and review gates

### Phase 0 — inventory (design only)

Document existing Core APIs and Names call sites, identify duplicated mechanics, and verify that the proposed extraction would remove real duplication. Do not change protocol code or release artifacts.

### Phase 1 — independent second consumer

Require a second application with a materially similar need. A hypothetical future application or a renamed Names call site is not sufficient evidence.

### Phase 2 — smallest additive extraction

Extract only the mechanic shared by both consumers. Preserve existing Names behavior and keep application-specific wrappers at the application boundary. Avoid compatibility shims that duplicate canonical logic.

### Phase 3 — parity and adversarial evidence

The extraction must include cheap deterministic tests covering, as applicable:

- FreshResolver/full-replay parity;
- forged, out-of-range, and wrong-position references as nonfatal rejected claims;
- missing, malformed, and chain-inconsistent canonical sources as fatal errors;
- exact action/transaction ordering and canonical identifier normalization;
- competing spends, stale heads, reset boundaries, abandonment, and reorg-scoped cache behavior;
- cycle and bound handling in lineage traversal.

### Phase 4 — adoption review

Accept the abstraction only if it has two independent consumers, reduces semantic duplication, introduces no new authority, and leaves the dependency graph proof- and application-agnostic. Deprecation or relocation of existing code requires a separate review with an explicit parity record.

## 10. Acceptance criteria

The proposal is successful only if a future implementation can demonstrate all of the following:

1. Coppice Core remains unaware of Names payloads, Names state, and proof semantics.
2. Zcash consensus remains the sole authority for canonical ordering and fork choice.
3. Names ZK remains the authority for local transition validity; runtime remains the authority for canonical applicability and history.
4. Exact canonical producer/action authentication is preserved.
5. Untrusted operation claims cannot turn a valid canonical resolution into a fatal source error.
6. Genuine canonical-source corruption cannot be silently converted into an ordinary rejected application operation.
7. Fresh resolution and complete replay agree for accepted and rejected operations, subject to explicitly documented bounded-discovery limits and post-action parity checks.
8. Reorgs, caches, cycles, bounds, and missing sources have deterministic behavior.
9. No global application root, trusted snapshot, provider dependency, custom-node assumption, or second consensus mechanism is introduced.
10. The change is additive, documented, and covered by focused tests before any expensive proving or live qualification.

## 11. Risks and open questions

- **Existing API overlap:** Core already carries much of the canonical transaction/action context. The first task for any implementation is to prove that a new provenance type is not a duplicate.
- **Operation granularity:** `action_index` is consensus-facing; an application-defined `operation_index` may not be. Combining them prematurely could reintroduce payload knowledge into Core.
- **Cache invalidation:** A cache that survives a canonical reorg can create false applicability. Snapshot/branch scoping must be explicit and tested.
- **Error naming:** Shared error names must communicate whether a result is an ordinary rejected claim or a fatal source-integrity failure without importing Names semantics into Core.
- **Abstraction timing:** Extracting before a second consumer exists is likely to freeze the wrong API and create more code than it removes.

## 12. Decision requested

Approve this as a design direction, not as an immediate refactor. Continue with the corrected Names v2 release-finalization work independently. Revisit implementation only when a second application supplies a concrete, independently validated use case and the migration gates above can be met.

Any resulting pull request should be additive, preserve the authority table in Section 5, include focused parity/adversarial evidence, and explicitly state which mechanics were generalized and which Names rules were intentionally left in the application.
