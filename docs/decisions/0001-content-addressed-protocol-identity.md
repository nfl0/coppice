# ADR 0001: Content-addressed Core and application identity

Status: Accepted for the undeployed Core protocol

Date: 2026-09-04

## Context

Core previously stacked several sequential labels over the same compatibility
boundary: a runtime protocol version, the `CPV1` carrier name, the `CA01`
envelope name, and an application `version: u16` beside `ApplicationId`. That
made it unclear which value selected the authoritative decoder and allowed a
nominal application family and version to cover multiple semantic deployments.

Core and its current applications are undeployed, so there is no canonical
history or released client that requires compatibility with those bytes.

## Decision

Core uses content-addressed identity instead of sequential protocol versions.
The canonical machine-readable manifest `ruleset/core.json` freezes semantic
clauses and wire constants. Its personalized BLAKE2b-256 fingerprint is bound
into every `CoreRuntimeId` together with the network, activation, and exact
rendezvous configuration.

The stable carrier and application-envelope domain markers are `CPCF` and
`CAPP`. They are fixed recognition bytes, not version counters. The application
envelope contains one 32-byte `ApplicationId` and no secondary version field.
Every application ID must select exactly one immutable decoder and semantic
deployment. An incompatible Core or application change therefore changes its
content-addressed identity instead of incrementing a global version number.

Local replay, application, reducer, resolver, and wallet snapshots retain
independent schema identifiers. Persisted local bytes can outlive the process
that created them and may require explicit migration or safe rejection; they
are not protocol-generation labels and are not authoritative chain state.

## Consequences

- Core routing has one authority instead of an `(ID, version)` pair.
- The envelope header shrinks from 38 to 36 bytes and its maximum payload grows
  from 16,055 to 16,057 bytes.
- Core runtime identities, carrier bytes, application identities, downstream
  deployment identities, proofs, and conformance vectors must be regenerated.
- Unknown identities fail closed. Existing identifiers must never be
  reinterpreted to mean new bytes or semantics.
- Future protocol changes update the applicable canonical manifest and receive
  new content-derived identities; no `v2` or `v3` compatibility vocabulary is
  required.

## Rejected alternatives

- **Keep sequential versions beside content hashes:** duplicates authority and
  permits disagreement about which identifier defines compatibility.
- **Use a fixed family-only application ID:** cannot safely select between
  incompatible deployments before application decoding.
- **Remove snapshot schema identifiers:** would make persisted-state migration
  and fail-closed rejection ambiguous.
