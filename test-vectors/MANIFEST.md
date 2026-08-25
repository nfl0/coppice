# Coppice Core vector manifest

This directory contains generic Core interoperability evidence. The vectors
freeze CoreRuntimeId, CPV1/CA01 framing mechanics, and a Core-only rewind/replay
property. Names-specific operation, bond, carrier-sample, envelope, and state
vectors are owned by `coppice-names/test-vectors/` and are not duplicated here.

Frozen byte values are not regenerated during conformance runs. The Core
protocol specification is authoritative for their meaning; this manifest is
only an inventory and authority boundary.

```text
core_runtime_id.json
core_application_id.json
core_transport.json
replay_reorg.json
```
