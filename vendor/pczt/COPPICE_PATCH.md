# Coppice PCZT compatibility copy

This is the published `pczt` 0.9.3 source. Coppice's self-contained real-transaction carrier tests
use its Ironwood `zcp-builder` effecting-data API, while `coppice-cli` uses the ordinary PCZT API
from upstream librustzcash revision `6c07e5f`.

The only source adjustment is lowering the two `zcash_protocol` dependency requirements from
0.10.4 to the API-compatible 0.10.3 used at that wallet revision. The wire format and transaction
consensus behavior are unchanged. The wallet does not depend on this compatibility copy.
