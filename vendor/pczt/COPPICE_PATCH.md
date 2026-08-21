# Coppice PCZT compatibility copy

This is the published `pczt` 0.9.3 source. Coppice needs its `zcp-builder` effecting-data API for
pre-authorization memo grinding, while the current public testnet `coppice-cli` wallet remains
on librustzcash revision `6c07e5f` and PCZT 0.9.1.

The only source adjustment is lowering the two `zcash_protocol` dependency requirements from
0.10.4 to the API-compatible 0.10.3 used at that wallet revision. The wire format and transaction
consensus behavior are unchanged. The wallet crosses this temporary library-version boundary only
through serialized PCZT bytes.
