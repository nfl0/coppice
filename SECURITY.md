# Security

Coppice is pre-release cryptographic software. It has a production-authoritative
code path, but it has not received an independent security audit and there is
no announced public Coppice Testnet or Mainnet deployment.

## Scope

Security-sensitive areas include:

- CPV1 transport parsing and exact rendezvous receiver binding;
- canonical Zcash/Ironwood effect validation and replay;
- Names commitments, owner authorization, BondProof verification, and state roots;
- rewind, rebuild, and snapshot validation;
- wallet bond inventory, pending registrations, output locks, and protected-spend gates.

The repository does not promise privacy beyond the protocol specification.
Coppice bulletin contents are public to holders of the configured incoming
viewing capability once the transaction is visible, and Names resolution is
not a custodial service. Ordinary Zcash behavior outside Coppice remains the
host wallet's responsibility.

## Reporting a vulnerability

Please do not publish an exploitable vulnerability, private key material, or a
reproducible attack in a public issue. Use GitHub's private vulnerability
reporting flow for the repository when available, or contact the maintainers
through the project page with the subject `Coppice security report`.

Include the affected commit, relevant configuration, a minimal reproduction,
and the expected versus observed behavior. Allow maintainers reasonable time
to investigate and coordinate disclosure. Do not assume that a local
qualification result is an audit or a guarantee for an eventual public
deployment.
