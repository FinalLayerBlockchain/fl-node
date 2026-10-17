# Security Policy

## Supported versions

Only the latest commit on `master` and the latest [release](../../releases) are supported. Final
Layer chain ID `20261012` runs this client exclusively; the earlier java-tron based Final Layer
network is retired and its code is not supported.

## Scope

In scope: everything listed in [`docs/FINAL-LAYER-CHANGES.md`](docs/FINAL-LAYER-CHANGES.md), and
any upstream bsc or go-ethereum code whose behavior those changes affect (signature handling,
transaction validation, Parlia consensus, block import, the txpool, precompiles, and consensus
reads of system contracts).

Of most interest:

- forging or replaying an ML-DSA-87 authorization for a transaction, block seal, key rotation or
  system transaction
- producing a block that some nodes accept and others reject (consensus split)
- halting block production or the daily breathe block
- minting or redirecting staking inflation
- bypassing the key registry or the 1.5 MB block size cap
- reviving any classical signature path (ecrecover, BLS, builder bids)

## Audit reports

| Scope | Date | Auditor | Report |
| --- | --- | --- | --- |
| Final Layer changes | none yet | | No third-party audit has been completed. |

Reports will be published in [`docs/audits/`](docs/audits) as `YYYY-MM-DD_<scope>_<auditor>.pdf`.
Upstream go-ethereum audits already in that folder cover upstream code only.

## Reporting a vulnerability

**Do not open a public issue.** Report privately through GitHub:
**Security → Report a vulnerability** on this repository. Include the affected commit, a
description, and a reproduction (a failing test is ideal).

Published advisories are listed under [Security advisories](../../security/advisories).
