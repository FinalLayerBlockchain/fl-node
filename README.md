# Final Layer node (fl-node)

Final Layer is a post-quantum EVM Layer 1. This repository is its node client: a fork of the
[BNB Smart Chain client](https://github.com/bnb-chain/bsc) (bsc-geth v1.8.x, itself a go-ethereum
fork) in which every signature that authorizes value or consensus is a NIST FIPS 204 **ML-DSA-87**
signature. No classical signature (ECDSA, BLS, Ed25519) is accepted for transactions, block seals
or system transactions.

Final Layer previously ran on a java-tron based codebase. That network is retired; this
bsc-geth based client is the only supported Final Layer node.

## Network

| Parameter | Value |
| --- | --- |
| Chain ID | `20261012` |
| Consensus | Parlia (PoSA) with ML-DSA-87 block seals; BLS fast finality disabled |
| Block time | 3 s |
| Block size cap | 1.5 MB (consensus rule) |
| Transaction type | `0x07` (PQ transaction, the only accepted type) |
| PQ key registry | `0x0000000000000000000000000000000000005051` |
| PQ verify precompile | `0x0000000000000000000000000000000000000f01` |
| Native coin | FL, 5,000,000,000 at genesis |
| Staking inflation | minted once per day in the breathe block, paid through StakeHub |

## For auditors

Start here, in this order:

1. [`docs/FINAL-LAYER-CHANGES.md`](docs/FINAL-LAYER-CHANGES.md): every file changed from upstream
   bsc, grouped by subsystem, with what changed and why.
2. The git history. The first commit is the unmodified upstream bsc snapshot
   (`baseline: bsc-master from zip`). Every Final Layer change is a separate commit on top, so
   `git diff <baseline>..HEAD` is the complete Final Layer delta.
3. [`SECURITY.md`](SECURITY.md) for scope, audit reports and vulnerability reporting.

Related repositories:

| Repository | Contents |
| --- | --- |
| [fl-genesis-contracts](https://github.com/FinalLayerBlockchain/fl-genesis-contracts) | System contracts (StakeHub, validator set, governance) |
| [fl-network](https://github.com/FinalLayerBlockchain/fl-network) | Genesis, node service files, Docker image, build and devnet scripts |
| [fl-wallet](https://github.com/FinalLayerBlockchain/fl-wallet) | ML-DSA-87 browser extension and web wallet |
| [fl-explorer](https://github.com/FinalLayerBlockchain/fl-explorer) | Block explorer |
| [finalswap-contracts](https://github.com/FinalLayerBlockchain/finalswap-contracts) | FinalSwap (Uniswap V2) deployment |

## Build

```shell
make geth             # node
go build ./cmd/flpq   # PQ key and transaction tool
```

Requires Go 1.25 or newer and a C compiler. Final Layer tests (the same set CI runs):

```shell
build/finallayer/test.sh
```

## Upstream

Everything not listed in the change map is upstream bsc code. The upstream README is kept as
[`README.bsc.md`](README.bsc.md). License: LGPL-3.0 for the library code and GPL-3.0 for the
binaries, as upstream (see `COPYING` and `COPYING.LESSER`).
