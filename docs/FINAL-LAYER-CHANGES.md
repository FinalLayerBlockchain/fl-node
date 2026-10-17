# Final Layer changes to upstream bsc

This is the map of every file Final Layer changed in the upstream
[bnb-chain/bsc](https://github.com/bnb-chain/bsc) client. All other files are unmodified upstream
code. To see the full delta:

```shell
BASE=$(git rev-list --max-parents=0 HEAD)
git diff --stat $BASE HEAD
git diff $BASE HEAD -- <path>
```

68 files changed, about 4,750 lines added and 250 removed (tests included).

## Threat model in one paragraph

A quantum adversary able to break ECDSA, BLS or Ed25519 must not be able to move funds, produce
or finalize blocks, or forge system transactions. So every signature that authorizes value or
consensus is ML-DSA-87 (FIPS 204), each one bound to a purpose-specific context string
(transaction, seal, key rotation, contract verify). Classical signature paths are disabled, not
just unused. Accounts keep their address when they rotate to a new PQ key.

## 1. Post-quantum signatures

| File | Change |
| --- | --- |
| `crypto/pq/pq.go` | ML-DSA-87 keys, signing and verification (cloudflare/circl), scheme identifier byte for algorithm agility, per-purpose contexts, validator proof of possession, key registry address and storage layout |
| `crypto/pq/pq_test.go` | Vectors, context separation, wrong-scheme and malformed-input rejection |
| `go.mod`, `go.sum` | Adds `github.com/cloudflare/circl` |

## 2. Transactions

| File | Change |
| --- | --- |
| `core/types/tx_pq.go` | New transaction type `0x07`: fields, PQ public key and signature, signing hash |
| `core/types/transaction_signing.go` | Every signer accepts only PQ transactions; classical transactions are rejected |
| `core/types/transaction.go`, `transaction_marshalling.go` | Type registration, JSON encoding of the PQ fields |
| `core/types/receipt.go` | PQ receipts encode their full contents, so receipt roots are stable when rebuilt from the database |
| `core/types/block.go` | Header extra-data seal size is the ML-DSA seal size (`pq.SealSize`) instead of 65 bytes |
| `core/types/builder/bid.go` | Builder bids are ECDSA-authorized, so every bid is rejected |
| `core/pq_auth.go` | Authorization: the transaction's PQ key must be the key the registry holds for the sender (or the first-use key that registers it) |
| `core/state_transition.go` | PQ authorization in `preCheck`; intrinsic gas charges the 7,219-byte key and signature at calldata rate |
| `core/types/*_pq_test.go`, `core/pq_auth_test.go` | Encoding, signing, authorization and rotation tests |

## 3. Key registry and rotation

The registry at `0x...5051` is a genesis account (nonce 1, code `0xfe`) whose storage the node
writes natively. A rotation transaction replaces an account's authorized key; the address never
changes.

| File | Change |
| --- | --- |
| `core/genesis.go` | Chain `20261012` genesis must allocate the registry exactly |
| `core/txpool/validation.go` | Cheap checks run before the ML-DSA verify (DoS); PQ fields validated |
| `core/txpool/legacypool/legacypool.go` | Drops transactions signed by a key the account no longer authorizes |
| `eth/tracers/native/*.go` | Native key rotations appear in call, prestate and ERC-7562 traces |
| `cmd/flpq/` | `flpq` tool: key generation (exclusive create), address, signing, rotation, validator proof of possession |

## 4. Consensus (Parlia)

| File | Change |
| --- | --- |
| `consensus/parlia/pq_signer.go` | Validators seal blocks and sign system transactions with ML-DSA-87 |
| `consensus/parlia/parlia.go` | Seal = last 7,220 bytes of header extra; deterministic seals (re-sealing the same height with a different header is slashable); unsealed header fields must be nil; a missing or wrong slash system transaction invalidates the block; BLS attestations rejected |
| `consensus/parlia/snapshot.go` | Signer recovery uses the PQ seal, not ecrecover; BLS vote attestations never justify or finalize; turn length bounded |
| `consensus/parlia/feynmanfork.go` | Empty election keeps the current validator set instead of halting |
| `consensus/parlia/consensus_revocation.go` | Rotated consensus keys are revoked immediately (reads StakeHub storage slot directly) |
| `consensus/parlia/staking_inflation.go` | Daily breathe block mints staking inflation and forwards it to `StakeHub.distributeStakingInflation`; must never revert |
| `consensus/parlia/abi.go`, `stakehub.go`, `bohrFork.go`, `lubanFork.go` | StakeHub ABI with the consensus key proof; system contract reads go through `ConsensusCall` |
| `core/vm/contracts_finallayer.go` | PQ verify precompile `0x...0f01`; double-sign evidence precompile `0x68` verifies ML-DSA seals (input capped at 32 KiB); classical signature precompiles (ecrecover, BLS12-381) disabled |
| `core/vm/contracts.go` | Registers the above |
| `core/forkchoice.go` | Deterministic tie-break for equal-difficulty siblings: `keccak(height ‖ coinbase)` |
| `consensus/parlia/*_test.go`, `core/forkchoice_finallayer_test.go`, `core/vm/contracts_finallayer*_test.go` | Tests |

## 5. Block size and miner

| File | Change |
| --- | --- |
| `params/protocol_params.go` | `FinalLayerMaxBlockSize` = 1.5 MB consensus cap |
| `core/block_validator.go`, `core/blockchain.go` | Cap enforced on import, including snap sync |
| `miner/worker.go`, `miner/bid_block.go` | Miner fills to cap minus 100 KB; never seals an oversized block or one whose gas used exceeds the limit |
| `core/finallayer_limits_test.go`, `miner/finallayer_size_test.go`, `consensus/parlia/finallayer_size_test.go` | Worst-case system transaction and boundary tests |

## 6. Networking, RPC and node

| File | Change |
| --- | --- |
| `eth/backend.go` | BLS vote pool disabled; node-ID registration bumps the nonce only after a submitted removal |
| `eth/handler.go`, `eth/handler_finallayer.go`, `eth/peerset.go`, `eth/sync.go` | Re-sends a stale head with backoff so stalled forks recover; a full-syncing node with no peer ahead marks itself synced |
| `eth/api_backend.go`, `eth/api_backend_finallayer.go` | `finalized` and `safe` tags report probabilistic finality (no fast finality votes) |
| `internal/ethapi/api.go`, `api_finallayer.go` | Consensus reads use a fixed gas budget independent of `--rpc.gascap`; not exposed over RPC; PQ fields in RPC output |
| `cmd/geth/config.go` | Refuses test parameters and fork-override flags on chain `20261012` |
| `params/fltest_breathe.go` | Test-only build tag (`-tags fltest`): breathe every 10 minutes for devnets; never in releases |

## Known limitations and open items

- BLS fast finality is disabled, so finality is probabilistic (see `eth/api_backend_finallayer.go`).
- `permit()` style flows that rely on `ecrecover` cannot work on Final Layer by design.
- `eth_getDiffAccounts*` replay endpoints are public on nodes that expose RPC; operators should
  rate-limit or proxy them.
