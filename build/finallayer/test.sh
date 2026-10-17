#!/usr/bin/env bash
# Runs the Final Layer test suite: every test function in the test files that
# Final Layer added to upstream bsc. Upstream tests are not run here: many of
# them build classical (ECDSA) transactions, which Final Layer rejects.
set -euo pipefail
cd "$(dirname "$0")/../.."

FILES=(
  cmd/flpq/args_test.go
  consensus/parlia/consensus_revocation_test.go
  consensus/parlia/election_paging_test.go
  consensus/parlia/finallayer_size_test.go
  consensus/parlia/pq_signer_test.go
  consensus/parlia/system_receipt_pq_test.go
  core/finallayer_limits_test.go
  core/forkchoice_finallayer_test.go
  core/pq_auth_test.go
  core/txpool/legacypool/pq_rotation_test.go
  core/txpool/validation_pq_test.go
  core/types/receipt_pq_test.go
  core/types/tx_pq_test.go
  core/vm/contracts_finallayer_size_test.go
  core/vm/contracts_finallayer_test.go
  crypto/pq/pq_test.go
  eth/protocols/eth/receipt_pq_test.go
  eth/tracers/native/pq_rotation_test.go
  internal/ethapi/api_finallayer_test.go
  miner/finallayer_size_test.go
)

pkgs=$(printf '%s\n' "${FILES[@]}" | xargs -n1 dirname | sort -u | sed 's#^#./#')
names=$(grep -ohE '^func Test[A-Za-z0-9_]+' "${FILES[@]}" | sed 's/^func //' | sort -u | paste -sd'|')
go test -count=1 -run "^(${names})\$" $pkgs
