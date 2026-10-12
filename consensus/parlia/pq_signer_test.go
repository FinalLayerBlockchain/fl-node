package parlia

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// Final Layer genesis activates Luban at block 6 and Plato at block 7 (Fermi
// from genesis). Upstream only rejects bad attestations from Plato on, and
// since Fermi updateAttestation trusts them, so an unverified attestation in
// a block before Plato would set the snapshot's justified/finalized numbers
// forever (no attestation can ever replace it on Final Layer). A huge
// finalized number makes BEP-524 clear Recents on every block, disabling the
// "recently signed" rule for every validator.
func TestAttestationNeverEntersSnapshot(t *testing.T) {
	zero := uint64(0)
	cfg := &params.ChainConfig{
		ChainID:     big.NewInt(20261012),
		LondonBlock: big.NewInt(0),
		LubanBlock:  big.NewInt(6),
		PlatoBlock:  big.NewInt(7),
		FermiTime:   &zero,
	}
	att := &types.VoteAttestation{
		VoteAddressSet: 7,
		Data: &types.VoteData{
			SourceNumber: 1 << 40,
			SourceHash:   common.Hash{1},
			TargetNumber: 1<<40 + 1,
			TargetHash:   common.Hash{2},
		},
	}
	attBytes, err := rlp.EncodeToBytes(att)
	if err != nil {
		t.Fatal(err)
	}
	extra := make([]byte, extraVanity)
	extra = append(extra, attBytes...)
	extra = append(extra, make([]byte, pq.SealSize)...)
	header := &types.Header{Number: big.NewInt(6), Extra: extra, Difficulty: big.NewInt(2)}

	if got, err := getVoteAttestationFromHeader(header, cfg, defaultEpochLength); err != nil || got == nil {
		t.Fatalf("test header carries no attestation: %v", err)
	}
	snap := &Snapshot{EpochLength: defaultEpochLength}
	snap.updateAttestation(header, cfg)
	if snap.Attestation != nil {
		t.Fatalf("unverified attestation entered the snapshot: finalized number %d", snap.getFinalizedNumber())
	}
}

// Transactions that the validator node signs itself (node ID registration)
// must carry enough gas for the post-quantum authorization, while system
// transactions (zero gas price) must keep exactly the gas the importer
// expects.
func TestPQSignerTxAuthGas(t *testing.T) {
	key, _ := pq.GenerateKey()
	chainID := big.NewInt(20261012)
	val, _, signTx := PQSignerFns(key)
	to := common.HexToAddress("0x2002")

	user := types.NewTransaction(0, to, common.Big0, 50_000, big.NewInt(1_000_000_000), nil)
	signed, err := signTx(accountOf(val), user, chainID)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Gas() != 50_000+pq.AuthGas(pq.SchemeMLDSA87) {
		t.Fatalf("node transaction gas %d lacks the PQ auth surcharge", signed.Gas())
	}

	system := types.NewTransaction(0, to, common.Big0, 1<<62, common.Big0, nil)
	signed, err = signTx(accountOf(val), system, chainID)
	if err != nil {
		t.Fatal(err)
	}
	if signed.Gas() != 1<<62 {
		t.Fatalf("system transaction gas changed to %d", signed.Gas())
	}
}

func accountOf(addr common.Address) accounts.Account { return accounts.Account{Address: addr} }
