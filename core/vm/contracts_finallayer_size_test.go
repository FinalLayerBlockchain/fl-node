package vm

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/rlp"
)

func pqSealedHeaderExtra(t *testing.T, key *pq.PrivateKey, chainID *big.Int, root byte, extraLen int) []byte {
	t.Helper()
	h := &types.Header{
		ParentHash: common.Hash{0xaa},
		Coinbase:   key.Address(),
		Root:       common.Hash{root},
		Difficulty: big.NewInt(2),
		Number:     big.NewInt(1000),
		GasLimit:   40_000_000,
		Time:       1_700_000_000,
		Extra:      make([]byte, extraLen),
	}
	seal, err := pq.EncodeSeal(key, types.SealHash(h, chainID).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	copy(h.Extra[extraLen-pq.SealSize:], seal)
	enc, err := rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

// Regression: the evidence precompile charges fixed gas, so its input is
// capped. The largest real evidence (two epoch headers with 50 validators)
// must still fit; padded headers past the cap are rejected before decoding.
func TestPQDoubleSignEvidenceSizeCap(t *testing.T) {
	chainID := big.NewInt(20261012)
	val, _ := pq.GenerateKey()
	// vanity + validator count + 50 * (address + vote id) + turn length + seal
	epochExtra := 32 + 1 + 50*(20+48) + 1 + pq.SealSize
	in := doubleSignInput(t, chainID, pqSealedHeaderExtra(t, val, chainID, 1, epochExtra), pqSealedHeaderExtra(t, val, chainID, 2, epochExtra))
	if len(in) > maxDoubleSignEvidenceSize {
		t.Fatalf("largest real evidence is %d bytes, over the %d cap", len(in), maxDoubleSignEvidenceSize)
	}
	if _, err := (&pqDoubleSignEvidence{}).Run(in); err != nil {
		t.Fatalf("largest real evidence rejected: %v", err)
	}
	in = doubleSignInput(t, chainID, pqSealedHeaderExtra(t, val, chainID, 1, 20_000), pqSealedHeaderExtra(t, val, chainID, 2, 20_000))
	if len(in) <= maxDoubleSignEvidenceSize {
		t.Fatalf("fixture too small: %d", len(in))
	}
	if _, err := (&pqDoubleSignEvidence{}).Run(in); err != ErrExecutionReverted {
		t.Fatalf("oversized evidence: got %v, want ErrExecutionReverted", err)
	}
}
