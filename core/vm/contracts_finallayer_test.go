package vm

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

var doubleSignAddress = common.BytesToAddress([]byte{0x68})

func pqSealedHeader(t *testing.T, key *pq.PrivateKey, chainID *big.Int, number int64, parent common.Hash, root byte) []byte {
	t.Helper()
	h := &types.Header{
		ParentHash: parent,
		Coinbase:   key.Address(),
		Root:       common.Hash{root},
		Difficulty: big.NewInt(2),
		Number:     big.NewInt(number),
		GasLimit:   40_000_000,
		Time:       1_700_000_000,
		Extra:      make([]byte, 32+pq.SealSize),
	}
	seal, err := pq.EncodeSeal(key, types.SealHash(h, chainID).Bytes())
	if err != nil {
		t.Fatal(err)
	}
	copy(h.Extra[32:], seal)
	enc, err := rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	return enc
}

func doubleSignInput(t *testing.T, chainID *big.Int, h1, h2 []byte) []byte {
	t.Helper()
	in, err := rlp.EncodeToBytes(&DoubleSignEvidence{ChainId: chainID, HeaderBytes1: h1, HeaderBytes2: h2})
	if err != nil {
		t.Fatal(err)
	}
	return in
}

// The double-sign evidence precompile (used by SlashIndicator) must verify
// post-quantum header seals, so equivocating validators can still be slashed.
func TestPQDoubleSignEvidence(t *testing.T) {
	rules := params.TestChainConfig.Rules(big.NewInt(1), false, 1)
	p, ok := ActivePrecompiledContracts(rules)[doubleSignAddress]
	if !ok {
		t.Fatal("double sign evidence precompile missing")
	}
	chainID := big.NewInt(20261012)
	val, _ := pq.GenerateKey()
	other, _ := pq.GenerateKey()
	parent := common.Hash{0xaa}

	h1 := pqSealedHeader(t, val, chainID, 100, parent, 1)
	h2 := pqSealedHeader(t, val, chainID, 100, parent, 2)
	out, err := p.Run(doubleSignInput(t, chainID, h1, h2))
	if err != nil {
		t.Fatalf("valid double sign evidence rejected: %v", err)
	}
	if len(out) != 52 || common.BytesToAddress(out[:20]) != val.Address() || new(big.Int).SetBytes(out[20:]).Int64() != 100 {
		t.Fatalf("unexpected output %x", out)
	}
	if gas := p.RequiredGas(nil); gas < 2*PQVerifyGas {
		t.Fatalf("double sign evidence gas %d does not cover two PQ verifications", gas)
	}

	bad := []struct {
		name   string
		input  []byte
		reason string
	}{
		{"same header", doubleSignInput(t, chainID, h1, h1), "identical headers"},
		{"different signers", doubleSignInput(t, chainID, h1, pqSealedHeader(t, other, chainID, 100, parent, 2)), "two validators"},
		{"different heights", doubleSignInput(t, chainID, h1, pqSealedHeader(t, val, chainID, 101, parent, 2)), "different heights"},
		{"different parents", doubleSignInput(t, chainID, h1, pqSealedHeader(t, val, chainID, 100, common.Hash{0xbb}, 2)), "different parents"},
		{"wrong chain id", doubleSignInput(t, big.NewInt(56), h1, h2), "seal over another chain id"},
		{"garbage", []byte{0xc0}, "not evidence"},
	}
	for _, c := range bad {
		if _, err := p.Run(c.input); err == nil {
			t.Fatalf("%s: accepted (%s)", c.name, c.reason)
		}
	}

	// A tampered seal (signature byte flipped) is rejected.
	var hdr types.Header
	if err := rlp.DecodeBytes(h2, &hdr); err != nil {
		t.Fatal(err)
	}
	hdr.Extra[len(hdr.Extra)-1] ^= 1
	tampered, _ := rlp.EncodeToBytes(&hdr)
	if _, err := p.Run(doubleSignInput(t, chainID, h1, tampered)); err == nil {
		t.Fatal("tampered seal accepted")
	}

	// Classical (65 byte ECDSA) seals are never evidence.
	hdr.Extra = make([]byte, 32+65)
	classical, _ := rlp.EncodeToBytes(&hdr)
	if _, err := p.Run(doubleSignInput(t, chainID, classical, classical)); !errors.Is(err, ErrExecutionReverted) && err == nil {
		t.Fatal("classical seal accepted")
	}
}
