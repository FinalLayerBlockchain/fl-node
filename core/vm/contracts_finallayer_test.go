package vm

import (
	"bytes"
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

// TestPQVerifyValidatorProofLayout feeds the precompile exactly what
// StakeHub._checkConsensusProof builds: proof[:1] || message || proof[1:].
// A seal or transaction signature by the same key over the same message must
// not verify.
func TestPQVerifyValidatorProofLayout(t *testing.T) {
	key, err := pq.GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	op := common.HexToAddress("0x2222222222222222222222222222222222222222")
	proof, err := pq.EncodeValidatorProof(key, 20261012, op)
	if err != nil {
		t.Fatal(err)
	}
	msg := pq.ValidatorProofHash(20261012, key.Address(), op)
	build := func(p []byte) []byte {
		in := append([]byte{}, p[:1]...)
		in = append(in, msg...)
		return append(in, p[1:]...)
	}
	pc := &pqVerify{}
	if out, err := pc.Run(build(proof)); err != nil || out[31] != 1 {
		t.Fatal("precompile rejected a valid validator proof in the StakeHub layout")
	}
	if pc.RequiredGas(build(proof)) != PQVerifyGas {
		t.Fatal("unexpected precompile gas")
	}
	seal, err := pq.EncodeSeal(key, msg)
	if err != nil {
		t.Fatal(err)
	}
	if out, _ := pc.Run(build(seal)); out[31] != 0 {
		t.Fatal("precompile accepted a block seal signature as a contract signature")
	}
	txSig, _ := key.Sign(pq.DomainTx, msg)
	txProof := append(append([]byte{byte(pq.SchemeMLDSA87)}, key.PublicKey()...), txSig...)
	if out, _ := pc.Run(build(txProof)); out[31] != 0 {
		t.Fatal("precompile accepted a transaction signature as a contract signature")
	}
}

// Seals are deterministic, so sealing the same header twice gives the same
// block; a second, different seal over the same header (a re-rolled randomized
// signature, which would give a validator many block hashes to choose from in
// fork choice) is slashable equivocation.
func TestPQDoubleSignSameHeaderReseal(t *testing.T) {
	chainID := big.NewInt(20261012)
	key, _ := pq.GenerateKey()
	h1 := pqSealedHeader(t, key, chainID, 100, common.Hash{1}, 7)
	again := pqSealedHeader(t, key, chainID, 100, common.Hash{1}, 7)
	if !bytes.Equal(h1, again) {
		t.Fatal("sealing the same header twice gave different blocks")
	}

	// re-seal the same header with a randomized signature
	h := new(types.Header)
	if err := rlp.DecodeBytes(h1, h); err != nil {
		t.Fatal(err)
	}
	sealHash := types.SealHash(h, chainID)
	sig, err := key.Sign(pq.DomainSeal, sealHash.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	pkLen := len(key.PublicKey())
	copy(h.Extra[len(h.Extra)-len(sig):], sig)
	if _, err := pq.VerifySeal(h.Extra[len(h.Extra)-1-pkLen-len(sig):], sealHash.Bytes()); err != nil {
		t.Fatalf("randomized re-seal does not verify: %v", err)
	}
	h2, err := rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	out, err := (&pqDoubleSignEvidence{}).Run(doubleSignInput(t, chainID, h1, h2))
	if err != nil {
		t.Fatalf("re-sealed header not accepted as double sign: %v", err)
	}
	if common.BytesToAddress(out[:20]) != key.Address() {
		t.Fatal("wrong signer")
	}
}
