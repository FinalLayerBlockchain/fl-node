package pq

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

func TestSignVerify(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	if len(k.PublicKey()) != 2592 {
		t.Fatalf("ML-DSA-87 public key size %d", len(k.PublicKey()))
	}
	msg := crypto.Keccak256([]byte("hello final layer"))
	sig, err := k.Sign(msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 4627 {
		t.Fatalf("ML-DSA-87 signature size %d", len(sig))
	}
	if err := Verify(SchemeMLDSA87, k.PublicKey(), msg, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	bad := common.CopyBytes(sig)
	bad[10] ^= 1
	if Verify(SchemeMLDSA87, k.PublicKey(), msg, bad) == nil {
		t.Fatal("tampered signature accepted")
	}
	msg2 := crypto.Keccak256([]byte("other"))
	if Verify(SchemeMLDSA87, k.PublicKey(), msg2, sig) == nil {
		t.Fatal("signature accepted for wrong message")
	}
	if Verify(Scheme(0x02), k.PublicKey(), msg, sig) == nil {
		t.Fatal("unknown scheme accepted")
	}
	if Verify(Scheme(0x00), k.PublicKey(), msg, sig) == nil {
		t.Fatal("scheme 0 accepted")
	}
	// Truncated / extended inputs
	if Verify(SchemeMLDSA87, k.PublicKey(), msg, sig[:len(sig)-1]) == nil {
		t.Fatal("short signature accepted")
	}
	if Verify(SchemeMLDSA87, k.PublicKey(), msg, append(common.CopyBytes(sig), 0)) == nil {
		t.Fatal("long signature accepted")
	}
}

func TestSeedDeterminism(t *testing.T) {
	var seed [32]byte
	seed[0] = 7
	a, _ := KeyFromSeed(SchemeMLDSA87, seed)
	b, _ := KeyFromSeed(SchemeMLDSA87, seed)
	if !bytes.Equal(a.PublicKey(), b.PublicKey()) || a.Address() != b.Address() {
		t.Fatal("seed is not deterministic")
	}
	f := a.ToKeyFile()
	c, err := FromKeyFile(f)
	if err != nil || c.Address() != a.Address() {
		t.Fatalf("key file round trip failed: %v", err)
	}
	f.Address = common.Address{1}.Hex()
	if _, err := FromKeyFile(f); err == nil {
		t.Fatal("mismatched key file address accepted")
	}
}

func TestAddressDomainSeparation(t *testing.T) {
	k, _ := GenerateKey()
	pk := k.PublicKey()
	// Address must commit to the scheme byte, not just the key bytes.
	plain := common.BytesToAddress(crypto.Keccak256(pk)[12:])
	if k.Address() == plain {
		t.Fatal("address does not include scheme")
	}
}

func TestRotationPayload(t *testing.T) {
	newKey, _ := GenerateKey()
	acct := common.HexToAddress("0x1234")
	data, err := EncodeRotation(newKey, 77, acct, 5)
	if err != nil {
		t.Fatal(err)
	}
	s, pk, proof, err := ParseRotation(data)
	if err != nil {
		t.Fatal(err)
	}
	if s != SchemeMLDSA87 || !bytes.Equal(pk, newKey.PublicKey()) {
		t.Fatal("parsed rotation mismatch")
	}
	if err := Verify(s, pk, RotationProofHash(77, acct, 5), proof); err != nil {
		t.Fatalf("rotation proof invalid: %v", err)
	}
	// Proof is bound to chain, account and nonce.
	if Verify(s, pk, RotationProofHash(78, acct, 5), proof) == nil ||
		Verify(s, pk, RotationProofHash(77, common.HexToAddress("0x9999"), 5), proof) == nil ||
		Verify(s, pk, RotationProofHash(77, acct, 6), proof) == nil {
		t.Fatal("rotation proof not bound to context")
	}
	if _, _, _, err := ParseRotation(data[:len(data)-1]); err == nil {
		t.Fatal("short rotation payload accepted")
	}
	bad := common.CopyBytes(data)
	bad[0] = 0x09
	if _, _, _, err := ParseRotation(bad); err == nil {
		t.Fatal("rotation to unknown scheme accepted")
	}
}

func TestSeal(t *testing.T) {
	k, _ := GenerateKey()
	h := crypto.Keccak256([]byte("header"))
	seal, err := EncodeSeal(k, h)
	if err != nil {
		t.Fatal(err)
	}
	if len(seal) != SealSize {
		t.Fatalf("seal size %d want %d", len(seal), SealSize)
	}
	addr, err := VerifySeal(seal, h)
	if err != nil || addr != k.Address() {
		t.Fatalf("seal verify failed: %v", err)
	}
	seal[SealSize-1] ^= 0x80
	if _, err := VerifySeal(seal, h); err == nil {
		t.Fatal("tampered seal accepted")
	}
}
