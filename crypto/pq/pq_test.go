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
	sig, err := k.Sign(DomainTx, msg)
	if err != nil {
		t.Fatal(err)
	}
	if len(sig) != 4627 {
		t.Fatalf("ML-DSA-87 signature size %d", len(sig))
	}
	if err := Verify(SchemeMLDSA87, DomainTx, k.PublicKey(), msg, sig); err != nil {
		t.Fatalf("valid signature rejected: %v", err)
	}
	bad := common.CopyBytes(sig)
	bad[10] ^= 1
	if Verify(SchemeMLDSA87, DomainTx, k.PublicKey(), msg, bad) == nil {
		t.Fatal("tampered signature accepted")
	}
	msg2 := crypto.Keccak256([]byte("other"))
	if Verify(SchemeMLDSA87, DomainTx, k.PublicKey(), msg2, sig) == nil {
		t.Fatal("signature accepted for wrong message")
	}
	if Verify(Scheme(0x02), DomainTx, k.PublicKey(), msg, sig) == nil {
		t.Fatal("unknown scheme accepted")
	}
	if Verify(Scheme(0x00), DomainTx, k.PublicKey(), msg, sig) == nil {
		t.Fatal("scheme 0 accepted")
	}
	// Truncated / extended inputs
	if Verify(SchemeMLDSA87, DomainTx, k.PublicKey(), msg, sig[:len(sig)-1]) == nil {
		t.Fatal("short signature accepted")
	}
	if Verify(SchemeMLDSA87, DomainTx, k.PublicKey(), msg, append(common.CopyBytes(sig), 0)) == nil {
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
	if err := Verify(s, DomainRotation, pk, RotationProofHash(77, acct, 5), proof); err != nil {
		t.Fatalf("rotation proof invalid: %v", err)
	}
	// Proof is bound to chain, account and nonce.
	if Verify(s, DomainRotation, pk, RotationProofHash(78, acct, 5), proof) == nil ||
		Verify(s, DomainRotation, pk, RotationProofHash(77, common.HexToAddress("0x9999"), 5), proof) == nil ||
		Verify(s, DomainRotation, pk, RotationProofHash(77, acct, 6), proof) == nil {
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

// TestDomainSeparation checks that a signature made in one domain verifies in
// no other domain, so for example a message signed for a contract can never
// be replayed as a transaction, seal or key rotation.
func TestDomainSeparation(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	msg := crypto.Keccak256([]byte("same 32 byte message"))
	domains := []Domain{DomainTx, DomainSeal, DomainRotation, DomainContract}
	for _, signIn := range domains {
		sig, err := k.Sign(signIn, msg)
		if err != nil {
			t.Fatal(err)
		}
		for _, verifyIn := range domains {
			err := Verify(SchemeMLDSA87, verifyIn, k.PublicKey(), msg, sig)
			if signIn == verifyIn && err != nil {
				t.Fatalf("%s signature rejected in its own domain: %v", signIn, err)
			}
			if signIn != verifyIn && err == nil {
				t.Fatalf("%s signature accepted in domain %s", signIn, verifyIn)
			}
		}
	}
}

// TestValidatorProofHashVector pins ValidatorProofHash to the bytes StakeHub
// hashes: keccak256(abi.encodePacked("FinalLayer/validator-pop/v1", uint256
// chainid, address consensus, address operator)). The expected value was
// computed independently with foundry's cast (abi-encode-packed + keccak) and
// is asserted by the forge test testValidatorProofHashMatchesGo as well.
func TestValidatorProofHashVector(t *testing.T) {
	got := ValidatorProofHash(20261012,
		common.HexToAddress("0x1111111111111111111111111111111111111111"),
		common.HexToAddress("0x2222222222222222222222222222222222222222"))
	want := common.FromHex("0x59469dac0654c3ab96107422aaf84bfb2e30481a1bd352706c265b6fc8835d0b")
	if !bytes.Equal(got, want) {
		t.Fatalf("validator proof hash %x, want %x", got, want)
	}
}

// TestValidatorProofDomain checks the proof layout and that the proof
// signature is valid only in the contract domain and only for its operator.
func TestValidatorProofDomain(t *testing.T) {
	k, err := GenerateKey()
	if err != nil {
		t.Fatal(err)
	}
	op := common.HexToAddress("0x2222222222222222222222222222222222222222")
	proof, err := EncodeValidatorProof(k, 20261012, op)
	if err != nil {
		t.Fatal(err)
	}
	if len(proof) != 1+2592+4627 || Scheme(proof[0]) != SchemeMLDSA87 {
		t.Fatalf("proof layout: len %d scheme %d", len(proof), proof[0])
	}
	pk, sig := proof[1:1+2592], proof[1+2592:]
	if Address(SchemeMLDSA87, pk) != k.Address() {
		t.Fatal("proof key does not derive the consensus address")
	}
	msg := ValidatorProofHash(20261012, k.Address(), op)
	if err := Verify(SchemeMLDSA87, DomainContract, pk, msg, sig); err != nil {
		t.Fatalf("proof rejected in contract domain: %v", err)
	}
	for _, d := range []Domain{DomainTx, DomainSeal, DomainRotation, ""} {
		if Verify(SchemeMLDSA87, d, pk, msg, sig) == nil {
			t.Fatalf("proof accepted in domain %q", d)
		}
	}
	other := ValidatorProofHash(20261012, k.Address(), common.HexToAddress("0x3333"))
	if Verify(SchemeMLDSA87, DomainContract, pk, other, sig) == nil {
		t.Fatal("proof accepted for another operator")
	}
}
