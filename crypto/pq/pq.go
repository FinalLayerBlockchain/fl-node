// Package pq implements the post-quantum signature layer of Final Layer.
//
// Final Layer accepts no classical signatures (ECDSA, BLS, Ed25519) for
// transactions, block seals or system transactions. Every signature that
// authorizes value or consensus is a NIST FIPS 204 ML-DSA signature.
//
// Algorithm agility: every signature carries a one-byte scheme identifier.
// Only schemes listed in the registry below are accepted. A future scheme is
// added by registering a new identifier in a coordinated node release, after
// which any account can move to it with a key rotation transaction (see
// RegistryAddress). Account addresses never change on rotation.
package pq

import (
	"crypto/rand"
	"encoding/json"
	"errors"
	"fmt"
	"os"

	"github.com/cloudflare/circl/sign/mldsa/mldsa87"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
)

// Scheme identifies a post-quantum signature algorithm.
type Scheme uint8

const (
	// SchemeMLDSA87 is FIPS 204 ML-DSA-87 (NIST security category 5).
	SchemeMLDSA87 Scheme = 0x01
)

var (
	ErrUnknownScheme   = errors.New("pq: unknown or disabled signature scheme")
	ErrBadPublicKey    = errors.New("pq: invalid public key length")
	ErrBadSignature    = errors.New("pq: invalid signature length")
	ErrInvalidSig      = errors.New("pq: signature verification failed")
	ErrBadRotationData = errors.New("pq: malformed key rotation payload")
)

// schemeInfo describes an enabled scheme.
type schemeInfo struct {
	name    string
	pkSize  int
	sigSize int
	// authGas is charged as extra intrinsic gas on every transaction signed
	// with this scheme, to price the bytes of the public key and signature
	// that travel with the transaction (8 gas per byte, rounded up).
	authGas uint64
	verify  func(pk, msg, sig []byte) bool
}

var schemes = map[Scheme]schemeInfo{
	SchemeMLDSA87: {
		name:    "ML-DSA-87",
		pkSize:  mldsa87.PublicKeySize,
		sigSize: mldsa87.SignatureSize,
		authGas: 58_000,
		verify:  verifyMLDSA87,
	},
}

// Enabled reports whether a scheme is accepted by this node release.
func Enabled(s Scheme) bool {
	_, ok := schemes[s]
	return ok
}

// Name returns the human readable name of a scheme.
func Name(s Scheme) string {
	if info, ok := schemes[s]; ok {
		return info.name
	}
	return fmt.Sprintf("unknown(%d)", s)
}

// PublicKeySize returns the public key size of an enabled scheme, or 0.
func PublicKeySize(s Scheme) int { return schemes[s].pkSize }

// SignatureSize returns the signature size of an enabled scheme, or 0.
func SignatureSize(s Scheme) int { return schemes[s].sigSize }

// AuthGas returns the extra intrinsic gas charged for a transaction signed
// with the given scheme.
func AuthGas(s Scheme) uint64 { return schemes[s].authGas }

// CheckKey validates the scheme and the public key length.
func CheckKey(s Scheme, pk []byte) error {
	info, ok := schemes[s]
	if !ok {
		return ErrUnknownScheme
	}
	if len(pk) != info.pkSize {
		return ErrBadPublicKey
	}
	return nil
}

// Verify checks sig over msg with the public key pk under scheme s.
// msg is normally a 32 byte domain separated hash.
func Verify(s Scheme, pk, msg, sig []byte) error {
	info, ok := schemes[s]
	if !ok {
		return ErrUnknownScheme
	}
	if len(pk) != info.pkSize {
		return ErrBadPublicKey
	}
	if len(sig) != info.sigSize {
		return ErrBadSignature
	}
	if !info.verify(pk, msg, sig) {
		return ErrInvalidSig
	}
	return nil
}

// Address derives the default account address of a public key:
// the last 20 bytes of keccak256(scheme || pk).
func Address(s Scheme, pk []byte) common.Address {
	return common.BytesToAddress(crypto.Keccak256([]byte{byte(s)}, pk)[12:])
}

// KeyHash is the value stored in the key registry for a rotated account:
// keccak256(scheme || pk).
func KeyHash(s Scheme, pk []byte) common.Hash {
	return crypto.Keccak256Hash([]byte{byte(s)}, pk)
}

func verifyMLDSA87(pkb, msg, sig []byte) bool {
	var pk mldsa87.PublicKey
	if err := pk.UnmarshalBinary(pkb); err != nil {
		return false
	}
	return mldsa87.Verify(&pk, msg, nil, sig)
}

// PrivateKey is an ML-DSA private key held by a wallet or validator.
type PrivateKey struct {
	Scheme Scheme
	Seed   [32]byte // FIPS 204 key generation seed; the whole key is derived from it
	sk     *mldsa87.PrivateKey
	pk     []byte
}

// GenerateKey creates a fresh ML-DSA-87 key from the system CSPRNG.
func GenerateKey() (*PrivateKey, error) {
	var seed [32]byte
	if _, err := rand.Read(seed[:]); err != nil {
		return nil, err
	}
	return KeyFromSeed(SchemeMLDSA87, seed)
}

// KeyFromSeed deterministically derives a key from its 32 byte seed.
func KeyFromSeed(s Scheme, seed [32]byte) (*PrivateKey, error) {
	if s != SchemeMLDSA87 {
		return nil, ErrUnknownScheme
	}
	pk, sk := mldsa87.NewKeyFromSeed(&seed)
	return &PrivateKey{Scheme: s, Seed: seed, sk: sk, pk: pk.Bytes()}, nil
}

// PublicKey returns the encoded public key.
func (k *PrivateKey) PublicKey() []byte { return common.CopyBytes(k.pk) }

// Address returns the default address of this key.
func (k *PrivateKey) Address() common.Address { return Address(k.Scheme, k.pk) }

// Sign signs msg (hedged/randomized signing as recommended by FIPS 204).
func (k *PrivateKey) Sign(msg []byte) ([]byte, error) {
	sig := make([]byte, mldsa87.SignatureSize)
	if err := mldsa87.SignTo(k.sk, msg, nil, true, sig); err != nil {
		return nil, err
	}
	return sig, nil
}

// ---------------------------------------------------------------------------
// Key registry (algorithm agility / key rotation)
// ---------------------------------------------------------------------------

// RegistryAddress is the reserved account that holds the key registry.
// Storage slot keccak256(pad32(account)) holds keccak256(scheme || pk) of the
// key currently authorized for that account. An empty slot means the account
// is controlled by the key whose default address equals the account.
//
// A key rotation is a PQ transaction sent to RegistryAddress with zero value
// and data = newScheme(1) || newPubKey || proofSig, where proofSig is a
// signature by the NEW key over RotationProofHash(chainID, account, nonce).
// The proof prevents locking an account to a key nobody holds.
var RegistryAddress = common.HexToAddress("0x0000000000000000000000000000000000005051")

// RotationGas is the gas charged for a key rotation on top of the intrinsic
// gas of the transaction.
const RotationGas uint64 = 100_000

// RegistrySlot returns the storage slot holding the key hash of an account.
func RegistrySlot(account common.Address) common.Hash {
	return crypto.Keccak256Hash(common.LeftPadBytes(account.Bytes(), 32))
}

// RotationProofHash is the message the new key signs in a rotation.
func RotationProofHash(chainID uint64, account common.Address, nonce uint64) []byte {
	var buf []byte
	buf = append(buf, []byte("FinalLayer/pq-key-rotation/v1")...)
	buf = append(buf, common.LeftPadBytes(new(uint256Shim).setUint64(chainID), 32)...)
	buf = append(buf, account.Bytes()...)
	buf = append(buf, common.LeftPadBytes(new(uint256Shim).setUint64(nonce), 32)...)
	return crypto.Keccak256(buf)
}

// ParseRotation splits a rotation payload into scheme, public key and proof.
func ParseRotation(data []byte) (Scheme, []byte, []byte, error) {
	if len(data) < 1 {
		return 0, nil, nil, ErrBadRotationData
	}
	s := Scheme(data[0])
	info, ok := schemes[s]
	if !ok {
		return 0, nil, nil, ErrUnknownScheme
	}
	if len(data) != 1+info.pkSize+info.sigSize {
		return 0, nil, nil, ErrBadRotationData
	}
	pk := data[1 : 1+info.pkSize]
	proof := data[1+info.pkSize:]
	return s, pk, proof, nil
}

// EncodeRotation builds a rotation payload signed by newKey.
func EncodeRotation(newKey *PrivateKey, chainID uint64, account common.Address, nonce uint64) ([]byte, error) {
	proof, err := newKey.Sign(RotationProofHash(chainID, account, nonce))
	if err != nil {
		return nil, err
	}
	out := []byte{byte(newKey.Scheme)}
	out = append(out, newKey.PublicKey()...)
	return append(out, proof...), nil
}

// uint256Shim encodes a uint64 big-endian without pulling in math/big.
type uint256Shim [8]byte

func (u *uint256Shim) setUint64(v uint64) []byte {
	for i := 7; i >= 0; i-- {
		u[i] = byte(v)
		v >>= 8
	}
	return u[:]
}

// ---------------------------------------------------------------------------
// Block seals
// ---------------------------------------------------------------------------

// SealSize is the number of bytes at the end of a block header's extra-data
// reserved for the validator seal: scheme(1) || pubkey || signature.
// All validators currently seal with ML-DSA-87. Introducing a seal scheme of a
// different size requires a coordinated network upgrade.
const SealSize = 1 + mldsa87.PublicKeySize + mldsa87.SignatureSize

// EncodeSeal builds a seal over hash with key.
func EncodeSeal(key *PrivateKey, hash []byte) ([]byte, error) {
	sig, err := key.Sign(hash)
	if err != nil {
		return nil, err
	}
	seal := make([]byte, 0, SealSize)
	seal = append(seal, byte(key.Scheme))
	seal = append(seal, key.pk...)
	seal = append(seal, sig...)
	if len(seal) != SealSize {
		return nil, ErrBadSignature
	}
	return seal, nil
}

// VerifySeal checks a seal over hash and returns the address of the signer.
func VerifySeal(seal, hash []byte) (common.Address, error) {
	if len(seal) != SealSize {
		return common.Address{}, ErrBadSignature
	}
	s := Scheme(seal[0])
	if s != SchemeMLDSA87 {
		return common.Address{}, ErrUnknownScheme
	}
	pk := seal[1 : 1+mldsa87.PublicKeySize]
	sig := seal[1+mldsa87.PublicKeySize:]
	if err := Verify(s, pk, hash, sig); err != nil {
		return common.Address{}, err
	}
	return Address(s, pk), nil
}

// ---------------------------------------------------------------------------
// Key files
// ---------------------------------------------------------------------------

// KeyFile is the on-disk JSON format of a Final Layer PQ key.
// The seed alone reconstructs the key; it must be kept secret.
type KeyFile struct {
	Scheme    uint8  `json:"scheme"`
	Algorithm string `json:"algorithm"`
	Address   string `json:"address"`
	Seed      string `json:"seed"`
	PublicKey string `json:"publicKey"`
}

// ToKeyFile serializes a key.
func (k *PrivateKey) ToKeyFile() KeyFile {
	return KeyFile{
		Scheme:    uint8(k.Scheme),
		Algorithm: Name(k.Scheme),
		Address:   k.Address().Hex(),
		Seed:      "0x" + common.Bytes2Hex(k.Seed[:]),
		PublicKey: "0x" + common.Bytes2Hex(k.pk),
	}
}

// FromKeyFile parses and checks a key file.
func FromKeyFile(f KeyFile) (*PrivateKey, error) {
	seed := common.FromHex(f.Seed)
	if len(seed) != 32 {
		return nil, errors.New("pq: key file seed must be 32 bytes")
	}
	var s [32]byte
	copy(s[:], seed)
	k, err := KeyFromSeed(Scheme(f.Scheme), s)
	if err != nil {
		return nil, err
	}
	if f.Address != "" && common.HexToAddress(f.Address) != k.Address() {
		return nil, errors.New("pq: key file address does not match seed")
	}
	return k, nil
}

// LoadKeyFile reads a JSON key file from disk.
func LoadKeyFile(path string) (*PrivateKey, error) {
	if path == "" {
		return nil, errors.New("pq: no key file path given")
	}
	raw, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var f KeyFile
	if err := json.Unmarshal(raw, &f); err != nil {
		return nil, err
	}
	return FromKeyFile(f)
}
