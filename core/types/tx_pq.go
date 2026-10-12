package types

import (
	"bytes"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/rlp"
)

// PQTxType is the Final Layer post-quantum transaction type. It is the only
// transaction type accepted by Final Layer: classical (secp256k1) signed
// transactions are rejected by every signer.
const PQTxType = 0x07

// PQTx is an EIP-1559 style transaction authorized by a post-quantum
// signature. Because ML-DSA public keys cannot be recovered from a
// signature, the transaction carries the sender address and the public key.
//
// The signature covers every field except PubKey and Signature. The sender is
// bound to the public key by state: either the account's key registry entry
// equals keccak256(scheme || pubkey), or the registry entry is empty and the
// account equals pq.Address(scheme, pubkey).
type PQTx struct {
	ChainID    *big.Int
	Nonce      uint64
	GasTipCap  *big.Int
	GasFeeCap  *big.Int
	Gas        uint64
	To         *common.Address `rlp:"nil"` // nil means contract creation
	Value      *big.Int
	Data       []byte
	AccessList AccessList
	From       common.Address
	Scheme     uint8

	// Authorization
	PubKey    []byte
	Signature []byte
}

func (tx *PQTx) copy() TxData {
	cpy := &PQTx{
		Nonce:      tx.Nonce,
		To:         copyAddressPtr(tx.To),
		Data:       common.CopyBytes(tx.Data),
		Gas:        tx.Gas,
		AccessList: make(AccessList, len(tx.AccessList)),
		Value:      new(big.Int),
		ChainID:    new(big.Int),
		GasTipCap:  new(big.Int),
		GasFeeCap:  new(big.Int),
		From:       tx.From,
		Scheme:     tx.Scheme,
		PubKey:     common.CopyBytes(tx.PubKey),
		Signature:  common.CopyBytes(tx.Signature),
	}
	copy(cpy.AccessList, tx.AccessList)
	if tx.Value != nil {
		cpy.Value.Set(tx.Value)
	}
	if tx.ChainID != nil {
		cpy.ChainID.Set(tx.ChainID)
	}
	if tx.GasTipCap != nil {
		cpy.GasTipCap.Set(tx.GasTipCap)
	}
	if tx.GasFeeCap != nil {
		cpy.GasFeeCap.Set(tx.GasFeeCap)
	}
	return cpy
}

func (tx *PQTx) txType() byte           { return PQTxType }
func (tx *PQTx) chainID() *big.Int      { return tx.ChainID }
func (tx *PQTx) accessList() AccessList { return tx.AccessList }
func (tx *PQTx) data() []byte           { return tx.Data }
func (tx *PQTx) gas() uint64            { return tx.Gas }
func (tx *PQTx) gasFeeCap() *big.Int    { return tx.GasFeeCap }
func (tx *PQTx) gasTipCap() *big.Int    { return tx.GasTipCap }
func (tx *PQTx) gasPrice() *big.Int     { return tx.GasFeeCap }
func (tx *PQTx) value() *big.Int        { return tx.Value }
func (tx *PQTx) nonce() uint64          { return tx.Nonce }
func (tx *PQTx) to() *common.Address    { return tx.To }

func (tx *PQTx) effectiveGasPrice(dst *big.Int, baseFee *big.Int) *big.Int {
	if baseFee == nil {
		return dst.Set(tx.GasFeeCap)
	}
	tip := dst.Sub(tx.GasFeeCap, baseFee)
	if tip.Cmp(tx.GasTipCap) > 0 {
		tip.Set(tx.GasTipCap)
	}
	return tip.Add(tip, baseFee)
}

// rawSignatureValues returns zeros: PQ transactions have no V, R, S.
func (tx *PQTx) rawSignatureValues() (v, r, s *big.Int) {
	return new(big.Int), new(big.Int), new(big.Int)
}

// setSignatureValues only records the chain id; the PQ signature is attached
// with WithPQSignature.
func (tx *PQTx) setSignatureValues(chainID, v, r, s *big.Int) {
	tx.ChainID = chainID
}

func (tx *PQTx) encode(b *bytes.Buffer) error {
	return rlp.Encode(b, tx)
}

func (tx *PQTx) decode(input []byte) error {
	return rlp.DecodeBytes(input, tx)
}

func (tx *PQTx) sigHash(chainID *big.Int) common.Hash {
	return prefixedRlpHash(
		PQTxType,
		[]any{
			chainID,
			tx.Nonce,
			tx.GasTipCap,
			tx.GasFeeCap,
			tx.Gas,
			tx.To,
			tx.Value,
			tx.Data,
			tx.AccessList,
			tx.From,
			tx.Scheme,
		})
}

// PQFrom returns the claimed sender of a PQ transaction (no verification).
func (tx *Transaction) PQFrom() (common.Address, bool) {
	if p, ok := tx.inner.(*PQTx); ok {
		return p.From, true
	}
	return common.Address{}, false
}

// PQAuth returns the scheme, public key and signature of a PQ transaction.
func (tx *Transaction) PQAuth() (pq.Scheme, []byte, []byte, bool) {
	if p, ok := tx.inner.(*PQTx); ok {
		return pq.Scheme(p.Scheme), p.PubKey, p.Signature, true
	}
	return 0, nil, nil, false
}

// SignPQTx signs an unsigned PQ transaction with key. The From and Scheme
// fields must already be set; From may differ from key.Address() for
// accounts that rotated their key.
func SignPQTx(tx *Transaction, s Signer, key *pq.PrivateKey) (*Transaction, error) {
	inner, ok := tx.inner.(*PQTx)
	if !ok {
		return nil, ErrTxTypeNotSupported
	}
	if pq.Scheme(inner.Scheme) != key.Scheme {
		return nil, pq.ErrUnknownScheme
	}
	h := s.Hash(tx)
	sig, err := key.Sign(pq.DomainTx, h[:])
	if err != nil {
		return nil, err
	}
	cpy := inner.copy().(*PQTx)
	cpy.ChainID = new(big.Int).Set(s.ChainID())
	cpy.PubKey = key.PublicKey()
	cpy.Signature = sig
	return &Transaction{inner: cpy, time: tx.time}, nil
}
