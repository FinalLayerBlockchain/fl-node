package parlia

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/accounts"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/lru"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/pq"
)

// Final Layer: validators seal blocks and sign system transactions with
// post-quantum ML-DSA keys. No ECDSA or BLS key is used by consensus.

var (
	errPQSystemTx      = errors.New("system transaction must be post-quantum signed by the block producer")
	errNoPQKey         = errors.New("no post-quantum validator key configured")
	errFastFinalityOff = errors.New("vote attestations (BLS fast finality) are disabled on Final Layer")
)

// recoverSealer verifies the post-quantum seal of a header and returns the
// address of the validator that produced it.
func recoverSealer(header *types.Header, sigCache *lru.Cache[common.Hash, common.Address], chainId *big.Int) (common.Address, error) {
	hash := header.Hash()
	if address, known := sigCache.Get(hash); known {
		return address, nil
	}
	if len(header.Extra) < extraSeal {
		return common.Address{}, errMissingSignature
	}
	seal := header.Extra[len(header.Extra)-extraSeal:]
	signer, err := pq.VerifySeal(seal, types.SealHash(header, chainId).Bytes())
	if err != nil {
		return common.Address{}, err
	}
	sigCache.Add(hash, signer)
	return signer, nil
}

// PQSignerFns adapts a PQ validator key to the Parlia signer callbacks.
//
// The header signer receives ParliaRLP(header) and returns the full seal
// (scheme || pubkey || signature over keccak256 of the RLP).
//
// The transaction signer converts the unsigned transaction it is given into a
// PQ transaction with the same nonce, recipient, value, gas and data, sent from
// the validator address, and signs it.
func PQSignerFns(key *pq.PrivateKey) (common.Address, SignerFn, SignerTxFn) {
	val := key.Address()
	signFn := func(acc accounts.Account, mimeType string, data []byte) ([]byte, error) {
		if acc.Address != val {
			return nil, errUnauthorizedValidator(acc.Address.Hex())
		}
		return pq.EncodeSeal(key, crypto.Keccak256(data))
	}
	signTxFn := func(acc accounts.Account, tx *types.Transaction, chainID *big.Int) (*types.Transaction, error) {
		if acc.Address != val {
			return nil, errUnauthorizedValidator(acc.Address.Hex())
		}
		// Transactions the node sends itself (e.g. node ID registration) are
		// gas-estimated without the PQ authorization surcharge. System
		// transactions (zero gas price) must keep the exact expected gas.
		gas := tx.Gas()
		if tx.GasPrice().Sign() != 0 {
			gas += pq.AuthGas(key.Scheme)
		}
		unsigned := pqTxFrom(tx, val, key.Scheme, chainID, gas)
		return types.SignPQTx(unsigned, types.LatestSignerForChainID(chainID), key)
	}
	return val, signFn, signTxFn
}

// pqTxFrom builds an unsigned PQ transaction carrying the payload of tx.
func pqTxFrom(tx *types.Transaction, from common.Address, scheme pq.Scheme, chainID *big.Int, gas uint64) *types.Transaction {
	return types.NewTx(&types.PQTx{
		ChainID:   new(big.Int).Set(chainID),
		Nonce:     tx.Nonce(),
		GasTipCap: new(big.Int).Set(tx.GasTipCap()),
		GasFeeCap: new(big.Int).Set(tx.GasFeeCap()),
		Gas:       gas,
		To:        tx.To(),
		Value:     new(big.Int).Set(tx.Value()),
		Data:      tx.Data(),
		From:      from,
		Scheme:    uint8(scheme),
	})
}

// AuthorizePQ injects a post-quantum validator key into the engine.
func (p *Parlia) AuthorizePQ(key *pq.PrivateKey) common.Address {
	val, signFn, signTxFn := PQSignerFns(key)
	p.Authorize(val, signFn, signTxFn)
	return val
}
