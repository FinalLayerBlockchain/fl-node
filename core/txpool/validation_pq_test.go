package txpool

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/params"
)

// Final Layer: cheap stateless rejections must come before the ML-DSA verify,
// so a forged signature on an underpriced or underfunded-gas transaction is
// reported for the cheap reason, without the verify ever running.
func TestValidateTransactionPQCheapChecksFirst(t *testing.T) {
	chain := params.TestChainConfig
	signer := types.LatestSigner(chain)
	key, err := pq.KeyFromSeed(pq.SchemeMLDSA87, [32]byte{61})
	if err != nil {
		t.Fatal(err)
	}
	head := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(0), GasLimit: 30_000_000, Time: 1}
	opts := &ValidationOptions{Config: chain, Accept: 1 << types.PQTxType, MaxSize: 128 * 1024, MinTip: big.NewInt(1)}

	build := func(gas uint64, tip int64, forge bool) *types.Transaction {
		to := common.HexToAddress("0x1234")
		inner := &types.PQTx{ChainID: chain.ChainID, Gas: gas, GasTipCap: big.NewInt(tip),
			GasFeeCap: big.NewInt(10), To: &to, Value: new(big.Int),
			From: key.Address(), Scheme: uint8(key.Scheme)}
		tx, err := types.SignPQTx(types.NewTx(inner), signer, key)
		if err != nil {
			t.Fatal(err)
		}
		if !forge {
			return tx
		}
		_, pub, sig, _ := tx.PQAuth()
		inner.PubKey = append([]byte(nil), pub...)
		inner.Signature = append([]byte(nil), sig...)
		inner.Signature[0] ^= 0xff
		return types.NewTx(inner)
	}
	enough := uint64(200_000)
	for _, tc := range []struct {
		name string
		tx   *types.Transaction
		want error
	}{
		{"low tip, forged", build(enough, 0, true), ErrTxGasPriceTooLow},
		{"low gas, forged", build(21_000, 1, true), core.ErrIntrinsicGas},
		{"forged", build(enough, 1, true), ErrInvalidSender},
		{"valid", build(enough, 1, false), nil},
	} {
		err := ValidateTransaction(tc.tx, head, signer, opts)
		if (tc.want == nil) != (err == nil) || (tc.want != nil && !errors.Is(err, tc.want)) {
			t.Errorf("%s: got %v, want %v", tc.name, err, tc.want)
		}
	}
}
