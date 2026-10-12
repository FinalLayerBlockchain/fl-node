package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// A plain PQ transfer needs exactly 21,000 + 116,000 gas: one gas less is
// rejected by the state transition (the same rule block import applies).
func TestPQTransferIntrinsicGasBoundary(t *testing.T) {
	if pq.AuthGas(pq.SchemeMLDSA87) != 116_000 {
		t.Fatalf("auth gas %d, want 116000 (16 gas per byte of key + signature)", pq.AuthGas(pq.SchemeMLDSA87))
	}
	e := newPQEnv(t)
	k, _ := pq.GenerateKey()
	acct := k.Address()
	dest := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	e.db.AddBalance(acct, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	if _, err := e.apply(e.sign(k, acct, dest, 1, nil, 136_999)); !errors.Is(err, ErrIntrinsicGas) {
		t.Fatalf("136,999 gas: err = %v, want intrinsic gas too low", err)
	}
	rcpt, err := e.apply(e.sign(k, acct, dest, 1, nil, 137_000))
	if err != nil || rcpt.Status != types.ReceiptStatusSuccessful || rcpt.GasUsed != 137_000 {
		t.Fatalf("137,000 gas: err = %v", err)
	}
}

// Final Layer blocks above 1.5 MB are invalid.
func TestFinalLayerBlockSizeCap(t *testing.T) {
	config := &params.ChainConfig{ChainID: big.NewInt(20261012), Parlia: &params.ParliaConfig{}}
	v := &BlockValidator{config: config}
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(2), GasLimit: 40_000_000}
	big := types.NewTx(&types.LegacyTx{Data: make([]byte, params.FinalLayerMaxBlockSize)})
	block := types.NewBlockWithHeader(header).WithBody(types.Body{Transactions: []*types.Transaction{big}})
	if err := v.ValidateBody(block); !errors.Is(err, ErrBlockOversized) {
		t.Fatalf("oversized block: err = %v, want ErrBlockOversized", err)
	}
}

// Snap sync (InsertReceiptChain) enforces the cap too.
func TestFinalLayerBlockSizeCapSnapSync(t *testing.T) {
	config := &params.ChainConfig{ChainID: big.NewInt(20261012), Parlia: &params.ParliaConfig{}}
	bc := &BlockChain{chainConfig: config}
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(2), GasLimit: 40_000_000}
	big := types.NewTx(&types.LegacyTx{Data: make([]byte, params.FinalLayerMaxBlockSize)})
	block := types.NewBlockWithHeader(header).WithBody(types.Body{Transactions: []*types.Transaction{big}})
	if _, err := bc.InsertReceiptChain(types.Blocks{block}, nil, 0); !errors.Is(err, ErrBlockOversized) {
		t.Fatalf("snap sync accepted an oversized block: %v", err)
	}
}
