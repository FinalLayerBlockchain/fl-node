package miner

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// The miner fills Final Layer blocks only up to the cap minus the buffer
// for the header and system transactions.
func TestFinalLayerMinerSizeCap(t *testing.T) {
	cfg := &params.ChainConfig{Parlia: &params.ParliaConfig{}}
	env := &environment{sizeCap: finalLayerSizeCap(cfg)}
	if env.sizeCap != params.FinalLayerMaxBlockSize-params.FinalLayerBlockSizeBufferZone {
		t.Fatalf("size cap %d", env.sizeCap)
	}
	tx := types.NewTx(&types.LegacyTx{Data: make([]byte, 1000)})
	env.size = env.sizeCap - tx.Size()
	if env.txFitsSize(tx) {
		t.Fatal("tx that reaches the cap fits")
	}
	env.size = env.sizeCap - tx.Size() - 1
	if !env.txFitsSize(tx) {
		t.Fatal("tx below the cap does not fit")
	}
	if finalLayerSizeCap(&params.ChainConfig{}) != 0 {
		t.Fatal("non-Parlia chains must keep the upstream limit")
	}
}

// The worker refuses to seal a Parlia block above the consensus cap: its own
// block is written without ValidateBody, so it would fork off every peer.
func TestFinalLayerAssembledBlockSizeGuard(t *testing.T) {
	cfg := &params.ChainConfig{Parlia: &params.ParliaConfig{}}
	header := &types.Header{Number: big.NewInt(1), Difficulty: big.NewInt(2)}
	mk := func(n int) *types.Block {
		tx := types.NewTx(&types.LegacyTx{Data: make([]byte, n)})
		return types.NewBlockWithHeader(header).WithBody(types.Body{Transactions: []*types.Transaction{tx}})
	}
	if err := checkFinalLayerBlockSize(cfg, mk(params.FinalLayerMaxBlockSize)); !errors.Is(err, errFinalLayerBlockOversized) {
		t.Fatalf("oversized block: err = %v", err)
	}
	if err := checkFinalLayerBlockSize(cfg, mk(params.FinalLayerMaxBlockSize-2000)); err != nil {
		t.Fatalf("block under the cap: err = %v", err)
	}
	if err := checkFinalLayerBlockSize(&params.ChainConfig{}, mk(params.FinalLayerMaxBlockSize)); err != nil {
		t.Fatalf("non-Parlia chain: err = %v", err)
	}
}
