package miner

import (
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
