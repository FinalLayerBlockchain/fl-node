package parlia

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/rawdb"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/trie"
)

// Regression: system transactions are PQ transactions. Their receipts used
// to be legacy typed, while receipts read back from the database take the
// type from the transaction, so the rebuilt receipt root differed from the
// header (snap sync, receipt serving and proofs).
func TestSystemReceiptRootSurvivesStorage(t *testing.T) {
	cfg := *params.TestChainConfig
	cfg.ChainID = big.NewInt(20261012)
	cfg.Parlia = &params.ParliaConfig{}
	key, err := pq.KeyFromSeed(pq.SchemeMLDSA87, [32]byte{99})
	if err != nil {
		t.Fatal(err)
	}
	val, _, signTx := PQSignerFns(key)
	p := &Parlia{chainConfig: &cfg, signer: types.LatestSignerForChainID(cfg.ChainID), val: val, signTxFn: signTx}
	st, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{Number: big.NewInt(1), Time: 1, Difficulty: big.NewInt(2), GasLimit: 40_000_000, Coinbase: val}
	to := common.HexToAddress(systemcontracts.ValidatorContract)
	var txs []*types.Transaction
	var receipts []*types.Receipt
	for i := 0; i < 2; i++ {
		msg := p.getSystemMessage(val, to, nil, new(big.Int))
		if err := p.applyTransaction(msg, st, header, chainContext{parlia: p}, &txs, &receipts, nil, &header.GasUsed, systemTxMining, nil); err != nil {
			t.Fatal(err)
		}
	}
	for i := range receipts {
		if receipts[i].Type != txs[i].Type() {
			t.Fatalf("system receipt %d type %d, tx type %d", i, receipts[i].Type, txs[i].Type())
		}
	}
	block := types.NewBlock(header, &types.Body{Transactions: txs}, receipts, trie.NewStackTrie(nil))
	db := rawdb.NewMemoryDatabase()
	defer db.Close()
	rawdb.WriteBlock(db, block)
	rawdb.WriteReceipts(db, block.Hash(), block.NumberU64(), receipts)
	reloaded := rawdb.ReadReceipts(db, block.Hash(), block.NumberU64(), block.Time(), &cfg)
	if len(reloaded) != len(receipts) {
		t.Fatalf("reloaded %d receipts, want %d", len(reloaded), len(receipts))
	}
	if got := types.DeriveSha(reloaded, trie.NewStackTrie(nil)); got != block.ReceiptHash() {
		t.Fatalf("receipt root changed after storage: built=%s reloaded=%s", block.ReceiptHash(), got)
	}
}
