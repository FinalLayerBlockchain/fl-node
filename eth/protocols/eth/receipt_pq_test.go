package eth

import (
	"testing"

	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
)

// Regression: receipts fetched over eth/68 and eth/69 must give the receipt
// root the block was built with, or receipt sync rejects blocks with PQ txs.
func TestPQReceiptNetworkRootMatchesConsensus(t *testing.T) {
	rs := types.Receipts{
		{Type: types.PQTxType, Status: 1, CumulativeGasUsed: 137000},
		{Type: types.LegacyTxType, Status: 1, CumulativeGasUsed: 158000},
		{Type: types.PQTxType, Status: 0, CumulativeGasUsed: 295000},
	}
	want := types.DeriveSha(rs, trie.NewStackTrie(nil))
	for name, list := range map[string]types.DerivableList{
		"eth68": NewReceiptList68(rs).Derivable(),
		"eth69": NewReceiptList(rs).Derivable(),
	} {
		if got := types.DeriveSha(list, trie.NewStackTrie(nil)); got != want {
			t.Errorf("%s network root=%s consensus=%s", name, got, want)
		}
	}
}
