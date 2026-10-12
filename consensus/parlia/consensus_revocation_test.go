package parlia

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/types"
)

// After StakeHub.editConsensusAddress the old consensus key may not seal any
// later block, even before the next breathe block updates the validator set.
func TestConsensusKeyRevoked(t *testing.T) {
	db, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	oldKey := common.HexToAddress("0x00000000000000000000000000000000000000a1")
	other := common.HexToAddress("0x00000000000000000000000000000000000000b2")
	stakeHub := common.HexToAddress(systemcontracts.StakeHubContract)
	// consensusExpiration[oldKey] = 1000 (edited in the block with timestamp 1000)
	db.SetState(stakeHub, consensusExpirationKey(oldKey), common.BigToHash(big.NewInt(1000)))

	cases := []struct {
		coinbase common.Address
		time     uint64
		revoked  bool
	}{
		{oldKey, 1000, false}, // the block that contains the edit
		{oldKey, 1003, true},  // any later block
		{other, 5000, false},  // a key that was never replaced
	}
	for i, c := range cases {
		err := checkConsensusKeyRevoked(db, &types.Header{Coinbase: c.coinbase, Time: c.time})
		if (err != nil) != c.revoked {
			t.Fatalf("case %d: err = %v, want revoked=%v", i, err, c.revoked)
		}
	}
}
