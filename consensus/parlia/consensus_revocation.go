package parlia

import (
	"errors"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
)

// stakeHubConsensusExpirationSlot is the storage slot of
// StakeHub.consensusExpiration (mapping(address => uint256)), from
// `forge inspect StakeHub storage-layout`. It must change if StakeHub's
// storage layout ever does.
const stakeHubConsensusExpirationSlot = 68

var errConsensusKeyRevoked = errors.New("block sealed with a consensus key its validator has replaced")

// checkConsensusKeyRevoked rejects a block whose coinbase is a consensus
// address its validator replaced through StakeHub.editConsensusAddress before
// this block. Without it the old (possibly compromised) key could keep sealing
// until the next breathe block updates the validator set. The block that
// contains the edit itself is still accepted (expiration == its timestamp).
func checkConsensusKeyRevoked(state vm.StateDB, header *types.Header) error {
	expiration := state.GetState(common.HexToAddress(systemcontracts.StakeHubContract), consensusExpirationKey(header.Coinbase))
	if expiration == (common.Hash{}) {
		return nil
	}
	if new(big.Int).SetBytes(expiration.Bytes()).Cmp(new(big.Int).SetUint64(header.Time)) < 0 {
		return errConsensusKeyRevoked
	}
	return nil
}

func consensusExpirationKey(consensus common.Address) common.Hash {
	return crypto.Keccak256Hash(
		common.LeftPadBytes(consensus.Bytes(), 32),
		common.LeftPadBytes(big.NewInt(stakeHubConsensusExpirationSlot).Bytes(), 32),
	)
}
