package ethapi

import (
	"context"
	"errors"

	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/ethapi/override"
	"github.com/ethereum/go-ethereum/rpc"
)

// ConsensusCallGas is the gas every consensus engine read of a system contract
// gets. It is a protocol constant, so the result of the read never depends on
// a node's --rpc.gascap or --rpc.evmtimeout setting.
const ConsensusCallGas uint64 = 1_000_000_000

// ConsensusCall is Call for the consensus engine (Final Layer). Unlike Call it
// ignores the local RPC gas cap and EVM timeout and always runs with
// ConsensusCallGas, so every node computes the same result from the same state.
func (api *BlockChainAPI) ConsensusCall(ctx context.Context, args TransactionArgs, blockNrOrHash *rpc.BlockNumberOrHash, overrides *override.StateOverride, blockOverrides *override.BlockOverrides) (hexutil.Bytes, error) {
	if blockNrOrHash == nil {
		latest := rpc.BlockNumberOrHashWithNumber(rpc.LatestBlockNumber)
		blockNrOrHash = &latest
	}
	gas := hexutil.Uint64(ConsensusCallGas)
	args.Gas = &gas
	result, err := DoCall(ctx, api.b, args, *blockNrOrHash, overrides, blockOverrides, 0, 0)
	if err != nil {
		return nil, err
	}
	if errors.Is(result.Err, vm.ErrExecutionReverted) {
		return nil, newRevertError(result.Revert())
	}
	return result.Return(), result.Err
}
