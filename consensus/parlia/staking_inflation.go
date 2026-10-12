package parlia

import (
	"context"
	"fmt"
	"math"
	"math/big"
	"strings"

	"github.com/holiman/uint256"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/internal/ethapi"
	"github.com/ethereum/go-ethereum/log"
	"github.com/ethereum/go-ethereum/rpc"
)

// Final Layer staking inflation.
//
// Once per breathe block (the first block of each UTC day) the engine asks
// StakeHub how much it owes stakers since the previous distribution
// (pendingStakingInflation, evaluated on the parent state with this block's
// timestamp), mints exactly that amount to the block producer and forwards it
// to StakeHub.distributeStakingInflation in a system transaction. Every node
// computes the same amount from the same parent state, so the mint is part of
// consensus. The rate (12% APR by default, capped at 20%) and the validator
// bonus live in StakeHub and can only be changed by on-chain governance.

const finalLayerStakeABI = `[
  {"type":"function","name":"pendingStakingInflation","stateMutability":"view",
   "inputs":[{"name":"timestamp","type":"uint256"}],
   "outputs":[{"name":"total","type":"uint256"}]},
  {"type":"function","name":"distributeStakingInflation","stateMutability":"payable",
   "inputs":[],"outputs":[]}
]`

// stakingInflationReservedGas is the block gas the miner keeps free on breathe
// blocks for distributeStakingInflation: ~138k gas per recipient pool, at most
// StakeHub.MAX_INFLATION_VALIDATORS (100) pools. System transactions count
// towards header.GasUsed, so without this reserve a full breathe block would
// exceed the gas limit and be rejected by every node.
const stakingInflationReservedGas uint64 = 15_000_000

var flStakeABI = func() abi.ABI {
	a, err := abi.JSON(strings.NewReader(finalLayerStakeABI))
	if err != nil {
		panic(err)
	}
	return a
}()

// pendingStakingInflation reads the amount to mint from the parent state.
func (p *Parlia) pendingStakingInflation(header *types.Header) (*big.Int, error) {
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	data, err := flStakeABI.Pack("pendingStakingInflation", new(big.Int).SetUint64(header.Time))
	if err != nil {
		return nil, err
	}
	msgData := hexutil.Bytes(data)
	to := common.HexToAddress(systemcontracts.StakeHubContract)
	gas := hexutil.Uint64(uint64(math.MaxUint64 / 2))
	blockNr := rpc.BlockNumberOrHashWithHash(header.ParentHash, false)
	result, err := p.ethAPI.ConsensusCall(ctx, ethapi.TransactionArgs{
		Gas:  &gas,
		To:   &to,
		Data: &msgData,
	}, &blockNr, nil, nil)
	if err != nil {
		return nil, err
	}
	out, err := flStakeABI.Unpack("pendingStakingInflation", result)
	if err != nil {
		return nil, err
	}
	amount, ok := out[0].(*big.Int)
	if !ok || amount.Sign() < 0 {
		return nil, fmt.Errorf("invalid staking inflation amount")
	}
	return amount, nil
}

// distributeStakingInflation mints the pending staking reward and hands it to
// StakeHub. It must run in the same position for mining and importing.
func (p *Parlia) distributeStakingInflation(state vm.StateDB, header *types.Header, chain core.ChainContext,
	txs *[]*types.Transaction, receipts *[]*types.Receipt, receivedTxs *[]*types.Transaction, usedGas *uint64,
	mode systemTxMode, tracer *tracing.Hooks) error {
	amount, err := p.pendingStakingInflation(header)
	if err != nil {
		return fmt.Errorf("staking inflation: %w", err)
	}
	value, overflow := uint256.FromBig(amount)
	if overflow {
		return fmt.Errorf("staking inflation: amount overflows")
	}
	if !value.IsZero() {
		state.AddBalance(header.Coinbase, value, tracing.BalanceIncreaseRewardMineBlock)
		log.Info("Staking inflation minted", "number", header.Number, "amount", amount)
	}
	data, err := flStakeABI.Pack("distributeStakingInflation")
	if err != nil {
		return err
	}
	msg := p.getSystemMessage(header.Coinbase, common.HexToAddress(systemcontracts.StakeHubContract), data, amount)
	return p.applyTransaction(msg, state, header, chain, txs, receipts, receivedTxs, usedGas, mode, tracer)
}
