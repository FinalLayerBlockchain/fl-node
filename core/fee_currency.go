// Copyright 2026 Final Layer
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package core

import (
	"errors"
	"fmt"
	"math/big"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// Final Layer fee currencies: a PQ transaction may name an ERC-20 token that
// pays for its gas (modelled on Celo's fee abstraction). Gas prices stay in FL
// wei; the charge is converted to the token at the rate published by the fee
// currency directory, a governance-owned contract pre-deployed in genesis.
//
// The token is debited the whole gas limit before execution and, after it,
// the unused part goes back to the sender and the fee to the block producer.
// Directory lookups, debits and credits are EVM calls from address(0), each
// limited to a fixed gas budget so a listed token cannot stall block
// production; the sender pays the token's intrinsic gas from the directory
// once on top of the normal intrinsic gas.

// FeeCurrencyDirectoryAddress is the genesis address of the directory.
var FeeCurrencyDirectoryAddress = common.HexToAddress("0x0000000000000000000000000000000000005052")

const (
	// feeCurrencyLookupGas bounds the directory + price source call.
	feeCurrencyLookupGas = 200_000
	// feeCurrencyBalanceGas bounds a balanceOf call made by the transaction pool.
	feeCurrencyBalanceGas = 100_000
	// MaxFeeCurrencyIntrinsicGas mirrors FeeCurrencyDirectory.MAX_INTRINSIC_GAS.
	MaxFeeCurrencyIntrinsicGas = 200_000
	minFeeCurrencyIntrinsicGas = 10_000 // sanity floor; the directory itself requires >= 40,000
)

var (
	// ErrFeeCurrencyNotAllowed is returned when the named token is not listed in
	// the directory or has no valid exchange rate.
	ErrFeeCurrencyNotAllowed = errors.New("fee currency not allowed")
	// ErrFeeCurrencyDebit is returned when the token refused the gas debit
	// (usually an insufficient token balance).
	ErrFeeCurrencyDebit = errors.New("fee currency debit failed")
	// ErrFeeCurrencyCredit is returned when the token refused the refund/fee
	// credit. A listed token must never do this; the transaction is invalid.
	ErrFeeCurrencyCredit = errors.New("fee currency credit failed")

	selGetCurrencyConfigAndRate = crypto.Keccak256([]byte("getCurrencyConfigAndRate(address)"))[:4]
	selDebitGasFees             = crypto.Keccak256([]byte("debitGasFees(address,uint256)"))[:4]
	selCreditGasFees            = crypto.Keccak256([]byte("creditGasFees(address[],uint256[])"))[:4]
	selBalanceOf                = crypto.Keccak256([]byte("balanceOf(address)"))[:4]

	maxUint256 = new(big.Int).Sub(new(big.Int).Lsh(common.Big1, 256), common.Big1)
)

// FeeCurrencyInfo is a fee currency's exchange rate and intrinsic gas, read
// from the directory: tokenAmount = flWei * Numerator / Denominator.
type FeeCurrencyInfo struct {
	Numerator    *big.Int
	Denominator  *big.Int
	IntrinsicGas uint64
}

// ToToken converts an amount of FL wei into token units, rounding up so the
// token never pays less than the FL price.
func (f *FeeCurrencyInfo) ToToken(flWei *big.Int) (*uint256.Int, error) {
	v := new(big.Int).Mul(flWei, f.Numerator)
	v.Add(v, new(big.Int).Sub(f.Denominator, common.Big1))
	v.Quo(v, f.Denominator)
	if v.Cmp(maxUint256) > 0 {
		return nil, fmt.Errorf("%w: fee in token exceeds 256 bits", ErrInsufficientFunds)
	}
	return uint256.MustFromBig(v), nil
}

func addressWord(a common.Address) []byte {
	return common.LeftPadBytes(a.Bytes(), 32)
}

// runFeeCurrencyCall runs a call from address(0) with the given gas budget and
// without the transaction tracer, so traces show only the transaction itself.
func runFeeCurrencyCall(evm *vm.EVM, to common.Address, input []byte, gas uint64, static bool) ([]byte, error) {
	tracer := evm.Config.Tracer
	evm.Config.Tracer = nil
	defer func() { evm.Config.Tracer = tracer }()
	if static {
		ret, _, err := evm.StaticCall(common.Address{}, to, input, vm.NewGasBudget(gas))
		return ret, err
	}
	ret, _, err := evm.Call(common.Address{}, to, input, vm.NewGasBudget(gas), new(uint256.Int))
	return ret, err
}

// LookupFeeCurrency reads token's exchange rate and intrinsic gas from the
// directory. Any failure means the token cannot pay for gas.
func LookupFeeCurrency(evm *vm.EVM, token common.Address) (*FeeCurrencyInfo, error) {
	// A call to an account without code succeeds and returns nothing, which
	// would make the debit a no-op (free gas). The directory refuses to list
	// such a token; the node refuses to trust one regardless.
	if evm.StateDB.GetCodeSize(token) == 0 {
		return nil, fmt.Errorf("%w: %v: no code", ErrFeeCurrencyNotAllowed, token)
	}
	input := append(common.CopyBytes(selGetCurrencyConfigAndRate), addressWord(token)...)
	ret, err := runFeeCurrencyCall(evm, FeeCurrencyDirectoryAddress, input, feeCurrencyLookupGas, true)
	if err != nil {
		return nil, fmt.Errorf("%w: %v: %v", ErrFeeCurrencyNotAllowed, token, err)
	}
	if len(ret) != 96 {
		return nil, fmt.Errorf("%w: %v: bad directory reply", ErrFeeCurrencyNotAllowed, token)
	}
	num := new(big.Int).SetBytes(ret[0:32])
	den := new(big.Int).SetBytes(ret[32:64])
	gas := new(big.Int).SetBytes(ret[64:96])
	if num.Sign() == 0 || den.Sign() == 0 || !gas.IsUint64() ||
		gas.Uint64() < minFeeCurrencyIntrinsicGas || gas.Uint64() > MaxFeeCurrencyIntrinsicGas {
		return nil, fmt.Errorf("%w: %v: invalid rate or intrinsic gas", ErrFeeCurrencyNotAllowed, token)
	}
	return &FeeCurrencyInfo{Numerator: num, Denominator: den, IntrinsicGas: gas.Uint64()}, nil
}

// FeeCurrencyBalance returns account's token balance (used by the pool).
func FeeCurrencyBalance(evm *vm.EVM, token, account common.Address) (*big.Int, error) {
	input := append(common.CopyBytes(selBalanceOf), addressWord(account)...)
	ret, err := runFeeCurrencyCall(evm, token, input, feeCurrencyBalanceGas, true)
	if err != nil {
		return nil, err
	}
	if len(ret) != 32 {
		return nil, errors.New("bad balanceOf reply")
	}
	return new(big.Int).SetBytes(ret), nil
}

func debitFeeCurrency(evm *vm.EVM, token, from common.Address, amount *uint256.Int, gas uint64) error {
	input := make([]byte, 0, 4+64)
	input = append(input, selDebitGasFees...)
	input = append(input, addressWord(from)...)
	input = append(input, amount.PaddedBytes(32)...)
	if _, err := runFeeCurrencyCall(evm, token, input, gas, false); err != nil {
		return fmt.Errorf("%w: %v: %v", ErrFeeCurrencyDebit, from, err)
	}
	return nil
}

func creditFeeCurrency(evm *vm.EVM, token common.Address, recipients []common.Address, amounts []*uint256.Int, gas uint64) error {
	n := len(recipients)
	// creditGasFees(address[],uint256[]): two offsets, then each array.
	input := make([]byte, 0, 4+64+2*32*(n+1))
	input = append(input, selCreditGasFees...)
	input = append(input, common.LeftPadBytes(big.NewInt(64).Bytes(), 32)...)
	input = append(input, common.LeftPadBytes(big.NewInt(int64(64+32*(n+1))).Bytes(), 32)...)
	input = append(input, common.LeftPadBytes(big.NewInt(int64(n)).Bytes(), 32)...)
	for _, r := range recipients {
		input = append(input, addressWord(r)...)
	}
	input = append(input, common.LeftPadBytes(big.NewInt(int64(n)).Bytes(), 32)...)
	for _, a := range amounts {
		input = append(input, a.PaddedBytes(32)...)
	}
	if _, err := runFeeCurrencyCall(evm, token, input, gas, false); err != nil {
		return fmt.Errorf("%w: %v", ErrFeeCurrencyCredit, err)
	}
	return nil
}

// NewFeeCurrencyEVM returns an EVM for read-only fee currency calls against
// statedb at header (transaction pool checks). The block context carries no
// hashes; directory, price source and balanceOf calls must not need them.
func NewFeeCurrencyEVM(config *params.ChainConfig, header *types.Header, statedb vm.StateDB) *vm.EVM {
	var baseFee *big.Int
	if header.BaseFee != nil {
		baseFee = new(big.Int).Set(header.BaseFee)
	}
	ctx := vm.BlockContext{
		CanTransfer: CanTransfer,
		Transfer:    Transfer,
		GetHash:     func(uint64) common.Hash { return common.Hash{} },
		Coinbase:    header.Coinbase,
		BlockNumber: new(big.Int).Set(header.Number),
		Time:        header.Time,
		Difficulty:  new(big.Int).Set(header.Difficulty),
		BaseFee:     baseFee,
		GasLimit:    header.GasLimit,
	}
	return vm.NewEVM(ctx, statedb, config, vm.Config{NoBaseFee: true})
}

// feeCurrencyProbe stands in for the block producer in the pool's dry run of
// the fee flow. A never-seen holder is the most expensive producer a plain
// token can face (a zero-to-nonzero storage write), so a transaction that
// passes here does not run the token out of its intrinsic gas at execution.
var feeCurrencyProbe = common.HexToAddress("0x000000000000000000000000000000000000fee1")

// CheckFeeCurrencyTx checks, against current state, that tx's fee currency is
// listed, that its gas covers the extra intrinsic gas, that the sender holds
// enough of the token for gasLimit * gasFeeCap, and then dry-runs the debit
// and a worst-case credit with the token's intrinsic gas budgets on a
// snapshot (reverted afterwards). Used by the pool: a transaction it admits
// must not be one that every producer executes, finds invalid at the credit
// and retries on the next block.
func CheckFeeCurrencyTx(evm *vm.EVM, tx *types.Transaction, from common.Address, intrinsic uint64) error {
	token := tx.FeeCurrency()
	if token == nil {
		return nil
	}
	info, err := LookupFeeCurrency(evm, *token)
	if err != nil {
		return err
	}
	if intrinsic+info.IntrinsicGas < intrinsic || tx.Gas() < intrinsic+info.IntrinsicGas {
		return fmt.Errorf("%w: gas %v, minimum needed %v (fee currency)", ErrIntrinsicGas, tx.Gas(), intrinsic+info.IntrinsicGas)
	}
	maxFee := new(big.Int).Mul(new(big.Int).SetUint64(tx.Gas()), tx.GasFeeCap())
	need, err := info.ToToken(maxFee)
	if err != nil {
		return err
	}
	have, err := FeeCurrencyBalance(evm, *token, from)
	if err != nil {
		return fmt.Errorf("%w: balanceOf: %v", ErrFeeCurrencyNotAllowed, err)
	}
	if have.Cmp(need.ToBig()) < 0 {
		return fmt.Errorf("%w: fee currency %v balance %v, need %v", ErrInsufficientFunds, *token, have, need)
	}
	// Dry run of what execution does with the same gas budgets: debit the
	// whole gasLimit * gasFeeCap, start a fresh access list like Prepare does
	// before the call, then credit the sender (refund) and a fresh producer
	// (fee), both non-zero.
	snap := evm.StateDB.Snapshot()
	defer evm.StateDB.RevertToSnapshot(snap)
	if err := debitFeeCurrency(evm, *token, from, need, info.IntrinsicGas); err != nil {
		return err
	}
	rules := evm.ChainConfig().Rules(evm.Context.BlockNumber, evm.Context.Random != nil, evm.Context.Time)
	evm.StateDB.Prepare(rules, from, feeCurrencyProbe, tx.To(), vm.ActivePrecompiles(rules), tx.AccessList())
	fee, refund := new(uint256.Int), new(uint256.Int).Set(need)
	if !need.IsZero() {
		fee.SetUint64(1)
		refund.SubUint64(refund, 1)
	}
	return creditFeeCurrency(evm, *token, []common.Address{from, feeCurrencyProbe}, []*uint256.Int{refund, fee}, info.IntrinsicGas)
}
