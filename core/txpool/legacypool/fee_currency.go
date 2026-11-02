// Copyright 2026 Final Layer
// This file is part of the go-ethereum library.
//
// The go-ethereum library is free software: you can redistribute it and/or modify
// it under the terms of the GNU Lesser General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

package legacypool

import (
	"errors"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/pq"
)

// ErrFeeCurrencyLimit is returned when a sender already has a pooled
// transaction paying gas in a fee currency (one at a time keeps the token
// balance check exact without tracking pooled token spending).
var ErrFeeCurrencyLimit = errors.New("only one pooled fee currency transaction per sender")

// validateFeeCurrency checks a transaction that pays gas in a fee currency
// against the pool state. The pool lock must be held.
func (pool *LegacyPool) validateFeeCurrency(tx *types.Transaction, from common.Address) error {
	if tx.FeeCurrency() == nil {
		return nil
	}
	other := func(l *list) bool {
		for _, t := range l.Flatten() {
			if t.FeeCurrency() != nil && t.Nonce() != tx.Nonce() {
				return true
			}
		}
		return false
	}
	if l := pool.pending[from]; l != nil && other(l) {
		return ErrFeeCurrencyLimit
	}
	if l, ok := pool.queue.get(from); ok && other(l) {
		return ErrFeeCurrencyLimit
	}
	return pool.checkFeeCurrencyState(tx, from)
}

// checkFeeCurrencyState checks the token is listed and the sender can pay.
func (pool *LegacyPool) checkFeeCurrencyState(tx *types.Transaction, from common.Address) error {
	head := pool.currentHead.Load()
	rules := pool.chainconfig.Rules(head.Number, head.Difficulty.Sign() == 0, head.Time)
	intr, err := core.IntrinsicGas(tx.Data(), tx.AccessList(), tx.SetCodeAuthorizations(), tx.To() == nil, true, rules.IsIstanbul, rules.IsShanghai, rules.IsAmsterdam)
	if err != nil {
		return err
	}
	if scheme, _, _, ok := tx.PQAuth(); ok {
		intr.RegularGas += pq.AuthGas(scheme)
	}
	evm := core.NewFeeCurrencyEVM(pool.chainconfig, head, pool.currentState)
	return core.CheckFeeCurrencyTx(evm, tx, from, intr.RegularGas)
}
