package core

import (
	"errors"
	"math/big"
	"testing"

	"github.com/holiman/uint256"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/params"
)

type pqEnv struct {
	t      *testing.T
	cfg    *params.ChainConfig
	db     *state.StateDB
	header *types.Header
	signer types.Signer
}

func newPQEnv(t *testing.T) *pqEnv {
	db, _ := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	// The registry account is pre-deployed at genesis with nonce 1 and an
	// INVALID opcode so it is never pruned as an empty account.
	db.SetNonce(pq.RegistryAddress, 1, tracing.NonceChangeGenesis)
	db.SetCode(pq.RegistryAddress, []byte{0xfe}, tracing.CodeChangeGenesis)
	cfg := params.TestChainConfig
	return &pqEnv{
		t:      t,
		cfg:    cfg,
		db:     db,
		header: &types.Header{Number: big.NewInt(1), Time: 1, GasLimit: 30_000_000, Difficulty: big.NewInt(1), BaseFee: big.NewInt(0)},
		signer: types.LatestSigner(cfg),
	}
}

func (e *pqEnv) apply(tx *types.Transaction) (*types.Receipt, error) {
	ctx := NewEVMBlockContext(e.header, nil, &common.Address{})
	ctx.GetHash = func(uint64) common.Hash { return common.Hash{} }
	evm := vm.NewEVM(ctx, e.db, e.cfg, vm.Config{})
	gp := NewGasPool(e.header.GasLimit)
	e.db.SetTxContext(tx.Hash(), 0)
	return ApplyTransaction(evm, gp, e.db, e.header, tx)
}

func (e *pqEnv) sign(key *pq.PrivateKey, from common.Address, to common.Address, value int64, data []byte, gas uint64) *types.Transaction {
	tx := types.NewTx(&types.PQTx{
		ChainID:   e.cfg.ChainID,
		Nonce:     e.db.GetNonce(from),
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(1),
		Gas:       gas,
		To:        &to,
		Value:     big.NewInt(value),
		Data:      data,
		From:      from,
		Scheme:    uint8(key.Scheme),
	})
	signed, err := types.SignPQTx(tx, e.signer, key)
	if err != nil {
		e.t.Fatal(err)
	}
	return signed
}

func TestPQTransferAndRotation(t *testing.T) {
	e := newPQEnv(t)
	k1, _ := pq.GenerateKey()
	k2, _ := pq.GenerateKey()
	attacker, _ := pq.GenerateKey()
	acct := k1.Address()
	dest := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	e.db.AddBalance(acct, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	// 1. Plain transfer with the default key; auth gas is charged.
	rcpt, err := e.apply(e.sign(k1, acct, dest, 1000, nil, 21000+pq.AuthGas(pq.SchemeMLDSA87)))
	if err != nil || rcpt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("transfer failed: %v", err)
	}
	if rcpt.GasUsed != 21000+pq.AuthGas(pq.SchemeMLDSA87) {
		t.Fatalf("gas used %d", rcpt.GasUsed)
	}
	if e.db.GetBalance(dest).Uint64() != 1000 {
		t.Fatal("value not transferred")
	}

	// 2. Not enough gas for the PQ auth surcharge is an invalid tx.
	if _, err := e.apply(e.sign(k1, acct, dest, 1, nil, 21000)); !errors.Is(err, ErrIntrinsicGas) {
		t.Fatalf("expected intrinsic gas error, got %v", err)
	}

	// 3. An attacker key cannot spend from acct even when it claims From=acct.
	if _, err := e.apply(e.sign(attacker, acct, dest, 1, nil, 21000+pq.AuthGas(pq.SchemeMLDSA87))); !errors.Is(err, ErrPQUnauthorized) {
		t.Fatalf("expected unauthorized, got %v", err)
	}

	// 4. Rotation with a proof signed by a DIFFERENT key than the payload key fails (VM error, nonce used).
	nonce := e.db.GetNonce(acct)
	data, _ := pq.EncodeRotation(k2, e.cfg.ChainID.Uint64(), acct, nonce)
	badProof, _ := pq.EncodeRotation(attacker, e.cfg.ChainID.Uint64(), acct, nonce)
	copy(data[1+pq.PublicKeySize(pq.SchemeMLDSA87):], badProof[1+pq.PublicKeySize(pq.SchemeMLDSA87):])
	rcpt, err = e.apply(e.sign(k1, acct, pq.RegistryAddress, 0, data, 2_000_000))
	if err != nil || rcpt.Status != types.ReceiptStatusFailed {
		t.Fatalf("bad-proof rotation should fail in VM: err=%v status=%v", err, rcpt)
	}
	if e.db.GetState(pq.RegistryAddress, pq.RegistrySlot(acct)) != (common.Hash{}) {
		t.Fatal("registry written by failed rotation")
	}

	// 5. Valid rotation k1 -> k2.
	nonce = e.db.GetNonce(acct)
	data, _ = pq.EncodeRotation(k2, e.cfg.ChainID.Uint64(), acct, nonce)
	rcpt, err = e.apply(e.sign(k1, acct, pq.RegistryAddress, 0, data, 2_000_000))
	if err != nil || rcpt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("rotation failed: %v %v", err, rcpt)
	}
	if e.db.GetState(pq.RegistryAddress, pq.RegistrySlot(acct)) != pq.KeyHash(pq.SchemeMLDSA87, k2.PublicKey()) {
		t.Fatal("registry not updated")
	}

	// 6. Old key is now rejected, new key spends from the SAME address.
	if _, err := e.apply(e.sign(k1, acct, dest, 1, nil, 21000+pq.AuthGas(pq.SchemeMLDSA87))); !errors.Is(err, ErrPQUnauthorized) {
		t.Fatalf("old key still accepted: %v", err)
	}
	before := e.db.GetBalance(dest).Uint64()
	rcpt, err = e.apply(e.sign(k2, acct, dest, 7, nil, 21000+pq.AuthGas(pq.SchemeMLDSA87)))
	if err != nil || rcpt.Status != types.ReceiptStatusSuccessful || e.db.GetBalance(dest).Uint64() != before+7 {
		t.Fatalf("new key transfer failed: %v", err)
	}

	// 7. Rotation replay (old payload, stale nonce) fails.
	rcpt, err = e.apply(e.sign(k2, acct, pq.RegistryAddress, 0, data, 2_000_000))
	if err != nil || rcpt.Status != types.ReceiptStatusFailed {
		t.Fatalf("replayed rotation should fail: %v", err)
	}

	// 8. Rotation carrying value fails and moves nothing.
	nonce = e.db.GetNonce(acct)
	data, _ = pq.EncodeRotation(k1, e.cfg.ChainID.Uint64(), acct, nonce)
	bal := e.db.GetBalance(pq.RegistryAddress).Uint64()
	rcpt, err = e.apply(e.sign(k2, acct, pq.RegistryAddress, 5, data, 2_000_000))
	if err != nil || rcpt.Status != types.ReceiptStatusFailed || e.db.GetBalance(pq.RegistryAddress).Uint64() != bal {
		t.Fatalf("value-carrying rotation should fail: %v", err)
	}
}

func TestClassicalPrecompilesDisabled(t *testing.T) {
	rules := params.TestChainConfig.Rules(big.NewInt(1), false, 1)
	pcs := vm.ActivePrecompiledContracts(rules)
	for _, a := range []common.Address{
		common.BytesToAddress([]byte{0x01}),
		common.BytesToAddress([]byte{0x66}),
		common.BytesToAddress([]byte{0x69}),
		common.BytesToAddress([]byte{0x01, 0x00}),
	} {
		p, ok := pcs[a]
		if !ok {
			t.Fatalf("classical address %v not occupied by a stub", a)
		}
		if _, err := p.Run(make([]byte, 128)); !errors.Is(err, vm.ErrExecutionReverted) {
			t.Fatalf("precompile %v not disabled", a)
		}
	}
	p, ok := pcs[vm.PQVerifyAddress]
	if !ok {
		t.Fatal("PQ verify precompile missing")
	}
	key, _ := pq.GenerateKey()
	msg := make([]byte, 32)
	msg[0] = 9
	// A transaction-domain signature over the same bytes must be rejected.
	txSig, _ := key.Sign(pq.DomainTx, msg)
	txIn := append([]byte{byte(pq.SchemeMLDSA87)}, msg...)
	txIn = append(txIn, key.PublicKey()...)
	txIn = append(txIn, txSig...)
	if out, err := p.Run(txIn); err != nil || out[31] != 0 {
		t.Fatal("precompile accepted a transaction-domain signature")
	}
	sig, _ := key.Sign(pq.DomainContract, msg)
	in := append([]byte{byte(pq.SchemeMLDSA87)}, msg...)
	in = append(in, key.PublicKey()...)
	in = append(in, sig...)
	out, err := p.Run(in)
	if err != nil || out[31] != 1 {
		t.Fatal("valid signature rejected by precompile")
	}
	in[1] ^= 1
	out, _ = p.Run(in)
	if out[31] != 0 {
		t.Fatal("invalid signature accepted by precompile")
	}
}
