package core

import (
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/holiman/uint256"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/pq"
)

var (
	fcOracle   = common.HexToAddress("0x0000000000000000000000000000000000005053")
	fcToken    = common.HexToAddress("0x0000000000000000000000000000000000005054")
	fcCoinbase = common.HexToAddress("0x00000000000000000000000000000000000c0b0b")
	fcTransfer = crypto.Keccak256Hash([]byte("Transfer(address,address,uint256)"))
)

func loadHex(t *testing.T, name string) []byte {
	b, err := os.ReadFile("testdata/feecurrency/" + name + ".hex")
	if err != nil {
		t.Fatal(err)
	}
	return hexutil.MustDecode(strings.TrimSpace(string(b)))
}

func mapSlot(key common.Address, slot uint64) common.Hash {
	return crypto.Keccak256Hash(common.LeftPadBytes(key.Bytes(), 32), common.LeftPadBytes(new(big.Int).SetUint64(slot).Bytes(), 32))
}

func addSlot(h common.Hash, n int64) common.Hash {
	return common.BigToHash(new(big.Int).Add(h.Big(), big.NewInt(n)))
}

// installFeeCurrency writes the directory, the fixed-rate oracle and token
// (with token listed at num/den) exactly like scripts/make_genesis.py.
func installFeeCurrency(t *testing.T, e *pqEnv, token common.Address, tokenCode []byte, num, den, intrinsic uint64, holder common.Address, supply *big.Int) {
	db := e.db
	db.SetCode(FeeCurrencyDirectoryAddress, loadHex(t, "FeeCurrencyDirectory"), tracing.CodeChangeGenesis)
	db.SetCode(fcOracle, loadHex(t, "FixedRateOracle"), tracing.CodeChangeGenesis)
	db.SetCode(token, tokenCode, tracing.CodeChangeGenesis)

	cfg := mapSlot(token, 0)
	db.SetState(FeeCurrencyDirectoryAddress, cfg, common.BytesToHash(fcOracle.Bytes()))
	db.SetState(FeeCurrencyDirectoryAddress, addSlot(cfg, 1), common.BigToHash(new(big.Int).SetUint64(intrinsic)))
	db.SetState(FeeCurrencyDirectoryAddress, common.BigToHash(big.NewInt(1)), common.BigToHash(big.NewInt(1)))
	db.SetState(FeeCurrencyDirectoryAddress, crypto.Keccak256Hash(common.LeftPadBytes([]byte{1}, 32)), common.BytesToHash(token.Bytes()))

	rate := new(big.Int).Lsh(new(big.Int).SetUint64(den), 128)
	rate.Or(rate, new(big.Int).SetUint64(num))
	r := mapSlot(token, 0)
	db.SetState(fcOracle, r, common.BigToHash(rate))
	db.SetState(fcOracle, addSlot(r, 1), common.BigToHash(new(big.Int).SetUint64(e.header.Time)))

	if supply != nil {
		db.SetState(token, mapSlot(holder, 0), common.BigToHash(supply))
		db.SetState(token, common.BigToHash(big.NewInt(2)), common.BigToHash(supply))
	}
}

func tokenBalance(e *pqEnv, a common.Address) *big.Int {
	return e.db.GetState(fcToken, mapSlot(a, 0)).Big()
}

func tokenSupply(e *pqEnv) *big.Int {
	return e.db.GetState(fcToken, common.BigToHash(big.NewInt(2))).Big()
}

func (e *pqEnv) applyAt(tx *types.Transaction, coinbase common.Address) (*types.Receipt, error) {
	ctx := NewEVMBlockContext(e.header, nil, &coinbase)
	ctx.GetHash = func(uint64) common.Hash { return common.Hash{} }
	evm := vm.NewEVM(ctx, e.db, e.cfg, vm.Config{})
	gp := NewGasPool(e.header.GasLimit)
	e.db.SetTxContext(tx.Hash(), 0)
	snap := e.db.Snapshot()
	rcpt, err := ApplyTransaction(evm, gp, e.db, e.header, tx)
	if err != nil {
		e.db.RevertToSnapshot(snap) // as the miner does
	}
	return rcpt, err
}

func (e *pqEnv) signFC(key *pq.PrivateKey, to common.Address, value int64, data []byte, gas uint64, price int64, fc *common.Address) *types.Transaction {
	from := key.Address()
	tx := types.NewTx(&types.PQTx{
		ChainID:     e.cfg.ChainID,
		Nonce:       e.db.GetNonce(from),
		GasTipCap:   big.NewInt(price),
		GasFeeCap:   big.NewInt(price),
		Gas:         gas,
		To:          &to,
		Value:       big.NewInt(value),
		Data:        data,
		From:        from,
		Scheme:      uint8(key.Scheme),
		FeeCurrency: fc,
	})
	signed, err := types.SignPQTx(tx, e.signer, key)
	if err != nil {
		e.t.Fatal(err)
	}
	return signed
}

const fcIntrinsic = 50_000 // mirrors FLTD_INTRINSIC_GAS in scripts/make_genesis.py

func TestFeeCurrencyTransfer(t *testing.T) {
	e := newPQEnv(t)
	key, _ := pq.GenerateKey()
	acct := key.Address()
	dest := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	supply := new(big.Int).Mul(big.NewInt(1_000_000), big.NewInt(1e18))
	// 1 FL wei = 1/100 token unit
	installFeeCurrency(t, e, fcToken, loadHex(t, "FLTestDollar"), 1, 100, fcIntrinsic, acct, supply)
	e.db.AddBalance(acct, uint256.NewInt(5), tracing.BalanceChangeUnspecified) // value only, no FL for gas

	price := int64(1e9)
	baseGas := 21000 + pq.AuthGas(pq.SchemeMLDSA87) + fcIntrinsic
	limit := baseGas + 30_000
	tx := e.signFC(key, dest, 5, nil, limit, price, &fcToken)
	rcpt, err := e.applyAt(tx, fcCoinbase)
	if err != nil || rcpt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("fee currency transfer failed: %v", err)
	}
	if rcpt.GasUsed != baseGas {
		t.Fatalf("gas used %d, want %d", rcpt.GasUsed, baseGas)
	}
	fee := new(big.Int).Mul(new(big.Int).SetUint64(baseGas), big.NewInt(price))
	tokenFee := new(big.Int).Div(new(big.Int).Add(fee, big.NewInt(99)), big.NewInt(100))
	if got := tokenBalance(e, fcCoinbase); got.Cmp(tokenFee) != 0 {
		t.Fatalf("producer got %v, want %v", got, tokenFee)
	}
	if got := new(big.Int).Sub(supply, tokenBalance(e, acct)); got.Cmp(tokenFee) != 0 {
		t.Fatalf("sender paid %v, want %v", got, tokenFee)
	}
	if tokenSupply(e).Cmp(supply) != 0 {
		t.Fatalf("supply changed: %v", tokenSupply(e))
	}
	if e.db.GetBalance(acct).Sign() != 0 || e.db.GetBalance(dest).Uint64() != 5 {
		t.Fatalf("FL balances: sender %v dest %v", e.db.GetBalance(acct), e.db.GetBalance(dest))
	}
	if e.db.GetBalance(fcCoinbase).Sign() != 0 {
		t.Fatal("producer received FL for a token-paid tx")
	}
	// debit + refund credit + fee credit, all visible as Transfer events
	n := 0
	for _, l := range rcpt.Logs {
		if l.Address == fcToken && len(l.Topics) == 3 && l.Topics[0] == fcTransfer {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("got %d token Transfer logs, want 3", n)
	}
}

func TestFeeCurrencyRevertedCallStillPays(t *testing.T) {
	e := newPQEnv(t)
	key, _ := pq.GenerateKey()
	acct := key.Address()
	supply := big.NewInt(1e18)
	installFeeCurrency(t, e, fcToken, loadHex(t, "FLTestDollar"), 1, 1, fcIntrinsic, acct, supply)
	reverter := common.HexToAddress("0x00000000000000000000000000000000000000bb")
	e.db.SetCode(reverter, []byte{0x60, 0x00, 0x60, 0x00, 0xfd}, tracing.CodeChangeUnspecified) // REVERT(0,0)

	limit := uint64(200_000)
	rcpt, err := e.applyAt(e.signFC(key, reverter, 0, nil, limit, 1, &fcToken), fcCoinbase)
	if err != nil || rcpt.Status != types.ReceiptStatusFailed {
		t.Fatalf("want failed receipt, got err=%v", err)
	}
	if got := tokenBalance(e, fcCoinbase); got.Uint64() != rcpt.GasUsed {
		t.Fatalf("producer got %v, want %d", got, rcpt.GasUsed)
	}
	if got := new(big.Int).Sub(supply, tokenBalance(e, acct)); got.Uint64() != rcpt.GasUsed {
		t.Fatalf("sender paid %v, want %d (rest refunded)", got, rcpt.GasUsed)
	}
	if e.db.GetNonce(acct) != 1 {
		t.Fatal("nonce not used")
	}
}

func TestFeeCurrencyRejections(t *testing.T) {
	e := newPQEnv(t)
	key, _ := pq.GenerateKey()
	acct := key.Address()
	dest := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	installFeeCurrency(t, e, fcToken, loadHex(t, "FLTestDollar"), 1, 1, fcIntrinsic, acct, big.NewInt(1_000_000))
	ok := 21000 + pq.AuthGas(pq.SchemeMLDSA87) + fcIntrinsic

	// unlisted token
	other := common.HexToAddress("0x0000000000000000000000000000000000005055")
	e.db.SetCode(other, loadHex(t, "FLTestDollar"), tracing.CodeChangeUnspecified)
	if _, err := e.applyAt(e.signFC(key, dest, 0, nil, ok, 1, &other), fcCoinbase); !errors.Is(err, ErrFeeCurrencyNotAllowed) {
		t.Fatalf("unlisted: got %v", err)
	}
	// not enough token for gasLimit * price
	if _, err := e.applyAt(e.signFC(key, dest, 0, nil, ok, 100, &fcToken), fcCoinbase); !errors.Is(err, ErrFeeCurrencyDebit) {
		t.Fatalf("insufficient token: got %v", err)
	}
	// gas does not cover the fee currency intrinsic gas
	if _, err := e.applyAt(e.signFC(key, dest, 0, nil, ok-1, 1, &fcToken), fcCoinbase); !errors.Is(err, ErrIntrinsicGas) {
		t.Fatalf("intrinsic: got %v", err)
	}
	// FL value still needs FL
	if _, err := e.applyAt(e.signFC(key, dest, 1, nil, ok, 1, &fcToken), fcCoinbase); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("value without FL: got %v", err)
	}
	// every rejection left state untouched
	if e.db.GetNonce(acct) != 0 || tokenBalance(e, acct).Uint64() != 1_000_000 {
		t.Fatal("rejected transaction changed state")
	}
	// an expired rate switches the token off
	r := mapSlot(fcToken, 0)
	e.db.SetState(fcOracle, addSlot(r, 1), common.BigToHash(new(big.Int).Lsh(big.NewInt(10), 64))) // maxAge 10s, updatedAt 0
	e.header.Time = 100
	if _, err := e.applyAt(e.signFC(key, dest, 0, nil, ok, 1, &fcToken), fcCoinbase); !errors.Is(err, ErrFeeCurrencyNotAllowed) {
		t.Fatalf("expired rate: got %v", err)
	}
}

// A listed token that burns all gas cannot take more than its intrinsic gas
// budget and makes its transactions invalid instead of stalling the block.
func TestFeeCurrencyGasBurningToken(t *testing.T) {
	e := newPQEnv(t)
	key, _ := pq.GenerateKey()
	loop := []byte{0x5b, 0x60, 0x00, 0x56} // JUMPDEST PUSH1 0 JUMP
	installFeeCurrency(t, e, fcToken, loop, 1, 1, fcIntrinsic, key.Address(), nil)
	ok := 21000 + pq.AuthGas(pq.SchemeMLDSA87) + fcIntrinsic
	if _, err := e.applyAt(e.signFC(key, fcCoinbase, 0, nil, ok, 1, &fcToken), fcCoinbase); !errors.Is(err, ErrFeeCurrencyDebit) {
		t.Fatalf("got %v", err)
	}
}

func TestFeeCurrencyRounding(t *testing.T) {
	info := &FeeCurrencyInfo{Numerator: big.NewInt(1), Denominator: big.NewInt(3), IntrinsicGas: fcIntrinsic}
	for _, c := range []struct{ fl, want int64 }{{0, 0}, {1, 1}, {3, 1}, {4, 2}, {6, 2}} {
		got, err := info.ToToken(big.NewInt(c.fl))
		if err != nil || got.Uint64() != uint64(c.want) {
			t.Fatalf("ToToken(%d) = %v, want %d", c.fl, got, c.want)
		}
	}
	huge := &FeeCurrencyInfo{Numerator: new(big.Int).Lsh(big.NewInt(1), 200), Denominator: big.NewInt(1)}
	if _, err := huge.ToToken(new(big.Int).Lsh(big.NewInt(1), 100)); err == nil {
		t.Fatal("expected overflow error")
	}
}

func TestFeeCurrencyPoolCheck(t *testing.T) {
	e := newPQEnv(t)
	key, _ := pq.GenerateKey()
	acct := key.Address()
	installFeeCurrency(t, e, fcToken, loadHex(t, "FLTestDollar"), 1, 1, fcIntrinsic, acct, big.NewInt(1_000_000))
	intr := 21000 + pq.AuthGas(pq.SchemeMLDSA87)
	evm := NewFeeCurrencyEVM(e.cfg, e.header, e.db)
	if err := CheckFeeCurrencyTx(evm, e.signFC(key, fcCoinbase, 0, nil, intr+fcIntrinsic, 1, &fcToken), acct, intr); err != nil {
		t.Fatalf("valid: %v", err)
	}
	if err := CheckFeeCurrencyTx(evm, e.signFC(key, fcCoinbase, 0, nil, intr+fcIntrinsic, 10, &fcToken), acct, intr); !errors.Is(err, ErrInsufficientFunds) {
		t.Fatalf("balance: %v", err)
	}
	if err := CheckFeeCurrencyTx(evm, e.signFC(key, fcCoinbase, 0, nil, intr+fcIntrinsic-1, 1, &fcToken), acct, intr); !errors.Is(err, ErrIntrinsicGas) {
		t.Fatalf("intrinsic: %v", err)
	}
}

// The fee currency is covered by the signature: swapping it breaks the sender.
func TestFeeCurrencySigned(t *testing.T) {
	e := newPQEnv(t)
	key, _ := pq.GenerateKey()
	tx := e.signFC(key, fcCoinbase, 0, nil, 100_000, 1, &fcToken)
	other := common.HexToAddress("0x0000000000000000000000000000000000005055")
	scheme, pk, sig, _ := tx.PQAuth()
	from, _ := tx.PQFrom()
	forged := types.NewTx(&types.PQTx{
		ChainID: e.cfg.ChainID, Nonce: tx.Nonce(), GasTipCap: tx.GasTipCap(), GasFeeCap: tx.GasFeeCap(),
		Gas: tx.Gas(), To: tx.To(), Value: tx.Value(), Data: tx.Data(), From: from, Scheme: uint8(scheme),
		FeeCurrency: &other, PubKey: pk, Signature: sig,
	})
	if _, err := types.Sender(e.signer, forged); err == nil {
		t.Fatal("changing the fee currency kept a valid signature")
	}
	if _, err := types.Sender(e.signer, tx); err != nil {
		t.Fatal(err)
	}
	// round trip through RLP and JSON keeps the field
	b, _ := tx.MarshalBinary()
	var dec types.Transaction
	if err := dec.UnmarshalBinary(b); err != nil || dec.FeeCurrency() == nil || *dec.FeeCurrency() != fcToken {
		t.Fatalf("rlp round trip: %v", err)
	}
	j, _ := tx.MarshalJSON()
	var decj types.Transaction
	if err := decj.UnmarshalJSON(j); err != nil || decj.Hash() != tx.Hash() {
		t.Fatalf("json round trip: %v", err)
	}
	if tx.Cost().Sign() != 0 {
		t.Fatalf("Cost of a token-paid zero-value tx = %v, want 0", tx.Cost())
	}
}

// The credit after execution must fit the token's intrinsic gas in the
// worst case for a plain token: the debit cleared the sender's balance slot
// (balance == gasLimit * price) and the producer has never held the token, so
// the refund and the fee both write fresh storage slots. If it does not fit,
// a transaction the pool accepts is invalid at execution and is retried by
// every producer on every block.
func TestFeeCurrencyCreditWorstCase(t *testing.T) {
	e := newPQEnv(t)
	key, _ := pq.GenerateKey()
	acct := key.Address()
	dest := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	price := int64(1e9)
	limit := uint64(21000) + pq.AuthGas(pq.SchemeMLDSA87) + fcIntrinsic + 30_000
	exact := new(big.Int).Mul(new(big.Int).SetUint64(limit), big.NewInt(price)) // rate 1:1
	installFeeCurrency(t, e, fcToken, loadHex(t, "FLTestDollar"), 1, 1, fcIntrinsic, acct, exact)
	commitEnv(t, e)
	fresh := common.HexToAddress("0x000000000000000000000000000000000000f4e5")

	rcpt, err := e.applyAt(e.signFC(key, dest, 0, nil, limit, price, &fcToken), fresh)
	if err != nil {
		t.Fatalf("worst-case credit made the transaction invalid: %v", err)
	}
	if rcpt.Status != types.ReceiptStatusSuccessful {
		t.Fatal("transaction failed")
	}
	fee := new(big.Int).Mul(new(big.Int).SetUint64(rcpt.GasUsed), big.NewInt(price))
	if got := tokenBalance(e, fresh); got.Cmp(fee) != 0 {
		t.Fatalf("producer got %v, want %v", got, fee)
	}
	if got := tokenBalance(e, acct); got.Cmp(new(big.Int).Sub(exact, fee)) != 0 {
		t.Fatalf("sender refund %v, want %v", got, new(big.Int).Sub(exact, fee))
	}
}

// A token credit that fails after execution (here: an intrinsic gas
// budget too small for the worst-case credit) makes the transaction invalid.
// The miner then reverts to its pre-transaction snapshot, which crosses the
// access list / transient storage reset in Prepare: that revert must not
// panic (it did: "reverting slot change, address not present in list", a
// process crash on every validator that tried the transaction) and must leave
// the state exactly as before.
func TestFeeCurrencyCreditFailureRevertsCleanly(t *testing.T) {
	e := newPQEnv(t)
	key, _ := pq.GenerateKey()
	acct := key.Address()
	dest := common.HexToAddress("0x00000000000000000000000000000000000000aa")
	price := int64(1e9)
	const tight = 20_000 // enough for the debit, not for the credit
	limit := uint64(21000) + pq.AuthGas(pq.SchemeMLDSA87) + tight + 30_000
	exact := new(big.Int).Mul(new(big.Int).SetUint64(limit), big.NewInt(price))
	installFeeCurrency(t, e, fcToken, loadHex(t, "FLTestDollar"), 1, 1, tight, acct, exact)
	commitEnv(t, e)
	fresh := common.HexToAddress("0x000000000000000000000000000000000000f4e5")

	rcpt, err := e.applyAt(e.signFC(key, dest, 0, nil, limit, price, &fcToken), fresh) // reverts on error like the miner
	if !errors.Is(err, ErrFeeCurrencyCredit) {
		t.Fatalf("got %v / %v, want %v", rcpt, err, ErrFeeCurrencyCredit)
	}
	if e.db.GetNonce(acct) != 0 || tokenBalance(e, acct).Cmp(exact) != 0 || tokenBalance(e, fresh).Sign() != 0 || tokenSupply(e).Cmp(exact) != 0 {
		t.Fatalf("state not restored: nonce %d balance %v producer %v supply %v", e.db.GetNonce(acct), tokenBalance(e, acct), tokenBalance(e, fresh), tokenSupply(e))
	}
	// and the pool check must refuse the same transaction up front
	intr := 21000 + pq.AuthGas(pq.SchemeMLDSA87)
	evm := NewFeeCurrencyEVM(e.cfg, e.header, e.db)
	if err := CheckFeeCurrencyTx(evm, e.signFC(key, dest, 0, nil, limit, price, &fcToken), acct, intr); !errors.Is(err, ErrFeeCurrencyCredit) {
		t.Fatalf("pool check: got %v, want %v", err, ErrFeeCurrencyCredit)
	}
	if tokenBalance(e, acct).Cmp(exact) != 0 || tokenSupply(e).Cmp(exact) != 0 {
		t.Fatal("pool check changed state")
	}
}

// Storage refunds earned inside the debit call (the token clearing the
// sender's balance slot) must not lower the gas the sender pays: the sender
// did not pay gas for that SSTORE. A sender whose balance is exactly the
// debit must use the same gas as one with a surplus.
func TestFeeCurrencyDebitRefundNotCounted(t *testing.T) {
	run := func(surplus int64) uint64 {
		e := newPQEnv(t)
		key, _ := pq.GenerateKey()
		acct := key.Address()
		dest := common.HexToAddress("0x00000000000000000000000000000000000000aa")
		price := int64(1e9)
		limit := uint64(21000) + pq.AuthGas(pq.SchemeMLDSA87) + fcIntrinsic + 30_000
		bal := new(big.Int).Mul(new(big.Int).SetUint64(limit), big.NewInt(price))
		bal.Add(bal, big.NewInt(surplus))
		installFeeCurrency(t, e, fcToken, loadHex(t, "FLTestDollar"), 1, 1, fcIntrinsic, acct, bal)
		commitEnv(t, e)
		rcpt, err := e.applyAt(e.signFC(key, dest, 0, nil, limit, price, &fcToken), fcCoinbase)
		if err != nil || rcpt.Status != types.ReceiptStatusSuccessful {
			t.Fatalf("apply: %v", err)
		}
		return rcpt.GasUsed
	}
	exact, surplus := run(0), run(1)
	if exact != surplus {
		t.Fatalf("gas used with an exactly-debited balance %d != with surplus %d (debit refund leaked into the transaction)", exact, surplus)
	}
}

// commitEnv commits the fixture so storage "original" values are the committed
// ones, as on a live chain (EIP-2200 refunds depend on it).
func commitEnv(t *testing.T, e *pqEnv) {
	root, err := e.db.Commit(0, true, false)
	if err != nil {
		t.Fatal(err)
	}
	db, err := state.New(root, e.db.Database())
	if err != nil {
		t.Fatal(err)
	}
	e.db = db
}

// The debit clears the sender's balance slot (EIP-2200 refund), the
// transaction itself refills it through a token transfer from a contract
// (EIP-2200 takes the refund back), then the credit refills it again. The
// refund bookkeeping around the debit must survive this without a refund
// counter underflow (a panic) and the sender must still get the full refund
// of the unused gas.
func TestFeeCurrencyDebitClearedSlotRefilled(t *testing.T) {
	e := newPQEnv(t)
	key, _ := pq.GenerateKey()
	acct := key.Address()
	price := int64(1e9)
	limit := uint64(21000) + pq.AuthGas(pq.SchemeMLDSA87) + fcIntrinsic + 60_000
	exact := new(big.Int).Mul(new(big.Int).SetUint64(limit), big.NewInt(price))
	helper := common.HexToAddress("0x000000000000000000000000000000000000be1f")
	installFeeCurrency(t, e, fcToken, loadHex(t, "FLTestDollar"), 1, 1, fcIntrinsic, acct, new(big.Int).Add(exact, big.NewInt(1e18)))
	e.db.SetState(fcToken, mapSlot(acct, 0), common.BigToHash(exact))
	e.db.SetState(fcToken, mapSlot(helper, 0), common.BigToHash(big.NewInt(1e18)))
	// helper: token.transfer(acct, 1)
	code := []byte{0x63, 0xa9, 0x05, 0x9c, 0xbb, 0x60, 0xe0, 0x1b, 0x60, 0x00, 0x52}
	code = append(code, 0x73)
	code = append(code, acct.Bytes()...)
	code = append(code, 0x60, 0x04, 0x52, 0x60, 0x01, 0x60, 0x24, 0x52,
		0x60, 0x00, 0x60, 0x00, 0x60, 0x44, 0x60, 0x00, 0x60, 0x00, 0x73)
	code = append(code, fcToken.Bytes()...)
	code = append(code, 0x5a, 0xf1, 0x50, 0x00)
	e.db.SetCode(helper, code, tracing.CodeChangeUnspecified)
	commitEnv(t, e)

	rcpt, err := e.applyAt(e.signFC(key, helper, 0, nil, limit, price, &fcToken), fcCoinbase)
	if err != nil || rcpt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("apply: %v (status %d)", err, rcpt.Status)
	}
	fee := new(big.Int).Mul(new(big.Int).SetUint64(rcpt.GasUsed), big.NewInt(price))
	want := new(big.Int).Sub(exact, fee)
	want.Add(want, big.NewInt(1))
	if got := tokenBalance(e, acct); got.Cmp(want) != 0 {
		t.Fatalf("sender balance %v, want %v", got, want)
	}
	if tokenBalance(e, helper).Cmp(new(big.Int).Sub(big.NewInt(1e18), big.NewInt(1))) != 0 {
		t.Fatal("helper transfer did not happen")
	}
}

// The sender may be the block producer (a validator paying in a token).
func TestFeeCurrencySenderIsCoinbase(t *testing.T) {
	e := newPQEnv(t)
	key, _ := pq.GenerateKey()
	acct := key.Address()
	supply := big.NewInt(1e18)
	installFeeCurrency(t, e, fcToken, loadHex(t, "FLTestDollar"), 1, 1, fcIntrinsic, acct, supply)
	limit := uint64(21000) + pq.AuthGas(pq.SchemeMLDSA87) + fcIntrinsic + 10_000
	rcpt, err := e.applyAt(e.signFC(key, fcCoinbase, 0, nil, limit, 1, &fcToken), acct)
	if err != nil || rcpt.Status != types.ReceiptStatusSuccessful {
		t.Fatalf("apply: %v", err)
	}
	if tokenBalance(e, acct).Cmp(supply) != 0 || tokenSupply(e).Cmp(supply) != 0 {
		t.Fatalf("self-paid fee changed balances: %v / %v", tokenBalance(e, acct), tokenSupply(e))
	}
}

// Tracing a token-paid transaction must not panic and must leave the
// tracer installed on the shared EVM afterwards.
func TestFeeCurrencyTraced(t *testing.T) {
	e := newPQEnv(t)
	key, _ := pq.GenerateKey()
	acct := key.Address()
	installFeeCurrency(t, e, fcToken, loadHex(t, "FLTestDollar"), 1, 1, fcIntrinsic, acct, big.NewInt(1e18))
	limit := uint64(21000) + pq.AuthGas(pq.SchemeMLDSA87) + fcIntrinsic + 10_000
	tx := e.signFC(key, fcCoinbase, 0, nil, limit, 1, &fcToken)

	hooks := &tracing.Hooks{
		OnGasChange: func(old, new uint64, reason tracing.GasChangeReason) {},
		OnEnter:     func(depth int, typ byte, from, to common.Address, input []byte, gas uint64, value *big.Int) {},
		OnExit:      func(depth int, output []byte, gasUsed uint64, err error, reverted bool) {},
		OnOpcode: func(pc uint64, op byte, gas, cost uint64, scope tracing.OpContext, rData []byte, depth int, err error) {
		},
	}
	ctx := NewEVMBlockContext(e.header, nil, &fcCoinbase)
	ctx.GetHash = func(uint64) common.Hash { return common.Hash{} }
	evm := vm.NewEVM(ctx, e.db, e.cfg, vm.Config{Tracer: hooks})
	e.db.SetTxContext(tx.Hash(), 0)
	if _, err := ApplyTransaction(evm, NewGasPool(e.header.GasLimit), e.db, e.header, tx); err != nil {
		t.Fatal(err)
	}
	if evm.Config.Tracer != hooks {
		t.Fatal("tracer not restored after the fee currency calls")
	}
}
