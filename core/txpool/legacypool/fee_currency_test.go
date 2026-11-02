package legacypool

import (
	"errors"
	"math/big"
	"os"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/pq"
)

var (
	fcPoolOracle = common.HexToAddress("0x0000000000000000000000000000000000005053")
	fcPoolToken  = common.HexToAddress("0x0000000000000000000000000000000000005054")
)

func fcCode(t *testing.T, name string) []byte {
	b, err := os.ReadFile("../../testdata/feecurrency/" + name + ".hex")
	if err != nil {
		t.Fatal(err)
	}
	return hexutil.MustDecode(strings.TrimSpace(string(b)))
}

func fcSlot(key common.Address, slot int64) common.Hash {
	return crypto.Keccak256Hash(common.LeftPadBytes(key.Bytes(), 32), common.LeftPadBytes(big.NewInt(slot).Bytes(), 32))
}

func fcPlus(h common.Hash, n int64) common.Hash {
	return common.BigToHash(new(big.Int).Add(h.Big(), big.NewInt(n)))
}

// installPoolFeeCurrency lists fcPoolToken at rate 1:1 with 50,000 intrinsic
// gas, like the genesis generator does.
func installPoolFeeCurrency(t *testing.T, pool *LegacyPool) {
	pool.mu.Lock()
	defer pool.mu.Unlock()
	db := pool.currentState
	db.SetCode(core.FeeCurrencyDirectoryAddress, fcCode(t, "FeeCurrencyDirectory"), tracing.CodeChangeUnspecified)
	db.SetCode(fcPoolOracle, fcCode(t, "FixedRateOracle"), tracing.CodeChangeUnspecified)
	db.SetCode(fcPoolToken, fcCode(t, "FLTestDollar"), tracing.CodeChangeUnspecified)
	cfg := fcSlot(fcPoolToken, 0)
	db.SetState(core.FeeCurrencyDirectoryAddress, cfg, common.BytesToHash(fcPoolOracle.Bytes()))
	db.SetState(core.FeeCurrencyDirectoryAddress, fcPlus(cfg, 1), common.BigToHash(big.NewInt(50_000))) // mirrors FLTD_INTRINSIC_GAS in scripts/make_genesis.py
	db.SetState(fcPoolOracle, fcSlot(fcPoolToken, 0), common.BigToHash(new(big.Int).Or(new(big.Int).Lsh(big.NewInt(1), 128), big.NewInt(1))))
	// totalSupply (slot 2) must cover every balance set by setTokenBalance:
	// the token keeps supply >= sum of balances and the credit checks it.
	db.SetState(fcPoolToken, common.BigToHash(big.NewInt(2)), common.BigToHash(new(big.Int).Lsh(big.NewInt(1), 64)))
}

func setTokenBalance(pool *LegacyPool, a common.Address, v int64) {
	pool.mu.Lock()
	pool.currentState.SetState(fcPoolToken, fcSlot(a, 0), common.BigToHash(big.NewInt(v)))
	pool.mu.Unlock()
}

func signFeeTx(t *testing.T, pool *LegacyPool, key *pq.PrivateKey, nonce uint64, price int64, fc *common.Address) *types.Transaction {
	to := common.HexToAddress("0x1234")
	unsigned := types.NewTx(&types.PQTx{ChainID: eip1559Config.ChainID, Nonce: nonce,
		GasTipCap: big.NewInt(price), GasFeeCap: big.NewInt(price), Gas: 200_000,
		To: &to, Value: new(big.Int), From: key.Address(), Scheme: uint8(key.Scheme), FeeCurrency: fc})
	tx, err := types.SignPQTx(unsigned, pool.signer, key)
	if err != nil {
		t.Fatal(err)
	}
	return tx
}

func TestPoolFeeCurrency(t *testing.T) {
	pool, _ := setupPoolWithConfig(eip1559Config)
	defer pool.Close()
	installPoolFeeCurrency(t, pool)
	key, _ := pq.KeyFromSeed(pq.SchemeMLDSA87, [32]byte{51})
	poor, _ := pq.KeyFromSeed(pq.SchemeMLDSA87, [32]byte{52})
	acct := key.Address()
	setTokenBalance(pool, acct, 10_000_000) // no FL at all
	setTokenBalance(pool, poor.Address(), 1_000)
	token := fcPoolToken

	first := signFeeTx(t, pool, key, 0, 10, &token)
	if err := pool.addRemote(first); err != nil {
		t.Fatalf("token-paid tx from a 0-FL account rejected: %v", err)
	}
	if err := pool.addRemote(signFeeTx(t, pool, key, 1, 10, &token)); !errors.Is(err, ErrFeeCurrencyLimit) {
		t.Fatalf("second pooled fee currency tx: got %v", err)
	}
	// replacing the same nonce is allowed
	repl := signFeeTx(t, pool, key, 0, 20, &token)
	if err := pool.addRemote(repl); err != nil {
		t.Fatalf("replacement rejected: %v", err)
	}
	if pool.Has(first.Hash()) || !pool.Has(repl.Hash()) {
		t.Fatal("replacement not applied")
	}
	// a sender without enough token for gasLimit * feeCap
	if err := pool.addRemote(signFeeTx(t, pool, poor, 0, 10, &token)); !errors.Is(err, core.ErrInsufficientFunds) {
		t.Fatalf("poor sender: got %v", err)
	}
	// an unlisted token
	other := common.HexToAddress("0x0000000000000000000000000000000000005055")
	setTokenBalance(pool, poor.Address(), 1_000_000_000)
	if err := pool.addRemote(signFeeTx(t, pool, poor, 0, 10, &other)); !errors.Is(err, core.ErrFeeCurrencyNotAllowed) {
		t.Fatalf("unlisted token: got %v", err)
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatal(err)
	}
	// A token whose intrinsic gas cannot cover its own worst-case
	// credit is refused up front (the transaction would be invalid at
	// execution and retried by every producer on every block).
	pool.mu.Lock()
	pool.currentState.SetState(core.FeeCurrencyDirectoryAddress, fcPlus(fcSlot(fcPoolToken, 0), 1), common.BigToHash(big.NewInt(20_000)))
	pool.mu.Unlock()
	setTokenBalance(pool, poor.Address(), 1_000_000_000)
	if err := pool.addRemote(signFeeTx(t, pool, poor, 0, 10, &token)); !errors.Is(err, core.ErrFeeCurrencyCredit) {
		t.Fatalf("tight credit budget: got %v", err)
	}
	pool.mu.Lock()
	pool.currentState.SetState(core.FeeCurrencyDirectoryAddress, fcPlus(fcSlot(fcPoolToken, 0), 1), common.BigToHash(big.NewInt(50_000)))
	bal := pool.currentState.GetState(fcPoolToken, fcSlot(poor.Address(), 0)).Big()
	pool.mu.Unlock()
	if bal.Int64() != 1_000_000_000 {
		t.Fatalf("dry run changed the pool state: balance %v", bal)
	}
	if err := pool.addRemote(signFeeTx(t, pool, poor, 0, 10, &token)); err != nil {
		t.Fatalf("after restoring the budget: %v", err)
	}
	// the token balance is spent elsewhere: the pooled tx leaves at the next reset
	setTokenBalance(pool, acct, 0)
	<-pool.requestReset(nil, nil)
	if pool.Has(repl.Hash()) {
		t.Fatal("unpayable fee currency transaction survived the reset")
	}
	if err := validatePoolInternals(pool); err != nil {
		t.Fatal(err)
	}
}
