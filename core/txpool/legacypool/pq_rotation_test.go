package legacypool

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/pq"
)

// Regression: after an account rotates its PQ key, transactions signed by the
// old key can never execute. They must leave the pool at the next reset, or
// they block the new key's transaction at the same nonce.
func TestPoolDropsRetiredPQKeys(t *testing.T) {
	for _, nonce := range []uint64{1, 5} {
		pool, _ := setupPoolWithConfig(eip1559Config)
		key1, err := pq.KeyFromSeed(pq.SchemeMLDSA87, [32]byte{41})
		if err != nil {
			t.Fatal(err)
		}
		key2, err := pq.KeyFromSeed(pq.SchemeMLDSA87, [32]byte{42})
		if err != nil {
			t.Fatal(err)
		}
		account := key1.Address()
		testAddBalance(pool, account, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
		sign := func(key *pq.PrivateKey) *types.Transaction {
			to := common.HexToAddress("0x1234")
			unsigned := types.NewTx(&types.PQTx{ChainID: eip1559Config.ChainID, Nonce: nonce,
				GasTipCap: big.NewInt(10), GasFeeCap: big.NewInt(10), Gas: 137000,
				To: &to, Value: big.NewInt(1), From: account, Scheme: uint8(key.Scheme)})
			tx, err := types.SignPQTx(unsigned, pool.signer, key)
			if err != nil {
				t.Fatal(err)
			}
			return tx
		}
		oldTx := sign(key1)
		if err := pool.addRemote(oldTx); err != nil {
			t.Fatalf("nonce %d: old-key admission: %v", nonce, err)
		}
		// the new head: the rotation at nonce 0 executed
		testSetNonce(pool, account, 1)
		pool.mu.Lock()
		pool.currentState.SetState(pq.RegistryAddress, pq.RegistrySlot(account), pq.KeyHash(key2.Scheme, key2.PublicKey()))
		if core.CheckPQAuthorization(pool.currentState, account, key1.Scheme, key1.PublicKey()) == nil {
			t.Fatal("fixture did not revoke the old key")
		}
		pool.mu.Unlock()
		<-pool.requestReset(nil, nil)
		if pool.Has(oldTx.Hash()) {
			t.Errorf("nonce %d: old-key transaction survived the reset", nonce)
		}
		newTx := sign(key2)
		if err := pool.addRemote(newTx); err != nil {
			t.Errorf("nonce %d: new-key transaction rejected: %v", nonce, err)
		}
		if err := validatePoolInternals(pool); err != nil {
			t.Error(err)
		}
		// a reorg back to the old key drops new-key transactions the same way
		pool.mu.Lock()
		pool.currentState.SetState(pq.RegistryAddress, pq.RegistrySlot(account), common.Hash{})
		pool.mu.Unlock()
		<-pool.requestReset(nil, nil)
		if pool.Has(newTx.Hash()) {
			t.Errorf("nonce %d: new-key transaction survived the registry rollback", nonce)
		}
		if err := validatePoolInternals(pool); err != nil {
			t.Error(err)
		}
		pool.Close()
	}
}
