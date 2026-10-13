package native_test

import (
	"encoding/json"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core"
	"github.com/ethereum/go-ethereum/core/state"
	"github.com/ethereum/go-ethereum/core/tracing"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/core/vm"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/eth/tracers"
	_ "github.com/ethereum/go-ethereum/eth/tracers/native"
	"github.com/ethereum/go-ethereum/params"
	"github.com/holiman/uint256"
)

// Regression: a key rotation is executed natively (no evm.Call), so
// it must still give tracers a top-level frame and the registry write.

type pqTraceCase struct {
	rotate   bool // send a rotation, otherwise a plain transfer
	badProof bool
	gas      uint64 // 0 means 2,000,000
	oog      bool   // one gas short of finishing the rotation
	value    int64
}

func tracePQTx(t *testing.T, c pqTraceCase, name string, cfg string) (json.RawMessage, *types.Receipt, common.Address, common.Hash) {
	t.Helper()
	chain := *params.TestChainConfig
	key1, err := pq.KeyFromSeed(pq.SchemeMLDSA87, [32]byte{51})
	if err != nil {
		t.Fatal(err)
	}
	key2, err := pq.KeyFromSeed(pq.SchemeMLDSA87, [32]byte{52})
	if err != nil {
		t.Fatal(err)
	}
	from := key1.Address()
	db, err := state.New(types.EmptyRootHash, state.NewDatabaseForTesting())
	if err != nil {
		t.Fatal(err)
	}
	db.SetNonce(pq.RegistryAddress, 1, tracing.NonceChangeGenesis)
	db.SetCode(pq.RegistryAddress, []byte{0xfe}, tracing.CodeChangeGenesis)
	db.AddBalance(from, uint256.NewInt(1e18), tracing.BalanceChangeUnspecified)

	to, data := common.HexToAddress("0x1234"), []byte(nil)
	if c.rotate {
		to = pq.RegistryAddress
		nonce := uint64(0)
		if c.badProof {
			nonce = 7 // proof bound to another nonce
		}
		if data, err = pq.EncodeRotation(key2, chain.ChainID.Uint64(), from, nonce); err != nil {
			t.Fatal(err)
		}
	}
	gas := c.gas
	if gas == 0 {
		gas = 2_000_000
	}
	if c.oog {
		// the proof is randomized, so the calldata cost is computed per tx
		intrinsic, err := core.IntrinsicGas(data, nil, nil, false, true, true, true, false)
		if err != nil {
			t.Fatal(err)
		}
		gas = intrinsic.RegularGas + pq.AuthGas(key1.Scheme) + pq.RotationGas - 1
	}
	tx, err := types.SignPQTx(types.NewTx(&types.PQTx{ChainID: chain.ChainID, Nonce: 0,
		GasTipCap: big.NewInt(1), GasFeeCap: big.NewInt(1), Gas: gas, To: &to,
		Value: big.NewInt(c.value), Data: data, From: from, Scheme: uint8(key1.Scheme)}), types.LatestSigner(&chain), key1)
	if err != nil {
		t.Fatal(err)
	}
	tracer, err := tracers.DefaultDirectory.New(name, &tracers.Context{}, json.RawMessage(cfg), &chain)
	if err != nil {
		t.Fatal(err)
	}
	header := &types.Header{Number: big.NewInt(1), Time: 1, Difficulty: big.NewInt(1), GasLimit: 30_000_000, BaseFee: big.NewInt(0)}
	blockCtx := core.NewEVMBlockContext(header, nil, &common.Address{})
	blockCtx.GetHash = func(uint64) common.Hash { return common.Hash{} }
	evm := vm.NewEVM(blockCtx, db, &chain, vm.Config{Tracer: tracer.Hooks})
	db.SetTxContext(tx.Hash(), 0)
	receipt, err := core.ApplyTransaction(evm, core.NewGasPool(header.GasLimit), db, header, tx)
	if err != nil {
		t.Fatal(err)
	}
	result, err := tracer.GetResult()
	if err != nil {
		t.Fatal(err)
	}
	return result, receipt, from, pq.KeyHash(key2.Scheme, key2.PublicKey())
}

type callFrame struct {
	Type    string         `json:"type"`
	To      common.Address `json:"to"`
	GasUsed string         `json:"gasUsed"`
	Error   string         `json:"error"`
}

func TestCallTracerNativeRotation(t *testing.T) {
	result, receipt, _, _ := tracePQTx(t, pqTraceCase{rotate: true}, "callTracer", `{"withLog":true}`)
	if receipt.Status != types.ReceiptStatusSuccessful {
		t.Fatal("rotation failed")
	}
	var f callFrame
	if err := json.Unmarshal(result, &f); err != nil {
		t.Fatal(err)
	}
	if f.Type != "CALL" || f.To != pq.RegistryAddress || f.Error != "" {
		t.Fatalf("wrong top-level frame: %s", result)
	}
	if f.GasUsed != (*hexUint)(&receipt.GasUsed).String() {
		t.Fatalf("frame gas %s, receipt gas %d", f.GasUsed, receipt.GasUsed)
	}
}

func TestCallTracerFailedNativeRotation(t *testing.T) {
	result, receipt, _, _ := tracePQTx(t, pqTraceCase{rotate: true, badProof: true}, "callTracer", `{}`)
	if receipt.Status != types.ReceiptStatusFailed {
		t.Fatal("bad-proof rotation succeeded")
	}
	var f callFrame
	if err := json.Unmarshal(result, &f); err != nil {
		t.Fatal(err)
	}
	if f.To != pq.RegistryAddress || f.Error == "" {
		t.Fatalf("failed rotation not reported in frame: %s", result)
	}
}

func TestPrestateTracerNativeRotationDiff(t *testing.T) {
	result, _, from, want := tracePQTx(t, pqTraceCase{rotate: true}, "prestateTracer", `{"diffMode":true}`)
	var diff struct {
		Post map[common.Address]struct {
			Storage map[common.Hash]common.Hash `json:"storage"`
		} `json:"post"`
	}
	if err := json.Unmarshal(result, &diff); err != nil {
		t.Fatal(err)
	}
	if got := diff.Post[pq.RegistryAddress].Storage[pq.RegistrySlot(from)]; got != want {
		t.Fatalf("registry update missing from diff: got %s want %s\n%s", got, want, result)
	}
}

// A plain PQ transfer depends on the sender's registry slot (read natively
// for authorization), so the prestate must contain it for standalone replay.
func TestPrestateTracerIncludesPQAuthSlot(t *testing.T) {
	result, _, from, _ := tracePQTx(t, pqTraceCase{}, "prestateTracer", `{}`)
	var pre map[common.Address]struct {
		Storage map[common.Hash]common.Hash `json:"storage"`
	}
	if err := json.Unmarshal(result, &pre); err != nil {
		t.Fatal(err)
	}
	if _, ok := pre[pq.RegistryAddress].Storage[pq.RegistrySlot(from)]; !ok {
		t.Fatalf("sender registry slot missing from prestate: %s", result)
	}
	// with storage disabled the slot is not reported
	result, _, _, _ = tracePQTx(t, pqTraceCase{}, "prestateTracer", `{"disableStorage":true}`)
	pre = nil
	if err := json.Unmarshal(result, &pre); err != nil {
		t.Fatal(err)
	}
	if len(pre[pq.RegistryAddress].Storage) != 0 {
		t.Fatalf("storage reported although disabled: %s", result)
	}
}

func rotationFrame(t *testing.T, c pqTraceCase) (callFrame, *types.Receipt) {
	t.Helper()
	result, receipt, _, _ := tracePQTx(t, c, "callTracer", `{}`)
	var f callFrame
	if err := json.Unmarshal(result, &f); err != nil {
		t.Fatal(err)
	}
	if f.To != pq.RegistryAddress {
		t.Fatalf("no rotation frame: %s", result)
	}
	return f, receipt
}

// Out of gas inside the rotation consumes the whole limit, like an EVM call.
func TestCallTracerOutOfGasRotation(t *testing.T) {
	f, receipt := rotationFrame(t, pqTraceCase{rotate: true, oog: true})
	if receipt.Status != types.ReceiptStatusFailed {
		t.Fatal("rotation one gas short succeeded")
	}
	if f.Error != vm.ErrOutOfGas.Error() || f.GasUsed != (*hexUint)(&receipt.GasUsed).String() {
		t.Fatalf("frame %+v, receipt gas %d", f, receipt.GasUsed)
	}
}

func TestCallTracerValueRotation(t *testing.T) {
	f, receipt := rotationFrame(t, pqTraceCase{rotate: true, value: 1})
	if receipt.Status != types.ReceiptStatusFailed || f.Error == "" {
		t.Fatalf("value rotation: status %d frame %+v", receipt.Status, f)
	}
}

// Other native tracers that build on enter/exit frames.
func TestOtherTracersNativeRotation(t *testing.T) {
	for _, tc := range []struct{ name, cfg string }{
		{"flatCallTracer", `{}`},
		{"flatCallTracer", `{"convertParityErrors":true}`},
		{"muxTracer", `{"callTracer":{"onlyTopCall":true},"prestateTracer":{"diffMode":true},"4byteTracer":null}`},
		{"erc7562Tracer", `{}`},
		{"4byteTracer", `{}`},
	} {
		for _, bad := range []bool{false, true} {
			result, _, _, _ := tracePQTx(t, pqTraceCase{rotate: true, badProof: bad}, tc.name, tc.cfg)
			if len(result) == 0 || string(result) == "null" {
				t.Fatalf("%s %s bad=%v: empty result", tc.name, tc.cfg, bad)
			}
		}
	}
}

type hexUint uint64

func (h *hexUint) String() string { return "0x" + new(big.Int).SetUint64(uint64(*h)).Text(16) }
