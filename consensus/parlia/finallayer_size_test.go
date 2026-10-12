package parlia

import (
	"math"
	"math/big"
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/systemcontracts"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// maxFinalLayerValidators mirrors StakeHub.MAX_INFLATION_VALIDATORS, the
// governance upper bound of maxElectedValidators.
const maxFinalLayerValidators = 50

// signedSystemTxSize is the RLP size of a PQ system transaction as the miner
// appends it in finalizeAndAssemble (ML-DSA-87 key and signature included).
func signedSystemTxSize(t *testing.T, to string, data []byte, value *big.Int) uint64 {
	t.Helper()
	addr := common.HexToAddress(to)
	tx := types.NewTx(&types.PQTx{
		ChainID:   big.NewInt(20261012),
		Nonce:     math.MaxUint64 / 2,
		GasTipCap: new(big.Int),
		GasFeeCap: new(big.Int),
		Gas:       math.MaxUint64 / 2,
		To:        &addr,
		Value:     value,
		Data:      data,
		From:      common.HexToAddress("0xffffffffffffffffffffffffffffffffffffffff"),
		Scheme:    uint8(pq.SchemeMLDSA87),
		PubKey:    make([]byte, pq.PublicKeySize(pq.SchemeMLDSA87)),
		Signature: make([]byte, pq.SignatureSize(pq.SchemeMLDSA87)),
	})
	return tx.Size()
}

// The miner stops adding user transactions FinalLayerBlockSizeBufferZone
// bytes below the consensus cap; everything added after that (the PQ-signed
// system transactions of the worst-case block, and any error in the header
// size estimate the miner starts from) must fit in the buffer, or the
// producer's own block is invalid on every other node.
func TestFinalLayerSystemTxsFitSizeBuffer(t *testing.T) {
	vABI, err := abi.JSON(strings.NewReader(validatorSetABI))
	if err != nil {
		t.Fatal(err)
	}
	sABI, err := abi.JSON(strings.NewReader(slashABI))
	if err != nil {
		t.Fatal(err)
	}
	maxValue, _ := new(big.Int).SetString("ffffffffffffffffffffffffffffffff", 16) // 2^128-1 wei
	n := maxFinalLayerValidators
	vals := make([]common.Address, n)
	powers := make([]uint64, n)
	weights := make([]*big.Int, n)
	voteAddrs := make([][]byte, n)
	for i := range vals {
		vals[i] = common.BigToAddress(big.NewInt(int64(i + 1)))
		powers[i] = math.MaxUint64
		weights[i] = new(big.Int).SetUint64(math.MaxUint64)
		voteAddrs[i] = make([]byte, types.BLSPublicKeyLength)
	}
	pack := func(a abi.ABI, method string, args ...interface{}) []byte {
		data, err := a.Pack(method, args...)
		if err != nil {
			t.Fatalf("pack %s: %v", method, err)
		}
		return data
	}
	initData := pack(vABI, "init")
	slash := signedSystemTxSize(t, systemcontracts.SlashContract, pack(sABI, "slash", vals[0]), new(big.Int))
	deposit := signedSystemTxSize(t, systemcontracts.ValidatorContract, pack(vABI, "deposit", vals[0]), maxValue)
	finality := signedSystemTxSize(t, systemcontracts.ValidatorContract, pack(vABI, "distributeFinalityReward", vals, weights), new(big.Int))
	update := signedSystemTxSize(t, systemcontracts.ValidatorContract, pack(vABI, "updateValidatorSetV2", vals, powers, voteAddrs), new(big.Int))
	inflation := signedSystemTxSize(t, systemcontracts.StakeHubContract, pack(flStakeABI, "distributeStakingInflation"), maxValue)
	initTx := signedSystemTxSize(t, systemcontracts.ValidatorContract, initData, new(big.Int))
	// distributeToSystem never runs (Kepler is active from genesis).

	// Worst case after block 1: an off-turn breathe block on the finality
	// reward interval. Block 1 (never on the interval) adds the 7 init txs
	// and may also be a breathe block when genesis is on an earlier UTC day.
	steady := slash + deposit + finality + update + inflation
	block1 := 7*initTx + slash + deposit + update + inflation
	worst := steady
	if block1 > worst {
		worst = block1
	}

	// Header: worst epoch extra (vanity + count + 50 x (address + BLS key) +
	// turnLength + ML-DSA seal) with every optional field set. The miner
	// starts env.size at header.Size(), an estimate; count any shortfall.
	extra := make([]byte, extraVanity+validatorNumberSize+n*validatorBytesLength+turnLengthSize+extraSeal)
	h := &types.Header{
		Difficulty: big.NewInt(2), Number: big.NewInt(math.MaxUint32), GasLimit: 40_000_000,
		GasUsed: 40_000_000, Time: math.MaxUint32, Extra: extra, BaseFee: big.NewInt(math.MaxUint32),
		WithdrawalsHash: &common.Hash{}, BlobGasUsed: new(uint64), ExcessBlobGas: new(uint64),
		ParentBeaconRoot: &common.Hash{}, RequestsHash: &common.Hash{},
	}
	enc, err := rlp.EncodeToBytes(h)
	if err != nil {
		t.Fatal(err)
	}
	var headerShortfall uint64
	if uint64(len(enc)) > uint64(h.Size()) {
		headerShortfall = uint64(len(enc)) - uint64(h.Size())
	}
	const listOverhead = 32 // outer block list + tx/uncle/withdrawal list headers
	need := worst + headerShortfall + listOverhead
	t.Logf("system tx bytes: slash=%d deposit=%d finality=%d update=%d inflation=%d init=%d; steady=%d block1=%d; header rlp=%d est=%d; need=%d buffer=%d",
		slash, deposit, finality, update, inflation, initTx, steady, block1, len(enc), uint64(h.Size()), need, params.FinalLayerBlockSizeBufferZone)
	if need >= params.FinalLayerBlockSizeBufferZone {
		t.Fatalf("worst-case trailing bytes %d do not fit the %d-byte buffer", need, params.FinalLayerBlockSizeBufferZone)
	}
}
