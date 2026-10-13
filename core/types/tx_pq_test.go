package types

import (
	"encoding/json"
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/params"
)

func newTestPQTx(from common.Address) *Transaction {
	to := common.HexToAddress("0xdead")
	return NewTx(&PQTx{
		ChainID:   big.NewInt(7777),
		Nonce:     3,
		GasTipCap: big.NewInt(1),
		GasFeeCap: big.NewInt(2),
		Gas:       100000,
		To:        &to,
		Value:     big.NewInt(5),
		Data:      []byte{1, 2, 3},
		From:      from,
		Scheme:    uint8(pq.SchemeMLDSA87),
	})
}

func TestPQTxSignAndSender(t *testing.T) {
	key, _ := pq.GenerateKey()
	signer := LatestSignerForChainID(big.NewInt(7777))
	tx, err := SignPQTx(newTestPQTx(key.Address()), signer, key)
	if err != nil {
		t.Fatal(err)
	}
	from, err := Sender(signer, tx)
	if err != nil || from != key.Address() {
		t.Fatalf("sender %v err %v", from, err)
	}
	// Binary round trip
	raw, err := tx.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if raw[0] != PQTxType {
		t.Fatalf("type byte %x", raw[0])
	}
	var dec Transaction
	if err := dec.UnmarshalBinary(raw); err != nil {
		t.Fatal(err)
	}
	if dec.Hash() != tx.Hash() {
		t.Fatal("hash changed after round trip")
	}
	if f, err := Sender(signer, &dec); err != nil || f != key.Address() {
		t.Fatalf("decoded sender %v %v", f, err)
	}
	// JSON round trip
	js, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var jtx Transaction
	if err := json.Unmarshal(js, &jtx); err != nil {
		t.Fatal(err)
	}
	if jtx.Hash() != tx.Hash() {
		t.Fatal("json round trip changed hash")
	}
}

func TestPQTxTamperRejected(t *testing.T) {
	key, _ := pq.GenerateKey()
	signer := LatestSignerForChainID(big.NewInt(7777))
	tx, _ := SignPQTx(newTestPQTx(key.Address()), signer, key)
	raw, _ := tx.MarshalBinary()

	// Change every signed field one by one by re-encoding a modified copy.
	inner := tx.inner.(*PQTx)
	mods := []func(p *PQTx){
		func(p *PQTx) { p.Nonce++ },
		func(p *PQTx) { p.Value = big.NewInt(6) },
		func(p *PQTx) { p.Gas++ },
		func(p *PQTx) { p.GasFeeCap = big.NewInt(3) },
		func(p *PQTx) { p.GasTipCap = big.NewInt(2) },
		func(p *PQTx) { p.Data = []byte{9} },
		func(p *PQTx) { a := common.HexToAddress("0xbeef"); p.To = &a },
		func(p *PQTx) { p.From = common.HexToAddress("0x1111") },
		func(p *PQTx) { p.Signature[0] ^= 1 },
	}
	for i, m := range mods {
		c := inner.copy().(*PQTx)
		m(c)
		if _, err := Sender(signer, NewTx(c)); err == nil {
			t.Fatalf("modification %d accepted", i)
		}
	}
	// Wrong chain id signer
	other := LatestSignerForChainID(big.NewInt(1))
	var dec Transaction
	_ = dec.UnmarshalBinary(raw)
	if _, err := Sender(other, &dec); err == nil {
		t.Fatal("tx accepted under a different chain id")
	}
}

func TestClassicalSignaturesRejected(t *testing.T) {
	ecKey, _ := crypto.GenerateKey()
	chainID := big.NewInt(7777)
	to := common.HexToAddress("0xdead")
	cfg := &params.ChainConfig{ChainID: chainID, HomesteadBlock: big.NewInt(0), EIP155Block: big.NewInt(0), BerlinBlock: big.NewInt(0), LondonBlock: big.NewInt(0)}
	signers := []Signer{
		LatestSignerForChainID(chainID),
		LatestSigner(cfg),
		MakeSigner(cfg, big.NewInt(0), 0),
		NewEIP155Signer(chainID),
		HomesteadSigner{},
		FrontierSigner{},
	}
	txdatas := []TxData{
		&LegacyTx{Nonce: 0, To: &to, Value: big.NewInt(1), Gas: 21000, GasPrice: big.NewInt(1)},
		&AccessListTx{ChainID: chainID, Nonce: 0, To: &to, Value: big.NewInt(1), Gas: 21000, GasPrice: big.NewInt(1)},
		&DynamicFeeTx{ChainID: chainID, Nonce: 0, To: &to, Value: big.NewInt(1), Gas: 21000, GasFeeCap: big.NewInt(1), GasTipCap: big.NewInt(1)},
	}
	for _, s := range signers {
		for _, d := range txdatas {
			tx, err := SignNewTx(ecKey, s, d)
			if err != nil {
				continue // signer does not support the type at all
			}
			if _, err := Sender(s, tx); err == nil {
				t.Fatalf("ECDSA tx type %d accepted by %T", tx.Type(), s)
			} else if !errors.Is(err, ErrClassicalSignatureDisabled) && !errors.Is(err, ErrTxTypeNotSupported) {
				t.Logf("signer %T type %d rejected with %v", s, tx.Type(), err)
			}
		}
	}
	// Even the pre-Berlin MakeSigner must understand PQ transactions.
	pk, _ := pq.GenerateKey()
	early := MakeSigner(&params.ChainConfig{ChainID: chainID, HomesteadBlock: big.NewInt(0), EIP155Block: big.NewInt(0), BerlinBlock: big.NewInt(100)}, big.NewInt(1), 0)
	tx, err := SignPQTx(newTestPQTx(pk.Address()), early, pk)
	if err != nil {
		t.Fatal(err)
	}
	if f, err := Sender(early, tx); err != nil || f != pk.Address() {
		t.Fatalf("pre-Berlin signer rejected PQ tx: %v", err)
	}
}

// A pqScheme above one byte must be rejected, not wrapped (0x101 -> 0x01).
func TestPQTxJSONSchemeOverflow(t *testing.T) {
	key, _ := pq.GenerateKey()
	tx, err := SignPQTx(newTestPQTx(key.Address()), LatestSignerForChainID(big.NewInt(7777)), key)
	if err != nil {
		t.Fatal(err)
	}
	js, err := json.Marshal(tx)
	if err != nil {
		t.Fatal(err)
	}
	var fields map[string]interface{}
	if err := json.Unmarshal(js, &fields); err != nil {
		t.Fatal(err)
	}
	fields["pqScheme"] = "0x101"
	bad, _ := json.Marshal(fields)
	var dec Transaction
	if err := json.Unmarshal(bad, &dec); err == nil {
		t.Fatal("pqScheme 0x101 accepted")
	}
}
