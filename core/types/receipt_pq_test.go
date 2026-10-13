package types_test

import (
	"bytes"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	. "github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/trie"
)

// Regression: a PQ receipt used to encode to just its type byte, so the
// receipt root ignored status, gas and logs, and it could not be decoded.
func TestPQReceiptCommitsToContents(t *testing.T) {
	a := &Receipt{Type: PQTxType, Status: 1, CumulativeGasUsed: 137000}
	b := &Receipt{Type: PQTxType, Status: 0, CumulativeGasUsed: 274000,
		Logs: []*Log{{Address: common.HexToAddress("0x1234"), Data: []byte("different")}}}
	var ea, eb bytes.Buffer
	Receipts{a}.EncodeIndex(0, &ea)
	Receipts{b}.EncodeIndex(0, &eb)
	if len(ea.Bytes()) <= 1 || bytes.Equal(ea.Bytes(), eb.Bytes()) {
		t.Fatalf("PQ receipt encoding does not carry its contents: A=%x B=%x", ea.Bytes(), eb.Bytes())
	}
	if DeriveSha(Receipts{a}, trie.NewStackTrie(nil)) == DeriveSha(Receipts{b}, trie.NewStackTrie(nil)) {
		t.Fatal("different PQ receipts give the same receipt root")
	}
	// the consensus encoding is the same as the binary encoding
	bin, err := a.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bin, ea.Bytes()) {
		t.Fatalf("EncodeIndex %x != MarshalBinary %x", ea.Bytes(), bin)
	}
}

func TestPQReceiptBinaryRoundTrip(t *testing.T) {
	r := &Receipt{Type: PQTxType, Status: 1, CumulativeGasUsed: 137000,
		Logs: []*Log{{Address: common.HexToAddress("0x1234"), Topics: []common.Hash{{1}}, Data: []byte{2}}}}
	r.Bloom = CreateBloom(r)
	b, err := r.MarshalBinary()
	if err != nil {
		t.Fatal(err)
	}
	var got Receipt
	if err := got.UnmarshalBinary(b); err != nil {
		t.Fatalf("PQ receipt round trip rejected: %v", err)
	}
	if got.Type != PQTxType || got.Status != r.Status || got.CumulativeGasUsed != r.CumulativeGasUsed ||
		got.Bloom != r.Bloom || len(got.Logs) != 1 || !bytes.Equal(got.Logs[0].Data, r.Logs[0].Data) {
		t.Fatalf("PQ receipt round trip changed it: %+v", got)
	}
}
