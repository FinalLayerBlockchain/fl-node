package core

import (
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/consensus"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/params"
)

// tieChain is a minimal ChainReader where every known header has the same TD.
type tieChain struct {
	config *params.ChainConfig
	tds    map[common.Hash]*big.Int
}

func (c *tieChain) Config() *params.ChainConfig             { return c.config }
func (c *tieChain) Engine() consensus.Engine                { return nil }
func (c *tieChain) GetJustifiedNumber(*types.Header) uint64 { return 0 }
func (c *tieChain) GetTd(h common.Hash, _ uint64) *big.Int  { return c.tds[h] }
func (c *tieChain) add(h *types.Header, td int64) *types.Header {
	c.tds[h.Hash()] = big.NewInt(td)
	return h
}

func tieHeader(coinbase byte, sec uint64, ms uint64) *types.Header {
	h := &types.Header{
		Number:     big.NewInt(40),
		Time:       sec,
		Difficulty: big.NewInt(1),
		Coinbase:   common.Address{coinbase},
		ParentHash: common.Hash{0x39},
	}
	if ms != 0 {
		h.MixDigest = common.BigToHash(new(big.Int).SetUint64(ms))
	}
	return h
}

func newTieChain() *tieChain {
	return &tieChain{config: &params.ChainConfig{Parlia: &params.ParliaConfig{}}, tds: map[common.Hash]*big.Int{}}
}

// Two validators that seal competing out-of-turn blocks at the same height
// with the same TD must be ordered the same way by every node; a random choice
// per node can leave each validator on its own block, where the Parlia recents
// rule forbids it from extending: a permanent halt while the third validator
// is offline.
func TestFinalLayerForkChoiceEqualTDIsDeterministic(t *testing.T) {
	for i := 0; i < 64; i++ {
		c := newTieChain()
		a := c.add(tieHeader(2, 1000, 0), 100)
		b := c.add(tieHeader(3, 1000, 0), 100)
		f := NewForkChoice(c)

		ab, err := f.ReorgNeeded(a, b)
		if err != nil {
			t.Fatal(err)
		}
		ba, err := f.ReorgNeeded(b, a)
		if err != nil {
			t.Fatal(err)
		}
		if ab == ba {
			t.Fatalf("iteration %d: nodes on a (reorg=%v) and on b (reorg=%v) do not converge", i, ab, ba)
		}
		want := parliaTieRank(b).Cmp(parliaTieRank(a)) < 0
		if ab != want {
			t.Fatalf("iteration %d: reorg a->b = %v, want %v", i, ab, want)
		}
	}
}

// A producer cannot win a tie by re-signing (ML-DSA signing is randomized, so
// every re-sign gives a new block hash) or by choosing its timestamp: every
// variant of its block ranks the same against the competitor.
func TestFinalLayerForkChoiceNotGrindable(t *testing.T) {
	c := newTieChain()
	rival := c.add(tieHeader(3, 1000, 0), 100)
	f := NewForkChoice(c)
	var first *bool
	for i := 0; i < 1000; i++ {
		v := tieHeader(2, 1000+uint64(i%3), uint64(i%1000))
		v.Extra = []byte{byte(i), byte(i >> 8)} // stands in for a fresh seal
		c.add(v, 100)
		reorg, err := f.ReorgNeeded(rival, v)
		if err != nil {
			t.Fatal(err)
		}
		if first == nil {
			first = &reorg
		} else if reorg != *first {
			t.Fatalf("variant %d changed the tie outcome", i)
		}
	}
}

// The rank of a block cannot be biased by the producer of its parent either:
// re-signing the parent (a new parent hash) leaves the order of the children's
// validators unchanged.
func TestFinalLayerForkChoiceParentNotGrindable(t *testing.T) {
	want := parliaTieRank(tieHeader(2, 1000, 0)).Cmp(parliaTieRank(tieHeader(3, 1000, 0)))
	for i := 0; i < 1000; i++ {
		a, b := tieHeader(2, 1000, 0), tieHeader(3, 1000, 0)
		parent := common.BigToHash(big.NewInt(int64(i)))
		a.ParentHash, b.ParentHash = parent, parent
		if parliaTieRank(a).Cmp(parliaTieRank(b)) != want {
			t.Fatalf("parent variant %d changed the order of the children", i)
		}
	}
}
