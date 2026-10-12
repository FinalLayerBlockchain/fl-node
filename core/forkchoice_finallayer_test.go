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
// with the same TD and the same second must be ordered the same way by every
// node; a random choice per node can leave each validator on its own block,
// where the Parlia recents rule forbids it from extending: a permanent halt
// while the third validator is offline.
func TestFinalLayerForkChoiceEqualSecondIsDeterministic(t *testing.T) {
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
		// lower hash wins the exact tie
		want := b.Hash().Cmp(a.Hash()) < 0
		if ab != want {
			t.Fatalf("iteration %d: reorg a->b = %v, want %v", i, ab, want)
		}
	}
}

// Within the same second the millisecond part of the Parlia timestamp decides.
func TestFinalLayerForkChoiceUsesMilliseconds(t *testing.T) {
	for i := 0; i < 64; i++ {
		c := newTieChain()
		early := c.add(tieHeader(2, 1000, 100), 100)
		late := c.add(tieHeader(3, 1000, 900), 100)
		f := NewForkChoice(c)

		if reorg, _ := f.ReorgNeeded(late, early); !reorg {
			t.Fatalf("iteration %d: node on the later block did not switch to the earlier one", i)
		}
		if reorg, _ := f.ReorgNeeded(early, late); reorg {
			t.Fatalf("iteration %d: node on the earlier block switched to the later one", i)
		}
	}
}
