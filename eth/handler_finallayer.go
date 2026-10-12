package eth

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/log"
)

const (
	// staleHeadCheckInterval is how often the head age is checked.
	staleHeadCheckInterval = 6 * time.Second
	// staleHeadAge is the head age (several 3 second blocks) after which the
	// head is re-sent to every peer.
	staleHeadAge = 12 * time.Second
)

// staleHeadRebroadcastLoop re-sends the current head block to all peers while
// the chain is not advancing.
//
// Final Layer runs Parlia without BLS fast finality votes. If two validators
// seal competing blocks at the same height while they cannot see each other
// (for example right after restarts), each fork can then only be extended by
// a validator that sits on the other fork, and no new block is ever announced
// to break the tie: the chain stalls for good. Re-sending the stale head lets
// every node import the competing block, after which the normal fork choice
// (earliest millisecond timestamp, then lowest hash, wins at equal
// difficulty and height; see core/forkchoice.go) makes all nodes agree on one
// branch and the remaining in-turn validator can extend it.
func (h *handler) staleHeadRebroadcastLoop() {
	defer h.wg.Done()

	ticker := time.NewTicker(staleHeadCheckInterval)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			h.rebroadcastStaleHead()
		case <-h.stopCh:
			return
		}
	}
}

func (h *handler) rebroadcastStaleHead() {
	// A node that has not finished its initial sync always has an old head;
	// pushing it to every peer every few seconds only wastes bandwidth. The
	// stall this repairs is specific to Parlia.
	if !h.synced.Load() || h.chain.Config().Parlia == nil {
		return
	}
	head := h.chain.CurrentBlock()
	if head == nil || head.Number.Sign() == 0 {
		return
	}
	age := time.Since(time.UnixMilli(int64(head.MilliTimestamp())))
	if age < staleHeadAge {
		return
	}
	block := h.chain.GetBlock(head.Hash(), head.Number.Uint64())
	td := h.chain.GetTd(head.Hash(), head.Number.Uint64())
	if block == nil || td == nil {
		return
	}
	peers := h.peers.allPeers()
	log.Debug("Re-sending stale head to peers", "number", head.Number, "hash", head.Hash(), "age", age.Truncate(time.Second), "peers", len(peers))
	for _, peer := range peers {
		peer.AsyncSendNewBlock(block, new(big.Int).Set(td))
	}
}
