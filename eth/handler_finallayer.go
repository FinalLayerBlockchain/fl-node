package eth

import (
	"math/big"
	"time"

	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/log"
)

const (
	// staleHeadCheckInterval is how often the head age is checked.
	staleHeadCheckInterval = 6 * time.Second
	// staleHeadAge is the head age (several 3 second blocks) after which the
	// head is re-sent to every peer.
	staleHeadAge = 12 * time.Second
	// staleHeadMaxBackoff bounds the exponential backoff between re-sends of
	// the same stale head.
	staleHeadMaxBackoff = 5 * time.Minute
)

// staleHeadState remembers what was re-sent, for backoff.
type staleHeadState struct {
	hash    common.Hash
	backoff time.Duration
	next    time.Time
}

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
	var st staleHeadState
	for {
		select {
		case <-ticker.C:
			h.rebroadcastStaleHead(&st, time.Now())
		case <-h.stopCh:
			return
		}
	}
}

// rebroadcastStaleHead sends a stale head once in full to every peer, then
// only announces its hash, with exponential backoff (6 s doubling up to 5 min)
// while the same head stays stale. A peer that lacks the block (for example
// one on a competing sibling) fetches it from the announcement; a peer that
// has it drops the announcement at almost no cost.
func (h *handler) rebroadcastStaleHead(st *staleHeadState, now time.Time) {
	// A node that has not finished its initial sync always has an old head;
	// pushing it to peers only wastes bandwidth. The stall this repairs is
	// specific to Parlia.
	if !h.synced.Load() || h.chain.Config().Parlia == nil {
		return
	}
	head := h.chain.CurrentBlock()
	if head == nil || head.Number.Sign() == 0 {
		return
	}
	age := now.Sub(time.UnixMilli(int64(head.MilliTimestamp())))
	if age < staleHeadAge {
		*st = staleHeadState{}
		return
	}
	full := head.Hash() != st.hash
	if !full && now.Before(st.next) {
		return
	}
	block := h.chain.GetBlock(head.Hash(), head.Number.Uint64())
	td := h.chain.GetTd(head.Hash(), head.Number.Uint64())
	if block == nil || td == nil {
		return
	}
	if full {
		st.hash = head.Hash()
		st.backoff = staleHeadCheckInterval
	} else {
		st.backoff *= 2
		if st.backoff > staleHeadMaxBackoff {
			st.backoff = staleHeadMaxBackoff
		}
	}
	st.next = now.Add(st.backoff)
	peers := h.peers.allPeers()
	log.Debug("Re-sending stale head to peers", "number", head.Number, "hash", head.Hash(), "full", full, "age", age.Truncate(time.Second), "peers", len(peers))
	for _, peer := range peers {
		if full {
			peer.AsyncSendNewBlock(block, new(big.Int).Set(td))
		} else {
			peer.AsyncSendNewBlockHash(block)
		}
	}
}
