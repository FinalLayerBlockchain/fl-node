package eth

import (
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/rpc"
)

// Final Layer runs Parlia without BLS fast-finality votes, so the chain's own
// finalized marker never leaves genesis. The "finalized" and "safe" RPC tags
// instead report probabilistic finality: the canonical block this many blocks
// below the head (3 s blocks). Reorganizing past it needs a majority of the
// validators (up to 21 elected, 11 needed) to sign a competing branch, which
// is slashable double signing. Integrators wanting more margin can use their
// own confirmation count on top of "latest".
const (
	finalLayerFinalizedDepth = 30 // 90 s
	finalLayerSafeDepth      = 15 // 45 s
)

// finalLayerTaggedHeader resolves the "finalized" and "safe" tags. It never
// reports less than a real (attestation based) finalized/safe block.
func (b *EthAPIBackend) finalLayerTaggedHeader(number rpc.BlockNumber) *types.Header {
	chain := b.eth.blockchain
	head := chain.CurrentBlock()
	if head == nil {
		return nil
	}
	depth := uint64(finalLayerFinalizedDepth)
	marker := chain.CurrentFinalBlock()
	if number == rpc.SafeBlockNumber {
		depth = finalLayerSafeDepth
		marker = chain.CurrentSafeBlock()
	}
	target := uint64(0)
	if head.Number.Uint64() > depth {
		target = head.Number.Uint64() - depth
	}
	if marker != nil && marker.Number.Uint64() > target {
		return marker
	}
	return chain.GetHeaderByNumber(target)
}
