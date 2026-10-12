package parlia

import (
	"errors"
	"math/big"
	"testing"

	"github.com/ethereum/go-ethereum/common"
)

// fakeElectionView mimics StakeHub.getValidatorElectionInfo(offset, limit) on a
// fixed state. maxPerCall models the eth_call gas cap (RPCGasCap, 50M by
// default): StakeHub spends ~95k gas per registered validator, so a single
// unpaginated call fails once ~530 validators are registered. Registering a
// validator is permissionless (2,000 FL self-delegation), so without paging
// every breathe block fails for every node: a permanent chain halt.
type fakeElectionView struct {
	vals       []ValidatorItem
	maxPerCall int
	calls      int
}

var errFakeGasCap = errors.New("out of gas (eth_call gas cap)")

func (f *fakeElectionView) fetch(offset, limit uint64) ([]common.Address, []*big.Int, [][]byte, uint64, error) {
	f.calls++
	total := uint64(len(f.vals))
	if offset >= total {
		return nil, nil, nil, total, nil
	}
	if limit == 0 {
		limit = total
	}
	count := total - offset
	if count > limit {
		count = limit
	}
	if int(count) > f.maxPerCall {
		return nil, nil, nil, 0, errFakeGasCap
	}
	var (
		addrs  []common.Address
		powers []*big.Int
		votes  [][]byte
	)
	for _, v := range f.vals[offset : offset+count] {
		addrs = append(addrs, v.address)
		powers = append(powers, v.votingPower)
		votes = append(votes, v.voteAddress)
	}
	return addrs, powers, votes, total, nil
}

func TestValidatorElectionInfoPaged(t *testing.T) {
	view := &fakeElectionView{maxPerCall: 2 * electionInfoPageSize}
	for i := 0; i < 1234; i++ {
		view.vals = append(view.vals, ValidatorItem{
			address:     common.BigToAddress(big.NewInt(int64(i + 1))),
			votingPower: big.NewInt(int64(i * 7 % 1000)),
			voteAddress: []byte{byte(i), byte(i >> 8)},
		})
	}
	// The upstream single call (offset 0, limit 0 = everything) hits the cap.
	if _, _, _, _, err := view.fetch(0, 0); !errors.Is(err, errFakeGasCap) {
		t.Fatal("fake view does not model the gas cap")
	}

	view.calls = 0
	got, err := collectValidatorElectionInfo(view.fetch)
	if err != nil {
		t.Fatalf("election info with %d registered validators failed: %v", len(view.vals), err)
	}
	if len(got) != len(view.vals) {
		t.Fatalf("got %d validators, want %d", len(got), len(view.vals))
	}
	for i := range got {
		w := view.vals[i]
		if got[i].address != w.address || got[i].votingPower.Cmp(w.votingPower) != 0 || string(got[i].voteAddress) != string(w.voteAddress) {
			t.Fatalf("validator %d differs from the unpaged order", i)
		}
	}
	if want := (len(view.vals) + electionInfoPageSize - 1) / electionInfoPageSize; view.calls != want {
		t.Fatalf("%d calls, want %d", view.calls, want)
	}

	// Empty and exact-multiple sets.
	for _, n := range []int{0, electionInfoPageSize, 2 * electionInfoPageSize} {
		v := &fakeElectionView{vals: view.vals[:n], maxPerCall: electionInfoPageSize}
		got, err := collectValidatorElectionInfo(v.fetch)
		if err != nil || len(got) != n {
			t.Fatalf("n=%d: got %d validators, err %v", n, len(got), err)
		}
	}

	// A page that disagrees with the reported total is an error, never a
	// silently shortened validator list.
	short := func(offset, limit uint64) ([]common.Address, []*big.Int, [][]byte, uint64, error) {
		a, p, v, total, err := view.fetch(offset, limit)
		if offset > 0 && len(a) > 0 {
			return a[:len(a)-1], p[:len(p)-1], v[:len(v)-1], total, err
		}
		return a, p, v, total, err
	}
	if _, err := collectValidatorElectionInfo(short); err == nil {
		t.Fatal("inconsistent page accepted")
	}
}
