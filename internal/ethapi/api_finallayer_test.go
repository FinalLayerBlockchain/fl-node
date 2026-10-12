package ethapi

import (
	"strings"
	"testing"

	"github.com/ethereum/go-ethereum/rpc"
)

// The consensus engine's uncapped system-contract read (1e9 gas, no EVM
// timeout) must not be reachable over RPC: every exported method of
// BlockChainAPI is served as eth_<name>, so as a method it would let any RPC
// client run 1e9 gas of arbitrary code (state overrides included) with no
// deadline.
func TestConsensusCallNotExposedOverRPC(t *testing.T) {
	server := rpc.NewServer()
	defer server.Stop()
	if err := server.RegisterName("eth", NewBlockChainAPI(nil)); err != nil {
		t.Fatal(err)
	}
	client := rpc.DialInProc(server)
	defer client.Close()

	var res interface{}
	err := client.Call(&res, "eth_consensusCall", map[string]interface{}{}, "latest")
	if err == nil || !strings.Contains(err.Error(), "does not exist") {
		t.Fatalf("eth_consensusCall is served over RPC (err = %v)", err)
	}
}
