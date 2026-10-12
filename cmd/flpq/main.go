// Command flpq is the Final Layer post-quantum wallet and operator tool.
//
// Every transaction it creates is an ML-DSA-87 signed PQ transaction (type
// 0x07). It never touches ECDSA keys.
package main

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/ethereum/go-ethereum"
	"github.com/ethereum/go-ethereum/accounts/abi"
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/common/hexutil"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/ethclient"
	"github.com/ethereum/go-ethereum/rlp"
)

const usage = `flpq - Final Layer post-quantum (ML-DSA-87) wallet and operator tool

Keys
  flpq keygen <out.json>                          create a new ML-DSA-87 key file
  flpq address <key.json>                         print the default address of a key

Queries
  flpq balance <rpc> <address>
  flpq registry <rpc> <address>                   show the key registry entry (rotation state)
  flpq call <rpc> <to> <datahex>                  eth_call

Transactions (add --from <address> to sign for an account that rotated its key)
  flpq send <rpc> <key.json> <to> <amountFL>
  flpq tx <rpc> <key.json> <to|create> <valueFL> <datahex> [gas]
  flpq rotate <rpc> <currentKey.json> <newKey.json>
  flpq create-validator <rpc> <operatorKey.json> <consensusKey.json> <selfStakeFL> <moniker> [commissionBps]
  flpq edit-consensus <rpc> <operatorKey.json> <newConsensusKey.json>   replace a validator's consensus key
  flpq delegate <rpc> <key.json> <operatorAddress> <amountFL>
  flpq undelegate <rpc> <key.json> <operatorAddress> <shares>
  flpq claim <rpc> <key.json> <operatorAddress>

Genesis helpers
  flpq genesis-validators <consensusAddr>...      print INIT_VALIDATORSET_BYTES and genesis extraData
`

var stakeHub = common.HexToAddress("0x0000000000000000000000000000000000002002")

const stakeHubABI = `[
 {"type":"function","name":"createValidator","stateMutability":"payable","inputs":[
   {"name":"consensusAddress","type":"address"},{"name":"voteAddress","type":"bytes"},{"name":"blsProof","type":"bytes"},
   {"name":"commission","type":"tuple","components":[{"name":"rate","type":"uint64"},{"name":"maxRate","type":"uint64"},{"name":"maxChangeRate","type":"uint64"}]},
   {"name":"description","type":"tuple","components":[{"name":"moniker","type":"string"},{"name":"identity","type":"string"},{"name":"website","type":"string"},{"name":"details","type":"string"}]}],"outputs":[]},
 {"type":"function","name":"editConsensusAddress","stateMutability":"nonpayable","inputs":[{"name":"newConsensusAddress","type":"address"},{"name":"consensusProof","type":"bytes"}],"outputs":[]},
 {"type":"function","name":"delegate","stateMutability":"payable","inputs":[{"name":"operatorAddress","type":"address"},{"name":"delegateVotePower","type":"bool"}],"outputs":[]},
 {"type":"function","name":"undelegate","stateMutability":"nonpayable","inputs":[{"name":"operatorAddress","type":"address"},{"name":"shares","type":"uint256"}],"outputs":[]},
 {"type":"function","name":"claim","stateMutability":"nonpayable","inputs":[{"name":"operatorAddress","type":"address"},{"name":"requestNumber","type":"uint256"}],"outputs":[]}
]`

func main() {
	args, from := extractFrom(os.Args[1:])
	if len(args) == 0 {
		fmt.Print(usage)
		os.Exit(1)
	}
	var err error
	switch args[0] {
	case "keygen":
		err = cmdKeygen(args[1:])
	case "address":
		err = cmdAddress(args[1:])
	case "balance":
		err = cmdBalance(args[1:])
	case "registry":
		err = cmdRegistry(args[1:])
	case "call":
		err = cmdCall(args[1:])
	case "send":
		err = cmdSend(args[1:], from)
	case "tx":
		err = cmdTx(args[1:], from)
	case "rotate":
		err = cmdRotate(args[1:], from)
	case "create-validator":
		err = cmdCreateValidator(args[1:], from)
	case "edit-consensus":
		err = cmdEditConsensus(args[1:], from)
	case "delegate":
		err = cmdDelegate(args[1:], from)
	case "undelegate":
		err = cmdUndelegate(args[1:], from)
	case "claim":
		err = cmdClaim(args[1:], from)
	case "genesis-validators":
		err = cmdGenesisValidators(args[1:])
	default:
		fmt.Print(usage)
		os.Exit(1)
	}
	if err != nil {
		fmt.Fprintln(os.Stderr, "error:", err)
		os.Exit(1)
	}
}

func extractFrom(in []string) ([]string, *common.Address) {
	var out []string
	var from *common.Address
	for i := 0; i < len(in); i++ {
		if in[i] == "--from" && i+1 < len(in) {
			a := common.HexToAddress(in[i+1])
			from = &a
			i++
			continue
		}
		out = append(out, in[i])
	}
	return out, from
}

func need(args []string, n int) error {
	if len(args) < n {
		return errors.New("missing arguments (run flpq without arguments for help)")
	}
	return nil
}

// parseFL converts a decimal FL amount to wei (18 decimals).
func parseFL(s string) (*big.Int, error) {
	r, ok := new(big.Rat).SetString(s)
	if !ok || r.Sign() < 0 {
		return nil, fmt.Errorf("invalid amount %q", s)
	}
	r.Mul(r, new(big.Rat).SetInt(new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil)))
	if !r.IsInt() {
		return nil, fmt.Errorf("amount %q has more than 18 decimals", s)
	}
	return r.Num(), nil
}

func formatFL(wei *big.Int) string {
	r := new(big.Rat).SetFrac(wei, new(big.Int).Exp(big.NewInt(10), big.NewInt(18), nil))
	return strings.TrimRight(strings.TrimRight(r.FloatString(18), "0"), ".")
}

func loadKey(path string) (*pq.PrivateKey, error) { return pq.LoadKeyFile(path) }

func cmdKeygen(args []string) error {
	if err := need(args, 1); err != nil {
		return err
	}
	if _, err := os.Stat(args[0]); err == nil {
		return fmt.Errorf("%s already exists, refusing to overwrite", args[0])
	}
	k, err := pq.GenerateKey()
	if err != nil {
		return err
	}
	raw, _ := json.MarshalIndent(k.ToKeyFile(), "", "  ")
	if err := os.WriteFile(args[0], raw, 0o600); err != nil {
		return err
	}
	fmt.Println(k.Address().Hex())
	return nil
}

func cmdAddress(args []string) error {
	if err := need(args, 1); err != nil {
		return err
	}
	k, err := loadKey(args[0])
	if err != nil {
		return err
	}
	fmt.Println(k.Address().Hex())
	return nil
}

func dial(rpc string) (*ethclient.Client, error) {
	return ethclient.Dial(rpc)
}

func cmdBalance(args []string) error {
	if err := need(args, 2); err != nil {
		return err
	}
	c, err := dial(args[0])
	if err != nil {
		return err
	}
	bal, err := c.BalanceAt(context.Background(), common.HexToAddress(args[1]), nil)
	if err != nil {
		return err
	}
	fmt.Printf("%s FL (%s wei)\n", formatFL(bal), bal)
	return nil
}

func cmdRegistry(args []string) error {
	if err := need(args, 2); err != nil {
		return err
	}
	c, err := dial(args[0])
	if err != nil {
		return err
	}
	acct := common.HexToAddress(args[1])
	v, err := c.StorageAt(context.Background(), pq.RegistryAddress, pq.RegistrySlot(acct), nil)
	if err != nil {
		return err
	}
	if common.BytesToHash(v) == (common.Hash{}) {
		fmt.Println("default: controlled by the key whose address equals the account")
	} else {
		fmt.Printf("rotated: authorized key hash %s\n", common.BytesToHash(v).Hex())
	}
	return nil
}

func cmdCall(args []string) error {
	if err := need(args, 3); err != nil {
		return err
	}
	c, err := dial(args[0])
	if err != nil {
		return err
	}
	to := common.HexToAddress(args[1])
	out, err := c.CallContract(context.Background(), ethereum.CallMsg{To: &to, Data: common.FromHex(args[2])}, nil)
	if err != nil {
		return err
	}
	fmt.Println(hexutil.Encode(out))
	return nil
}

// sendPQ builds, signs, broadcasts a PQ transaction and waits for the receipt.
func sendPQ(rpc string, key *pq.PrivateKey, from *common.Address, to *common.Address, value *big.Int, data []byte, gas uint64) error {
	ctx := context.Background()
	c, err := dial(rpc)
	if err != nil {
		return err
	}
	sender := key.Address()
	if from != nil {
		sender = *from
	}
	chainID, err := c.ChainID(ctx)
	if err != nil {
		return err
	}
	nonce, err := c.PendingNonceAt(ctx, sender)
	if err != nil {
		return err
	}
	price, err := c.SuggestGasPrice(ctx)
	if err != nil {
		return err
	}
	if gas == 0 {
		est, err := c.EstimateGas(ctx, ethereum.CallMsg{From: sender, To: to, Value: value, Data: data})
		if err != nil {
			return fmt.Errorf("gas estimation failed: %w", err)
		}
		gas = est + est/5 + pq.AuthGas(key.Scheme)
	}
	tx := types.NewTx(&types.PQTx{
		ChainID:   chainID,
		Nonce:     nonce,
		GasTipCap: price,
		GasFeeCap: price,
		Gas:       gas,
		To:        to,
		Value:     value,
		Data:      data,
		From:      sender,
		Scheme:    uint8(key.Scheme),
	})
	signed, err := types.SignPQTx(tx, types.LatestSignerForChainID(chainID), key)
	if err != nil {
		return err
	}
	if err := c.SendTransaction(ctx, signed); err != nil {
		return err
	}
	fmt.Println("tx:", signed.Hash().Hex())
	for i := 0; i < 60; i++ {
		rcpt, err := c.TransactionReceipt(ctx, signed.Hash())
		if err == nil {
			status := "SUCCESS"
			if rcpt.Status != types.ReceiptStatusSuccessful {
				status = "FAILED"
			}
			fmt.Printf("block %d, gas used %d, %s\n", rcpt.BlockNumber, rcpt.GasUsed, status)
			if rcpt.ContractAddress != (common.Address{}) {
				fmt.Println("contract:", rcpt.ContractAddress.Hex())
			}
			if rcpt.Status != types.ReceiptStatusSuccessful {
				return errors.New("transaction reverted")
			}
			return nil
		}
		time.Sleep(time.Second)
	}
	return errors.New("timed out waiting for receipt")
}

func cmdSend(args []string, from *common.Address) error {
	if err := need(args, 4); err != nil {
		return err
	}
	key, err := loadKey(args[1])
	if err != nil {
		return err
	}
	to := common.HexToAddress(args[2])
	amt, err := parseFL(args[3])
	if err != nil {
		return err
	}
	return sendPQ(args[0], key, from, &to, amt, nil, 0)
}

func cmdTx(args []string, from *common.Address) error {
	if err := need(args, 5); err != nil {
		return err
	}
	key, err := loadKey(args[1])
	if err != nil {
		return err
	}
	var to *common.Address
	if args[2] != "create" {
		a := common.HexToAddress(args[2])
		to = &a
	}
	amt, err := parseFL(args[3])
	if err != nil {
		return err
	}
	var gas uint64
	if len(args) > 5 {
		gas, _ = strconv.ParseUint(args[5], 10, 64)
	}
	return sendPQ(args[0], key, from, to, amt, common.FromHex(args[4]), gas)
}

func cmdRotate(args []string, from *common.Address) error {
	if err := need(args, 3); err != nil {
		return err
	}
	cur, err := loadKey(args[1])
	if err != nil {
		return err
	}
	next, err := loadKey(args[2])
	if err != nil {
		return err
	}
	ctx := context.Background()
	c, err := dial(args[0])
	if err != nil {
		return err
	}
	acct := cur.Address()
	if from != nil {
		acct = *from
	}
	chainID, err := c.ChainID(ctx)
	if err != nil {
		return err
	}
	nonce, err := c.PendingNonceAt(ctx, acct)
	if err != nil {
		return err
	}
	data, err := pq.EncodeRotation(next, chainID.Uint64(), acct, nonce)
	if err != nil {
		return err
	}
	gas := uint64(21000) + 16*uint64(len(data)) + pq.RotationGas + pq.AuthGas(cur.Scheme) + 10000
	// EIP-7623 data floor: 21000 + 40 gas per non-zero payload byte.
	if floor := uint64(21000) + 40*uint64(len(data)) + 10000; floor > gas {
		gas = floor
	}
	to := pq.RegistryAddress
	fmt.Printf("rotating %s to the key of %s (%s)\n", acct.Hex(), args[2], pq.Name(next.Scheme))
	return sendPQ(args[0], cur, &acct, &to, new(big.Int), data, gas)
}

func packStake(method string, args ...interface{}) ([]byte, error) {
	a, err := abi.JSON(strings.NewReader(stakeHubABI))
	if err != nil {
		return nil, err
	}
	return a.Pack(method, args...)
}

// voteIdentifier derives the opaque 48 byte validator identifier StakeHub
// still stores in its voteAddress field (no BLS key exists on Final Layer).
func voteIdentifier(consensus common.Address) []byte {
	id := make([]byte, 48)
	copy(id, []byte("FLPQ"))
	copy(id[28:], consensus.Bytes())
	return id
}

func cmdCreateValidator(args []string, from *common.Address) error {
	if err := need(args, 5); err != nil {
		return err
	}
	key, err := loadKey(args[1])
	if err != nil {
		return err
	}
	// The consensus key proves possession; StakeHub rejects a consensus
	// address registered without it.
	consensusKey, err := loadKey(args[2])
	if err != nil {
		return err
	}
	consensus := consensusKey.Address()
	chainID, err := rpcChainID(args[0])
	if err != nil {
		return err
	}
	operator := key.Address()
	if from != nil {
		operator = *from
	}
	proof, err := pq.EncodeValidatorProof(consensusKey, chainID, operator)
	if err != nil {
		return err
	}
	stake, err := parseFL(args[3])
	if err != nil {
		return err
	}
	commission := uint64(1000)
	if len(args) > 5 {
		commission, _ = strconv.ParseUint(args[5], 10, 64)
	}
	type comm struct{ Rate, MaxRate, MaxChangeRate uint64 }
	type desc struct{ Moniker, Identity, Website, Details string }
	data, err := packStake("createValidator", consensus, voteIdentifier(consensus), proof,
		comm{Rate: commission, MaxRate: 5000, MaxChangeRate: 500},
		desc{Moniker: args[4], Identity: "", Website: "", Details: "Final Layer validator"})
	if err != nil {
		return err
	}
	// createValidator locks 1 FL on top of the self delegation.
	value := new(big.Int).Add(stake, big.NewInt(1e18))
	to := stakeHub
	return sendPQ(args[0], key, from, &to, value, data, 0)
}

// cmdEditConsensus moves a validator to a new consensus key. This is how a
// validator replaces a lost or compromised sealing key: rotating the consensus
// address in the key registry does not revoke the old key for block seals.
func cmdEditConsensus(args []string, from *common.Address) error {
	if err := need(args, 3); err != nil {
		return err
	}
	key, err := loadKey(args[1])
	if err != nil {
		return err
	}
	consensusKey, err := loadKey(args[2])
	if err != nil {
		return err
	}
	chainID, err := rpcChainID(args[0])
	if err != nil {
		return err
	}
	operator := key.Address()
	if from != nil {
		operator = *from
	}
	// A BEP-410 agent acts for its operator; StakeHub checks the proof
	// against the operator, so sign for the operator.
	if op, err := agentOperator(args[0], operator); err != nil {
		return err
	} else if op != (common.Address{}) {
		operator = op
	}
	proof, err := pq.EncodeValidatorProof(consensusKey, chainID, operator)
	if err != nil {
		return err
	}
	data, err := packStake("editConsensusAddress", consensusKey.Address(), proof)
	if err != nil {
		return err
	}
	to := stakeHub
	return sendPQ(args[0], key, from, &to, new(big.Int), data, 0)
}

func cmdDelegate(args []string, from *common.Address) error {
	if err := need(args, 4); err != nil {
		return err
	}
	key, err := loadKey(args[1])
	if err != nil {
		return err
	}
	amt, err := parseFL(args[3])
	if err != nil {
		return err
	}
	data, err := packStake("delegate", common.HexToAddress(args[2]), false)
	if err != nil {
		return err
	}
	to := stakeHub
	return sendPQ(args[0], key, from, &to, amt, data, 0)
}

func cmdUndelegate(args []string, from *common.Address) error {
	if err := need(args, 4); err != nil {
		return err
	}
	key, err := loadKey(args[1])
	if err != nil {
		return err
	}
	shares, ok := new(big.Int).SetString(args[3], 10)
	if !ok {
		return errors.New("shares must be an integer")
	}
	data, err := packStake("undelegate", common.HexToAddress(args[2]), shares)
	if err != nil {
		return err
	}
	to := stakeHub
	return sendPQ(args[0], key, from, &to, new(big.Int), data, 0)
}

func cmdClaim(args []string, from *common.Address) error {
	if err := need(args, 3); err != nil {
		return err
	}
	key, err := loadKey(args[1])
	if err != nil {
		return err
	}
	data, err := packStake("claim", common.HexToAddress(args[2]), big.NewInt(0))
	if err != nil {
		return err
	}
	to := stakeHub
	return sendPQ(args[0], key, from, &to, new(big.Int), data, 0)
}

// cmdGenesisValidators prints the RLP validator set package used by
// BSCValidatorSet.INIT_VALIDATORSET_BYTES and the genesis extraData
// (32 byte vanity, validator addresses, zeroed PQ seal space).
func cmdGenesisValidators(args []string) error {
	if len(args) == 0 {
		return errors.New("give at least one consensus address")
	}
	type val struct {
		Consensus   common.Address
		BscFee      common.Address
		Fee         common.Address
		VotingPower uint64
		VoteAddress []byte
	}
	var vals []val
	extra := make([]byte, 32)
	for _, a := range args {
		addr := common.HexToAddress(a)
		vals = append(vals, val{addr, addr, addr, 100, voteIdentifier(addr)})
		extra = append(extra, addr.Bytes()...)
	}
	extra = append(extra, make([]byte, pq.SealSize)...)
	pkg, err := rlp.EncodeToBytes([]interface{}{uint64(0), vals})
	if err != nil {
		return err
	}
	fmt.Println("INIT_VALIDATORSET_BYTES=" + common.Bytes2Hex(pkg))
	fmt.Println("EXTRA_DATA=0x" + common.Bytes2Hex(extra))
	return nil
}

func rpcChainID(url string) (uint64, error) {
	c, err := ethclient.Dial(url)
	if err != nil {
		return 0, err
	}
	defer c.Close()
	id, err := c.ChainID(context.Background())
	if err != nil {
		return 0, err
	}
	return id.Uint64(), nil
}

// agentOperator returns the operator an address is a BEP-410 agent for, or
// the zero address.
func agentOperator(rpc string, agent common.Address) (common.Address, error) {
	c, err := dial(rpc)
	if err != nil {
		return common.Address{}, err
	}
	defer c.Close()
	data := append(crypto.Keccak256([]byte("agentToOperator(address)"))[:4], common.LeftPadBytes(agent.Bytes(), 32)...)
	to := stakeHub
	out, err := c.CallContract(context.Background(), ethereum.CallMsg{To: &to, Data: data}, nil)
	if err != nil {
		return common.Address{}, err
	}
	if len(out) != 32 {
		return common.Address{}, errors.New("unexpected agentToOperator result")
	}
	return common.BytesToAddress(out[12:]), nil
}
