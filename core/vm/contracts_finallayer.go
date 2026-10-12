package vm

import (
	"github.com/ethereum/go-ethereum/common"
	"github.com/ethereum/go-ethereum/core/types"
	"github.com/ethereum/go-ethereum/crypto/pq"
	"github.com/ethereum/go-ethereum/params"
	"github.com/ethereum/go-ethereum/rlp"
)

// Final Layer precompile policy.
//
// Every precompile whose purpose is to verify or recover a classical
// signature (secp256k1 ECDSA, secp256r1, BLS, Tendermint/CometBFT Ed25519
// light-client checks, ECDSA double-sign evidence) is replaced by a stub that
// always reverts. A post-quantum signature verifier is added instead.

// PQVerifyAddress is the post-quantum signature verification precompile.
//
// Input:  scheme(1) || msg(32) || pubkey || signature
// Output: 32 byte word, 1 if the signature is valid, 0 otherwise.
var PQVerifyAddress = common.HexToAddress("0x0000000000000000000000000000000000000f01")

// PQVerifyGas is the flat gas cost of one ML-DSA verification.
const PQVerifyGas uint64 = 40_000

// classicalSignaturePrecompiles lists every precompile address disabled by
// the policy.
var classicalSignaturePrecompiles = []common.Address{
	common.BytesToAddress([]byte{0x01}),       // ecrecover (secp256k1)
	common.BytesToAddress([]byte{0x0b}),       // BLS12-381 G1 add
	common.BytesToAddress([]byte{0x0c}),       // BLS12-381 G1 multiexp
	common.BytesToAddress([]byte{0x0d}),       // BLS12-381 G2 add
	common.BytesToAddress([]byte{0x0e}),       // BLS12-381 G2 multiexp
	common.BytesToAddress([]byte{0x0f}),       // BLS12-381 pairing
	common.BytesToAddress([]byte{0x10}),       // BLS12-381 map to G1
	common.BytesToAddress([]byte{0x11}),       // BLS12-381 map to G2
	common.BytesToAddress([]byte{0x64}),       // Tendermint header validate (Ed25519)
	common.BytesToAddress([]byte{0x65}),       // IAVL proof (BC light client)
	common.BytesToAddress([]byte{0x66}),       // BLS signature verify
	common.BytesToAddress([]byte{0x67}),       // CometBFT light block validate
	common.BytesToAddress([]byte{0x68}),       // double sign evidence (ECDSA headers), replaced by pqDoubleSignEvidence
	common.BytesToAddress([]byte{0x69}),       // secp256k1 signature recover
	common.BytesToAddress([]byte{0x01, 0x00}), // P256VERIFY (secp256r1)
}

// disabledPrecompile reverts every call and consumes no gas.
type disabledPrecompile struct{ name string }

func (c *disabledPrecompile) RequiredGas(input []byte) uint64 { return 0 }
func (c *disabledPrecompile) Run(input []byte) ([]byte, error) {
	return nil, ErrExecutionReverted
}
func (c *disabledPrecompile) Name() string { return "DISABLED_" + c.name }

// pqVerify verifies a post-quantum signature.
type pqVerify struct{}

func (c *pqVerify) RequiredGas(input []byte) uint64 { return PQVerifyGas }

func (c *pqVerify) Run(input []byte) ([]byte, error) {
	out := make([]byte, 32)
	if len(input) < 1+32 {
		return out, nil
	}
	s := pq.Scheme(input[0])
	if !pq.Enabled(s) {
		return out, nil
	}
	pkLen, sigLen := pq.PublicKeySize(s), pq.SignatureSize(s)
	if len(input) != 1+32+pkLen+sigLen {
		return out, nil
	}
	msg := input[1:33]
	pk := input[33 : 33+pkLen]
	sig := input[33+pkLen:]
	if pq.Verify(s, pq.DomainContract, pk, msg, sig) == nil {
		out[31] = 1
	}
	return out, nil
}

func (c *pqVerify) Name() string { return "PQVERIFY" }

// applyFinalLayerPrecompilePolicy rewrites every fork's precompile set. It
// runs at package init before the address lists are derived from the maps.
func applyFinalLayerPrecompilePolicy() {
	sets := []PrecompiledContracts{
		PrecompiledContractsHomestead,
		PrecompiledContractsByzantium,
		PrecompiledContractsIstanbulForBSC,
		PrecompiledContractsNano,
		PrecompiledContractsMoran,
		PrecompiledContractsPlanck,
		PrecompiledContractsLuban,
		PrecompiledContractsPlato,
		PrecompiledContractsBerlin,
		PrecompiledContractsHertz,
		PrecompiledContractsFeynman,
		PrecompiledContractsCancunForBSC,
		PrecompiledContractsHaber,
		PrecompiledContractsPragueForBSC,
		PrecompiledContractsOsakaForBSC,
		PrecompiledContractsPasteur,
		PrecompiledContractsIstanbul,
		PrecompiledContractsCancun,
		PrecompiledContractsPrague,
		PrecompiledContractsOsaka,
		PrecompiledContractsP256Verify,
	}
	for _, set := range sets {
		// Every classical address is occupied by a reverting stub in every
		// fork, so a call can never silently succeed against an empty account.
		for _, addr := range classicalSignaturePrecompiles {
			name := addr.Hex()
			if p, ok := set[addr]; ok {
				name = p.Name()
			}
			set[addr] = &disabledPrecompile{name: name}
		}
		set[PQVerifyAddress] = &pqVerify{}
		// Double-sign slashing stays available, verifying ML-DSA header seals.
		set[pqDoubleSignEvidenceAddress] = &pqDoubleSignEvidence{}
	}
}

// pqDoubleSignEvidenceAddress is the BSC double-sign evidence precompile used
// by SlashIndicator.submitDoubleSignEvidence.
var pqDoubleSignEvidenceAddress = common.BytesToAddress([]byte{0x68})

// pqDoubleSignEvidence is the BSC double-sign evidence check with post-quantum
// header seals: two different headers at the same height and parent, both
// sealed by the same ML-DSA key.
//
// Input:  rlp(DoubleSignEvidence{ChainId, HeaderBytes1, HeaderBytes2})
// Output: signer address (20 bytes) || evidence height (32 bytes)
type pqDoubleSignEvidence struct{}

func (c *pqDoubleSignEvidence) RequiredGas(input []byte) uint64 {
	return params.DoubleSignEvidenceVerifyGas + 2*PQVerifyGas
}

func (c *pqDoubleSignEvidence) Run(input []byte) ([]byte, error) {
	evidence := &DoubleSignEvidence{}
	if err := rlp.DecodeBytes(input, evidence); err != nil || evidence.ChainId == nil {
		return nil, ErrExecutionReverted
	}
	header1, header2 := &types.Header{}, &types.Header{}
	if err := rlp.DecodeBytes(evidence.HeaderBytes1, header1); err != nil {
		return nil, ErrExecutionReverted
	}
	if err := rlp.DecodeBytes(evidence.HeaderBytes2, header2); err != nil {
		return nil, ErrExecutionReverted
	}
	if header1.Number == nil || header2.Number == nil || len(header1.Number.Bytes()) > 32 {
		return nil, errInvalidEvidence
	}
	if header1.Number.Cmp(header2.Number) != 0 || header1.ParentHash != header2.ParentHash {
		return nil, errInvalidEvidence
	}
	if len(header1.Extra) < pq.SealSize || len(header2.Extra) < pq.SealSize {
		return nil, errInvalidEvidence
	}
	msgHash1 := types.SealHash(header1, evidence.ChainId)
	msgHash2 := types.SealHash(header2, evidence.ChainId)
	if msgHash1 == msgHash2 {
		return nil, errInvalidEvidence
	}
	signer1, err := pq.VerifySeal(header1.Extra[len(header1.Extra)-pq.SealSize:], msgHash1.Bytes())
	if err != nil {
		return nil, ErrExecutionReverted
	}
	signer2, err := pq.VerifySeal(header2.Extra[len(header2.Extra)-pq.SealSize:], msgHash2.Bytes())
	if err != nil {
		return nil, ErrExecutionReverted
	}
	if signer1 != signer2 {
		return nil, errInvalidEvidence
	}
	out := make([]byte, 52) // 20 + 32
	copy(out[:20], signer1.Bytes())
	height := header1.Number.Bytes()
	copy(out[52-len(height):], height)
	return out, nil
}

func (c *pqDoubleSignEvidence) Name() string { return "PQ_VERIFY_DOUBLE_SIGN_EVIDENCE" }
