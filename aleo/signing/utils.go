// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"encoding/hex"
	"errors"
	"math/big"
	"math/bits"
	"strings"

	"github.com/Safulet/tss-lib-private/v2/aleo/bhp"
	"github.com/Safulet/tss-lib-private/v2/aleo/poseidon2"
	"github.com/Safulet/tss-lib-private/v2/aleo/poseidon4"
	"github.com/Safulet/tss-lib-private/v2/aleo/poseidon8"
	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/signatures/mina"
	"github.com/Safulet/tss-lib-private/v2/tss"
	"github.com/btcsuite/btcd/btcutil/bech32"
)

func ComputeRecordsH(signInputs RInputs) []*crypto.ECPoint {
	ret := make([]*crypto.ECPoint, 0)
	for item := range signInputs.Inputs {
		if signInputs.Inputs[item].InputType == RecordInputType {
			// Compute the generator `H` as `HashToGroup(commitment)`.
			// let h = N::hash_to_group_psd2(&[N::serial_number_domain(), commitment])?;
			panic("not implemented")
		}
	}
	return ret
}

func ComputeChallenge(tvk *big.Int, gR, pkSig, prSig *crypto.ECPoint, signInputs RInputs) *big.Int {
	ec := tss.EdBls12377()
	SkPrf := poseidon4.HashToScalarPSD4([]*big.Int{pkSig.X(), prSig.X()})
	PkPrf := crypto.ScalarBaseMult(ec, SkPrf)
	Address, _ := pkSig.Add(prSig)
	Address, _ = PkPrf.Add(Address)
	tcm := poseidon2.HashPSD2([]*big.Int{tvk})

	message := make([]*big.Int, 0)
	message = append(message, gR.X())
	message = append(message, pkSig.X())
	message = append(message, prSig.X())
	message = append(message, Address.X())
	message = append(message, tvk)
	message = append(message, tcm)
	message = append(message, signInputs.FunctionID)
	if signInputs.IsRoot {
		message = append(message, big.NewInt(1))
	} else {
		message = append(message, big.NewInt(0))
	}
	message = buildMessage(tvk, tcm, message, signInputs)

	ret := poseidon8.HashToScalarPSD8(message)
	return ret
}

func computeFunctionID(NetworkID *big.Int, programID, functionName string) *big.Int {
	prgID := strings.Split(programID, ".")
	if len(prgID) != 2 {
		panic("programID not correct")
	}
	toHash := make([]bool, 0, 1024)
	toHash = append(toHash, bhp.BigIntToBits(NetworkID, 16)...)
	nameBits := bhp.BytesToBits([]byte(prgID[0]))
	nameBitsLen := big.NewInt(int64(len(nameBits)))
	toHash = append(toHash, bhp.BigIntToBits(nameBitsLen, 8)...)
	toHash = append(toHash, nameBits...)
	networkBits := bhp.BytesToBits([]byte(prgID[1]))
	networkBitsLen := big.NewInt(int64(len(networkBits)))
	toHash = append(toHash, bhp.BigIntToBits(networkBitsLen, 8)...)
	toHash = append(toHash, networkBits...)
	fNameBits := bhp.BytesToBits([]byte(functionName))
	fNameBitsLen := big.NewInt(int64(len(fNameBits)))
	toHash = append(toHash, bhp.BigIntToBits(fNameBitsLen, 8)...)
	toHash = append(toHash, fNameBits...)
	return bhp.HashBHP1024(toHash)
}

func toFields(in string) []*big.Int {
	dataSize := 252
	ret := make([]*big.Int, 0)
	bzs, _ := hex.DecodeString(in)
	bzsBits := BytesToBitsReversed(bzs)
	numChunks := (len(bzsBits) + dataSize - 1) / dataSize
	for chk := 0; chk < numChunks; chk++ {
		start := chk * dataSize
		end := start + dataSize
		if end > len(bzsBits) {
			end = len(bzsBits)
		}
		val := bhp.BitsToBigInt(bzsBits[start:end])
		if chk == numChunks-1 {
			if val.Cmp(common.Zero) == 0 {
				continue
			}
		}
		ret = append(ret, val)
	}

	return ret
}

func BytesToBitsReversed(input []byte) []bool {
	output := make([]bool, len(input)*8)
	for i := range input {
		for j := 0; j < 8; j++ {
			output[i*8+(7-j)] = ((input[i] >> j) & 0x1) == 1
		}
	}
	return output
}

func ToAddress(addressPoint *crypto.ECPoint) (string, error) {
	if !tss.SameCurve(addressPoint.Curve(), tss.EdBls12377()) {
		return "", errors.New("not supported")
	}
	bzs := addressPoint.X().Bytes()
	bzs = common.ReverseBytes(common.PadToLengthBytesInPlace(bzs, 32))
	for i := range bzs {
		v := bits.Reverse8(bzs[i])
		bzs[i] = v
	}
	bitVec := mina.NewBitVector(bzs, 256)
	totalBlocks := (256 + 4) / 5
	ret := make([]byte, totalBlocks)
	for i := 0; i < totalBlocks; i++ {
		start := i * 5
		end := start + 5
		if end > 256 {
			end = 256
		}
		var v uint8
		for j := start; j < end; j++ {
			v = (v << 1) + bitVec.Element(j)
		}
		ret[i] = v
	}

	res, err := bech32.EncodeM("aleo", ret)
	if err != nil {
		return "", err
	}

	return res, nil

}

func buildMessage(tvk, tcm *big.Int, message []*big.Int, signInputs RInputs) []*big.Int {
	for i := range signInputs.Inputs {
		if signInputs.Inputs[i].InputType == ConstantInputType {
			preimage := make([]*big.Int, 0)
			preimage = append(preimage, signInputs.FunctionID)
			preimage = append(preimage, signInputs.Inputs[i].Fields...)
			preimage = append(preimage, tcm)
			preimage = append(preimage, big.NewInt(int64(signInputs.Inputs[i].Index)))
			inputHash := poseidon8.HashPSD8(preimage)
			message = append(message, inputHash)
		} else if signInputs.Inputs[i].InputType == PublicInputType {
			preimage := make([]*big.Int, 0)
			preimage = append(preimage, signInputs.FunctionID)
			preimage = append(preimage, signInputs.Inputs[i].Fields...)
			preimage = append(preimage, tcm)
			preimage = append(preimage, big.NewInt(int64(signInputs.Inputs[i].Index)))
			inputHash := poseidon8.HashPSD8(preimage)
			message = append(message, inputHash)
		} else if signInputs.Inputs[i].InputType == PrivateInputType {
			panic("not implemented")
		} else if signInputs.Inputs[i].InputType == RecordInputType {
			panic("not implemented")
		} else if signInputs.Inputs[i].InputType == ExternalRecordInputType {
			preimage := make([]*big.Int, 0)
			preimage = append(preimage, signInputs.FunctionID)
			preimage = append(preimage, signInputs.Inputs[i].Fields...)
			preimage = append(preimage, tvk)
			preimage = append(preimage, big.NewInt(int64(signInputs.Inputs[i].Index)))
			inputHash := poseidon8.HashPSD8(preimage)
			message = append(message, inputHash)
		}
	}
	return message
}

func Verify(pkSig, prSig *crypto.ECPoint, tvk, tcm, challenge, response *big.Int, signInputs RInputs) bool {
	ec := tss.EdBls12377()
	tcmToCheck := poseidon2.HashPSD2([]*big.Int{tvk})
	if tcm == nil || tcm.Cmp(tcmToCheck) != 0 {
		return false
	}

	message := make([]*big.Int, 0)
	message = append(message, tvk)
	message = append(message, tcm)
	message = append(message, signInputs.FunctionID)
	if signInputs.IsRoot {
		message = append(message, big.NewInt(1))
	} else {
		message = append(message, big.NewInt(0))
	}
	message = buildMessage(tvk, tcm, message, signInputs)

	// g_r := response * G + challenge * pk_sig
	var err error
	cPk := pkSig.ScalarMult(challenge)
	gR := crypto.ScalarBaseMult(ec, response)
	gR, err = cPk.Add(gR)
	if err != nil {
		return false
	}
	SkPrf := poseidon4.HashToScalarPSD4([]*big.Int{pkSig.X(), prSig.X()})
	PkPrf := crypto.ScalarBaseMult(ec, SkPrf)
	Address, err := pkSig.Add(prSig)
	if err != nil {
		return false
	}
	Address, err = PkPrf.Add(Address)
	if err != nil {
		return false
	}
	preimage := make([]*big.Int, 4)
	preimage[0] = gR.X()
	preimage[1] = pkSig.X()
	preimage[2] = prSig.X()
	preimage[3] = Address.X()
	preimage = append(preimage, message...)

	candidateChallenge := poseidon8.HashToScalarPSD8(preimage)
	if candidateChallenge == nil {
		return false
	}
	if candidateChallenge.Cmp(challenge) != 0 {
		return false
	}
	candidateAddress, err := ToAddress(Address)
	if err != nil {
		return false
	}
	if candidateAddress != signInputs.Signer {
		return false
	}

	return true
}
