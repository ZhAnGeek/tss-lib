// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package bhp

import (
	"encoding/binary"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

const (
	ChunkBits     = 3
	LookupSize    = 1 << ChunkBits
	NumWindows    = 8
	WindowSize    = 54
	FieldDataBits = 252
)

var (
	ec          = tss.EdBls12377()
	Bases       [][]*crypto.ECPoint
	BasesLookup [][][]*crypto.ECPoint
	RandomBase  []*crypto.ECPoint
	// domainSep from "AleoBHP1024"
	domainSep []bool
)

func HashBHP1024(inputBits []bool) *big.Int {

	numHasherBits := NumWindows * WindowSize * ChunkBits
	maxInputBitsPerIteration := numHasherBits - FieldDataBits // 1044

	totalNumBlocks := (len(inputBits) + maxInputBitsPerIteration - 1) / maxInputBitsPerIteration
	offset := 0
	var err error
	digest := crypto.NewInfinityPoint(ec)
	for block := 0; block < totalNumBlocks; block++ {
		end := offset + maxInputBitsPerIteration
		if end > len(inputBits) {
			end = len(inputBits)
		}
		blk := inputBits[offset:end]
		preimage := make([]bool, 0, numHasherBits)
		if block == 0 {
			// Construct the first iteration as: [ 0...0 || DOMAIN || LENGTH(INPUT) || INPUT[0..BLOCK_SIZE] ].
			preimage = append(preimage, domainSep...)
			// convert length to 64 bits
			lengthBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(lengthBytes, uint64(len(inputBits)))
			lengthBits := BytesToBits(lengthBytes)
			// Set length bits
			preimage = append(preimage, lengthBits...)
			// Set input bits
			preimage = append(preimage, blk...)
		} else {
			// Set digest bits
			preimage = append(preimage, BigIntToBits(digest.X(), FieldDataBits)...)
			// Set input bits
			preimage = append(preimage, blk...)
		}
		// Pad the input to a multiple of `BHP_CHUNK_SIZE` for hashing.
		if len(preimage)%ChunkBits != 0 {
			padding := ChunkBits - (len(preimage) % ChunkBits)
			paddingInput := make([]bool, padding)
			preimage = append(preimage, paddingInput...)
		}

		digest = crypto.NewInfinityPoint(ec)
		for window := 0; window < NumWindows; window++ {
			for pos := 0; pos < WindowSize; pos++ {
				indexBegin := window*WindowSize*ChunkBits + pos*ChunkBits
				if indexBegin > len(preimage)-1 {
					continue
				}
				chosen := BasesLookup[window][pos][BitsToInt(preimage[indexBegin:indexBegin+ChunkBits])]
				digest, err = digest.Add(chosen)
				if err != nil {
					panic(err)
				}
			}
		}
		offset += len(blk)
	}
	return digest.X()
}

func BytesToBits(input []byte) []bool {
	output := make([]bool, len(input)*8)
	for i := range input {
		for j := 0; j < 8; j++ {
			output[i*8+j] = ((input[i] >> j) & 0x1) == 1
		}
	}
	return output
}

func bitToInt(input bool) int {
	if input {
		return 1
	}
	return 0
}

func BitsToInt(input []bool) int {
	ret := 0
	for i, v := range input {
		va := bitToInt(v) << i
		ret += va
	}
	return ret
}

func BitsToBigInt(input []bool) *big.Int {
	ret := common.Zero
	for i, v := range input {
		// va := bitToInt(v) << i
		va := new(big.Int).Lsh(big.NewInt(int64(bitToInt(v))), uint(i))
		// ret += va
		ret = new(big.Int).Add(ret, va)
	}
	return ret
}

func BigIntToBits(input *big.Int, dataLen int) []bool {
	ret := make([]bool, dataLen)
	for i := 0; i < input.BitLen(); i++ {
		if i >= dataLen {
			continue
		}
		if input.Bit(i) == 1 {
			ret[i] = true
		}
		if i >= dataLen {
			ret[i] = false
		}
	}
	return ret
}
