package bhp

import (
	"encoding/binary"
	"errors"
	"fmt"
	"math/big"

	// bls "github.com/Safulet/tss-lib-private/v2/crypto/bls12377"
	bls "github.com/consensys/gnark-crypto/ecc/bls12-377"
	fr "github.com/consensys/gnark-crypto/ecc/bls12-377/fr"
)

const _BHP_CHUNK_SIZE = 3
const _BHP_LOOKUP_SIZE = 1 << _BHP_CHUNK_SIZE

type bhpHasher struct {
	Domain      string
	NumWindows  int
	WindowSize  int
	MinBits     int
	MaxBits     int
	Bases       [][]bls.G1Affine
	LookupBases [][][_BHP_LOOKUP_SIZE]bls.G1Affine
}

func (bhp *bhpHasher) BlockSize() int {
	return bhp.NumWindows*bhp.WindowSize*_BHP_CHUNK_SIZE - fr.Modulus().BitLen() - 1
}

func (bhp *bhpHasher) OutputSize() int {
	return bls.SizeOfG1AffineCompressed
}

func (bhp *bhpHasher) Setup(numWindows, windowSize int, domain string) error {
	bhp.Domain = domain
	bhp.NumWindows = numWindows
	bhp.WindowSize = windowSize
	// The maximum number of input bits.
	bhp.MaxBits = bhp.NumWindows * bhp.WindowSize * _BHP_CHUNK_SIZE
	// The minimum number of input bits (at least one window).
	bhp.MinBits = bhp.WindowSize * _BHP_CHUNK_SIZE

	// Calculate the maximum window size.
	var max_window_size = 0
	modulusMinusOne := fr.Modulus().Sub(fr.Modulus(), new(big.Int).SetUint64(1))
	modulusMinusOneDivTwo := modulusMinusOne.Div(modulusMinusOne, new(big.Int).SetUint64(2))
	_range := new(big.Int).SetUint64(2)
	shift4 := new(big.Int).SetUint64(16)
	for _range.Cmp(modulusMinusOneDivTwo) == -1 {
		_range = _range.Mul(_range, shift4)
		max_window_size++
	}
	if bhp.WindowSize > max_window_size {
		return fmt.Errorf("the maximum BHP window size is %d", max_window_size)
	}

	// Compute the bases
	bhp.Bases = make([][]bls.G1Affine, bhp.NumWindows)
	for i := range bhp.Bases {
		bhp.Bases[i] = make([]bls.G1Affine, bhp.WindowSize)

		g, err := bls.HashToG1([]byte(fmt.Sprintf("BHP.{%d}.{%d}.{%s}.{%d}", bhp.NumWindows, bhp.WindowSize, bhp.Domain, i)), nil)
		if err != nil {
			return errors.New("failed on hashing message to curve")
		}
		for j := range bhp.Bases[i] {
			bhp.Bases[i][j].Set(&g)
			for k := 0; k < 4; k++ {
				g = *g.Double(&g)
			}
		}
	}

	// Compute the bases lookup.
	bhp.LookupBases = make([][][_BHP_LOOKUP_SIZE]bls.G1Affine, bhp.NumWindows)
	var t bls.G1Affine
	// for each window
	for i, window := range bhp.Bases {
		bhp.LookupBases[i] = make([][_BHP_LOOKUP_SIZE]bls.G1Affine, bhp.WindowSize)
		// for each generator in the window
		for j, base := range window {
			var lookup [_BHP_LOOKUP_SIZE]bls.G1Affine
			// for each lookup of the generator
			for k := range lookup {
				lookup[k].Set(&base)
				if k&0x01 != 0 {
					lookup[k].Add(&lookup[k], &base)
				}
				if k&0x02 != 0 {
					t.Double(&base)
					lookup[k].Add(&lookup[k], &t)
				}
				if k&0x04 != 0 {
					lookup[k].Neg(&lookup[k])
				}
				bhp.LookupBases[i][j] = lookup
			}
		}
	}
	return nil
}

// input consists of bits each represented as bool
func (bhp *bhpHasher) hash(input []byte) (*bls.G1Affine, error) {
	if len(input) < bhp.MinBits {
		return nil, fmt.Errorf("error: input must be of length greater than minimum length %d", bhp.MinBits)
	}
	if len(input) > bhp.MaxBits {
		return nil, fmt.Errorf("error: input must be of length less than maximum length %d", bhp.MaxBits)
	}
	var result bls.G1Affine

	// Pad the input to a multiple of `BHP_CHUNK_SIZE` for hashing.
	if len(input)%_BHP_CHUNK_SIZE != 0 {
		padding_size := _BHP_CHUNK_SIZE - (len(input) % _BHP_CHUNK_SIZE)
		padding_input := make([]byte, padding_size) // defualt false = ie 0 bit
		input = append(input, padding_input...)
	}

	for i := 0; i < len(input); i += bhp.WindowSize * _BHP_CHUNK_SIZE {
		// chunk = window of bits
		end := i + bhp.WindowSize*_BHP_CHUNK_SIZE
		if end > len(input) {
			end = len(input)
		}
		chunk := input[i:end]

		for j := 0; j < len(chunk); j += _BHP_CHUNK_SIZE {
			endChunk := j + _BHP_CHUNK_SIZE
			if endChunk > len(chunk) {
				endChunk = len(chunk)
			}
			chunkBits := chunk[j:endChunk]
			index := 0
			multiplier := 1
			for t := 0; t < _BHP_CHUNK_SIZE; t++ {
				index += int(chunkBits[t]) * multiplier
				multiplier *= 2
			}
			iIndex := i / (bhp.WindowSize * _BHP_CHUNK_SIZE)
			jIndex := j / (_BHP_CHUNK_SIZE)
			result.Add(&result, &bhp.LookupBases[iIndex][jIndex][index])
		}
	}
	return &result, nil
}

func (bhp *bhpHasher) Hash(input []byte) ([]byte, error) {
	maxDataSize := fr.Modulus().BitLen() - 1
	// get domain bits
	domainBits := bytesToBits([]byte(bhp.Domain))
	maxDomainBits := maxDataSize - 64 // 64 bits for input length
	if len(domainBits) > maxDomainBits {
		return nil, fmt.Errorf("domain bits length %d cannot exceed maximum domain bits %d", len(domainBits), maxDomainBits)
	}

	// Pad the domain with zeros up to the maximum size in bits.
	pad := make([]byte, maxDomainBits-len(domainBits))
	domainBits = append(pad, domainBits...)

	hashBits := bhp.NumWindows * bhp.WindowSize * _BHP_CHUNK_SIZE

	if maxDataSize > hashBits {
		return nil, fmt.Errorf("max data size %d cannot exceed max hash bits %d", maxDataSize, hashBits)
	}

	// The maximum number of input bits per iteration.
	maxInputPerIteration := hashBits - maxDataSize

	// Initialize a variable to store the hash from the current iteration.
	var digest *bls.G1Affine
	var err error
	// convert input to bits
	inputBits := bytesToBits(input)
	// Pad input bits
	if len(inputBits)%maxInputPerIteration != 0 {
		padLen := maxInputPerIteration - len(inputBits)%maxInputPerIteration
		pad := make([]byte, padLen)
		inputBits = append(inputBits, pad...)
	}

	for i := 0; i < len(inputBits); i += maxInputPerIteration {
		preimage := make([]byte, hashBits)
		if i == 0 {
			// Construct the first iteration as: [ 0...0 || DOMAIN || LENGTH(INPUT) || INPUT[0..BLOCK_SIZE] ]
			copy(preimage, domainBits)
			// convert length to 64 bits
			length := uint64(len(inputBits))
			lengthBytes := make([]byte, 8)
			binary.LittleEndian.PutUint64(lengthBytes, length)
			lengthBits := bytesToBits(lengthBytes)
			// Set length bits
			copy(preimage[len(domainBits):], lengthBits)
			// Set input bits
			copy(preimage[maxDataSize:], inputBits[0:maxInputPerIteration])
		} else {
			// Construct the subsequent iterations as: [ PREVIOUS_HASH[0..DATA_BITS] || INPUT[I * BLOCK_SIZE..(I + 1) * BLOCK_SIZE] ].
			x := digest.X.Bytes()
			digestBits := bytesToBits(x[:])
			truncatedDigestBits := digestBits[:maxDataSize]
			copy(preimage, truncatedDigestBits)
			copy(preimage[maxDataSize:], inputBits[i*maxInputPerIteration:(i+1)*maxInputPerIteration])
		}
		digest, err = bhp.hash(preimage)
		if err != nil {
			return nil, err
		}

	}
	hashOutput := digest.X.Bytes()
	return hashOutput[:], nil
}

func bytesToBits(input []byte) []byte {
	output := make([]byte, len(input)*8)
	for i := range input {
		for j := 0; j < 8; j++ {
			output[i*8+j] = (input[i] >> j) & 0x1
		}
	}
	return output
}
