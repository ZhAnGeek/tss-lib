package edwards25519

import (
	"filippo.io/edwards25519"
	"math/big"
)

func EncodedBytesToBigInt(s *[32]byte) *big.Int {
	// Use a copy so we don't screw up our original
	// memory.
	sCopy := new([32]byte)
	for i := 0; i < 32; i++ {
		sCopy[i] = s[i]
	}
	Reverse(sCopy)

	bi := new(big.Int).SetBytes(sCopy[:])

	return bi
}

func BigIntToEncodedBytes(a *big.Int) *[32]byte {
	s := new([32]byte)
	if a == nil {
		return s
	}

	// Caveat: a can be longer than 32 bytes.
	s = CopyBytes(a.Bytes())

	// Reverse the byte string --> little endian after
	// encoding.
	Reverse(s)

	return s
}

func CopyBytes(aB []byte) *[32]byte {
	if aB == nil {
		return nil
	}
	s := new([32]byte)

	// If we have a short byte string, expand
	// it so that it's long enough.
	aBLen := len(aB)
	if aBLen < 32 {
		diff := 32 - aBLen
		for i := 0; i < diff; i++ {
			aB = append([]byte{0x00}, aB...)
		}
	}

	for i := 0; i < 32; i++ {
		s[i] = aB[i]
	}

	return s
}

// CopyBytes64 copies a byte slice to a 64 byte array.
func CopyBytes64(aB []byte) *[64]byte {
	if aB == nil {
		return nil
	}

	s := new([64]byte)

	// If we have a short byte string, expand
	// it so that it's long enough.
	aBLen := len(aB)
	if aBLen < 64 {
		diff := 64 - aBLen
		for i := 0; i < diff; i++ {
			aB = append([]byte{0x00}, aB...)
		}
	}

	for i := 0; i < 64; i++ {
		s[i] = aB[i]
	}

	return s
}

func EcPointToEncodedBytes(x *big.Int, y *big.Int) *[32]byte {
	s := BigIntToEncodedBytes(y)
	if x.Bit(0) == 1 {
		s[31] |= 1 << 7
	}

	return s
}

func EncodedBytesToEcPoint(s []byte) (x *big.Int, y *big.Int) {
	p, err := edwards25519.NewIdentityPoint().SetBytes(s)
	if err != nil {
		return nil, nil
	}
	x, y = ToAffine(p)
	return x, y
}

func Reverse(s *[32]byte) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}
