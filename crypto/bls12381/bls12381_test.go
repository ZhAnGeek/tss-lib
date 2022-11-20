package bls12381

import (
	"crypto/aes"
	"math/big"
	"testing"

	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
	"github.com/stretchr/testify/assert"
)

func TestSignAndVerify(t *testing.T) {
	g2 := bls.NewG2()
	m := big.NewInt(200).Bytes()
	sk := big.NewInt(2).Bytes()
	pk := G2MulScalarMont(&bls.PointG2{}, g2.One(), new(big.Int).SetBytes(sk))

	publicKey := bls.NewG2().ToBytes(pk)

	sk = PadToLengthBytesInPlace(sk, PrivateKeySize)

	signature := Sign(GetBLSSignatureSuiteG1(), sk, m)

	assert.Equal(t, true, Verify(GetBLSSignatureSuiteG1(), publicKey, m, signature))
}

func TestEncryptAndDecrypt(t *testing.T) {
	g2 := bls.NewG2()
	m := big.NewInt(200).Bytes()
	sk := big.NewInt(2).Bytes()
	pk := G2MulScalarMont(&bls.PointG2{}, g2.One(), new(big.Int).SetBytes(sk))

	publicKey := bls.NewG2().ToBytes(pk)

	sk = PadToLengthBytesInPlace(sk, PrivateKeySize)
	m = PadToLengthBytesInPlace(m, aes.BlockSize)
	encrypted, err := Encrypt(publicKey, m)
	if err != nil {
		panic(err)
	}
	decryptedShare, err := DecryptShare(sk, encrypted)
	if err != nil {
		panic(err)
	}
	pubPoints := []*bls.PointG2{pk}
	if err != nil {
		panic(err)
	}
	decryptedResult, err := Decrypt([][]byte{decryptedShare}, encrypted, pubPoints)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, 0, new(big.Int).SetBytes(decryptedResult).Cmp(new(big.Int).SetBytes(m)))
}
