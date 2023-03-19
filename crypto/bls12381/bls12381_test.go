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

	sk, err := PadToLengthBytesInPlace(sk, PrivateKeySize)
	if err != nil {
		panic(err)
	}

	signature := Sign(GetBLSSignatureSuiteG1(), sk, m)

	assert.Equal(t, true, Verify(GetBLSSignatureSuiteG1(), publicKey, m, signature))
}

func TestEncryptAndDecryptSignatureG1Suite(t *testing.T) {
	suite := GetBLSSignatureSuiteG1()
	g2 := bls.NewG2()
	m := big.NewInt(200).Bytes()
	sk := big.NewInt(2).Bytes()

	pk := G2MulScalarMont(&bls.PointG2{}, g2.One(), new(big.Int).SetBytes(sk))
	publicKey := bls.NewG2().ToBytes(pk)

	sk, err := PadToLengthBytesInPlace(sk, PrivateKeySize)
	if err != nil {
		panic(err)
	}
	m, err = PadToLengthBytesInPlace(m, aes.BlockSize)
	if err != nil {
		panic(err)
	}
	encrypted, err := Encrypt(suite, publicKey, m)
	if err != nil {
		panic(err)
	}
	decryptedShare, err := DecryptShare(suite, sk, encrypted)
	if err != nil {
		panic(err)
	}
	pubPoints := []*bls.PointG2{pk}
	if err != nil {
		panic(err)
	}
	decryptedResult, err := Decrypt(suite, [][]byte{decryptedShare}, encrypted, pubPoints, nil)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, 0, new(big.Int).SetBytes(decryptedResult).Cmp(new(big.Int).SetBytes(m)))
}

func TestEncryptAndDecryptSignatureG2Suite(t *testing.T) {
	suite := GetBLSSignatureSuiteG2()
	g1 := bls.NewG1()
	m := big.NewInt(200).Bytes()
	sk := big.NewInt(2).Bytes()

	pk := G1MulScalarMont(&bls.PointG1{}, g1.One(), new(big.Int).SetBytes(sk))
	publicKey := bls.NewG1().ToBytes(pk)

	sk, err := PadToLengthBytesInPlace(sk, PrivateKeySize)
	if err != nil {
		panic(err)
	}
	m, err = PadToLengthBytesInPlace(m, aes.BlockSize)
	if err != nil {
		panic(err)
	}
	encrypted, err := Encrypt(suite, publicKey, m)
	if err != nil {
		panic(err)
	}
	decryptedShare, err := DecryptShare(suite, sk, encrypted)
	if err != nil {
		panic(err)
	}
	pubPoints := []*bls.PointG1{pk}
	if err != nil {
		panic(err)
	}
	decryptedResult, err := Decrypt(suite, [][]byte{decryptedShare}, encrypted, nil, pubPoints)
	if err != nil {
		panic(err)
	}

	assert.Equal(t, 0, new(big.Int).SetBytes(decryptedResult).Cmp(new(big.Int).SetBytes(m)))
}
