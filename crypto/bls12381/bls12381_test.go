package bls12381

import (
	"crypto/aes"
	"crypto/rand"
	"math/big"
	"testing"

	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
	"github.com/stretchr/testify/assert"
)

var fuz = 10

func randScalar(max *big.Int) *big.Int {
	a, _ := rand.Int(rand.Reader, max)
	return a
}

func TestSignAndVerify(t *testing.T) {
	g2 := bls.NewG2()
	m := big.NewInt(200).Bytes()
	sk := big.NewInt(2).Bytes()
	pk := g2.MulScalar(&bls.PointG2{}, g2.One(), new(big.Int).SetBytes(sk))

	publicKey := bls.NewG2().ToBytes(pk)

	sk = PadToLengthBytesInPlace(sk, PrivateKeySize)

	signature := Sign(sk, m)

	assert.Equal(t, true, Verify(publicKey, m, signature))
}

func TestEncryptAndDecrypt(t *testing.T) {
	g2 := bls.NewG2()
	m := big.NewInt(200).Bytes()
	sk := big.NewInt(2).Bytes()
	pk := g2.MulScalar(&bls.PointG2{}, g2.One(), new(big.Int).SetBytes(sk))

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
