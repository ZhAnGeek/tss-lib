// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package paillier_test

import (
	"math/big"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"

	. "github.com/Safulet/tss-lib-private/v2/crypto/paillier"
)

// Using a modulus length of 2048 is recommended in the GG18 spec
const (
	testPaillierKeyLength = 2048
)

var (
	privateKey *PrivateKey
	publicKey  *PublicKey
)

func setUp(t *testing.T) {
	if privateKey != nil && publicKey != nil {
		return
	}
	var err error
	privateKey, publicKey, err = GenerateKeyPair(testPaillierKeyLength, 10*time.Minute)
	assert.NoError(t, err)
}

func TestGenerateKeyPair(t *testing.T) {
	setUp(t)
	assert.NotZero(t, publicKey)
	assert.NotZero(t, privateKey)
	t.Log(privateKey)
}

func TestEncrypt(t *testing.T) {
	setUp(t)
	cipher, err := publicKey.Encrypt(big.NewInt(1))
	assert.NoError(t, err, "must not error")
	assert.NotZero(t, cipher)
	t.Log(cipher)
}

func TestEncryptDecrypt(t *testing.T) {
	setUp(t)
	exp := big.NewInt(100)
	cypher, err := privateKey.Encrypt(exp)
	if err != nil {
		t.Error(err)
	}
	ret, err := privateKey.Decrypt(cypher)
	assert.NoError(t, err)
	assert.Equal(t, 0, exp.Cmp(ret),
		"wrong decryption ", ret, " is not ", exp)

	cypher = new(big.Int).Set(privateKey.N)
	_, err = privateKey.Decrypt(cypher)
	assert.Error(t, err)
}

func TestEncryptDecryptRandomness(t *testing.T) {
	setUp(t)
	exp := big.NewInt(100)
	c, r, err := privateKey.EncryptAndReturnRandomness(exp)
	if err != nil {
		t.Error(err)
	}
	ret, err := privateKey.Decrypt(c)
	assert.NoError(t, err)
	assert.Equal(t, 0, exp.Cmp(ret),
		"wrong decryption ", ret, " is not ", exp)

	r2, err := privateKey.GetRandomness(c)
	assert.NoError(t, err)
	assert.Equal(t, 0, r.Cmp(r2),
		"wrong randomness ", r2, " is not ", r)
}

func TestHomoMul(t *testing.T) {
	setUp(t)
	three, err := privateKey.Encrypt(big.NewInt(3))
	assert.NoError(t, err)

	// for HomoMul, the first argument `m` is not ciphered
	six := big.NewInt(6)

	cm, err := privateKey.HomoMult(six, three)
	assert.NoError(t, err)
	multiple, err := privateKey.Decrypt(cm)
	assert.NoError(t, err)

	// 3 * 6 = 18
	exp := int64(18)
	assert.Equal(t, 0, multiple.Cmp(big.NewInt(exp)))
}

func TestHomoAdd(t *testing.T) {
	setUp(t)
	num1 := big.NewInt(10)
	num2 := big.NewInt(32)

	one, _ := publicKey.Encrypt(num1)
	two, _ := publicKey.Encrypt(num2)

	ciphered, _ := publicKey.HomoAdd(one, two)

	plain, _ := privateKey.Decrypt(ciphered)

	assert.Equal(t, new(big.Int).Add(num1, num2), plain)
}

func TestComputeL(t *testing.T) {
	u := big.NewInt(21)
	n := big.NewInt(3)

	expected := big.NewInt(6)
	actual := L(u, n)

	assert.Equal(t, 0, expected.Cmp(actual))
}
