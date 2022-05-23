// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"crypto/rand"
	"fmt"
	"math/big"

	"github.com/pkg/errors"
)

const (
	mustGetRandomIntMaxBits = 5000
)

// MustGetRandomInt panics if it is unable to gather entropy from `rand.Reader` or when `bits` is <= 0
func MustGetRandomInt(bits int) *big.Int {
	if bits <= 0 || mustGetRandomIntMaxBits < bits {
		panic(fmt.Errorf("MustGetRandomInt: bits should be positive, non-zero and less than %d", mustGetRandomIntMaxBits))
	}
	// Max random value e.g. 2^256 - 1
	max := new(big.Int)
	max = max.Exp(two, big.NewInt(int64(bits)), nil)

	// Generate cryptographically strong pseudo-random int between 0 - max
	n, err := rand.Int(rand.Reader, max)
	if err != nil {
		panic(errors.Wrap(err, "rand.Int failure in MustGetRandomInt!"))
	}
	return n
}

// GetRandomPositiveInt returns a big.Int less than a threshold
func GetRandomPositiveInt(lessThan *big.Int) *big.Int {
	if lessThan == nil || zero.Cmp(lessThan) != -1 {
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(lessThan.BitLen())
		if try.Cmp(lessThan) < 0 && try.Cmp(zero) >= 0 {
			break
		}
	}
	return try
}

// GetRandomPrimeInt returns a prime with specified bits length
func GetRandomPrimeInt(bits int) *big.Int {
	if bits <= 1 {
		return nil
	}
	try, err := rand.Prime(rand.Reader, bits)
	if err != nil ||
		try.Cmp(zero) == 0 {
		// fallback to older method
		for {
			try = MustGetRandomInt(bits)
			if probablyPrime(try) {
				break
			}
		}
	}
	return try
}

// GetRandomPositiveRelativelyPrimeInt generates a random element in the group of all the elements in Z/nZ that
// has a multiplicative inverse.
func GetRandomPositiveRelativelyPrimeInt(n *big.Int) *big.Int {
	if n == nil || zero.Cmp(n) != -1 {
		return nil
	}
	var try *big.Int
	for {
		try = MustGetRandomInt(n.BitLen())
		if IsNumberInMultiplicativeGroup(n, try) {
			break
		}
	}
	return try
}

// IsNumberInMultiplicativeGroup checks if values in the same multiplicative group
func IsNumberInMultiplicativeGroup(n, v *big.Int) bool {
	if n == nil || v == nil || zero.Cmp(n) != -1 {
		return false
	}
	gcd := big.NewInt(0)
	return v.Cmp(n) < 0 && v.Cmp(one) >= 0 &&
		gcd.GCD(nil, nil, v, n).Cmp(one) == 0
}

// GetRandomGeneratorOfTheQuadraticResidue returns a random generator of RQn with high probability.
//  THIS METHOD ONLY WORKS IF N IS THE PRODUCT OF TWO SAFE PRIMES!
// https://github.com/didiercrunch/paillier/blob/d03e8850a8e4c53d04e8016a2ce8762af3278b71/utils.go#L39
func GetRandomGeneratorOfTheQuadraticResidue(n *big.Int) *big.Int {
	f := GetRandomPositiveRelativelyPrimeInt(n)
	fSq := new(big.Int).Mul(f, f)
	return fSq.Mod(fSq, n)
}

// GetRandomQuadraticNonResidue returns a quadratic non residue of odd n.
func GetRandomQuadraticNonResidue(n *big.Int) *big.Int {
	for {
		w := GetRandomPositiveInt(n)
		if big.Jacobi(w, n) == -1 {
			return w
		}
	}
}

// GetRandomBytes returns random bytes of length.
func GetRandomBytes(length int) ([]byte, error) {
	// Per [BIP32], the seed must be in range [MinSeedBytes, MaxSeedBytes].
	if length <= 0 {
		return nil, errors.New("invalid length")
	}

	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}
