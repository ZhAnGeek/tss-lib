package test_test

import (
	"fmt"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/vss"
	"github.com/Safulet/tss-lib-private/test"
	"github.com/Safulet/tss-lib-private/tss"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"

	ecdsa_keygen "github.com/Safulet/tss-lib-private/ecdsa/keygen"
	eddsa_keygen "github.com/Safulet/tss-lib-private/eddsa/keygen"
	kcdsa_keygen "github.com/Safulet/tss-lib-private/kcdsa/keygen"
	schnorr_keygen "github.com/Safulet/tss-lib-private/schnorr/keygen"
)

func TestRestoreEcdsaSK(t *testing.T) {
	// PHASE: load keygen fixtures
	keys, _, err := ecdsa_keygen.LoadKeygenTestFixturesRandomSet(test.TestThreshold+1, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))

	// PHASE: restore sk
	ec := tss.S256()
	var shares vss.Shares
	for _, key := range keys {
		shares = append(shares, &vss.Share{
			Threshold: test.TestThreshold,
			ID:        key.ShareID,
			Share:     key.Xi,
		})
	}
	sk, err := shares.ReConstruct(ec)
	assert.NoError(t, err, "reconstruct should not fail")

	pk2 := crypto.ScalarBaseMult(ec, sk)
	assert.True(t, pk2.Equals(keys[0].ECDSAPub), "pubkey derived from sk should equal pk")
	fmt.Println(pk2.Bytes())
}

func TestRestoreEddsaSK(t *testing.T) {
	// PHASE: load keygen fixtures
	keys, _, err := eddsa_keygen.LoadKeygenTestFixturesRandomSet(test.TestThreshold+1, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))

	// PHASE: restore sk
	ec := tss.Edwards()
	var shares vss.Shares
	for _, key := range keys {
		shares = append(shares, &vss.Share{
			Threshold: test.TestThreshold,
			ID:        key.ShareID,
			Share:     key.Xi,
		})
	}
	sk, err := shares.ReConstruct(ec)
	assert.NoError(t, err, "reconstruct should not fail")

	pk2 := crypto.ScalarBaseMult(ec, sk)
	assert.True(t, pk2.Equals(keys[0].EDDSAPub), "pubkey derived from sk should equal pk")
	fmt.Println(pk2.Bytes())
}

func TestRestoreKcdsaSK(t *testing.T) {
	// PHASE: load keygen fixtures
	keys, _, err := kcdsa_keygen.LoadKeygenTestFixturesRandomSet(test.TestThreshold+1, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))

	// PHASE: restore sk
	ec := tss.Curve25519()
	var shares vss.Shares
	for _, key := range keys {
		shares = append(shares, &vss.Share{
			Threshold: test.TestThreshold,
			ID:        key.ShareID,
			Share:     key.Xi,
		})
	}
	sk, err := shares.ReConstruct(ec)
	assert.NoError(t, err, "reconstruct should not fail")

	pk2 := crypto.ScalarBaseMult(ec, new(big.Int).ModInverse(sk, ec.Params().N))
	assert.True(t, pk2.Equals(keys[0].PubKey), "pubkey derived from sk should equal pk")
	fmt.Println(pk2.Bytes())
}

func TestRestoreSchnorrBtcSK(t *testing.T) {
	// PHASE: load keygen fixtures
	keys, _, err := schnorr_keygen.LoadKeygenTestFixturesRandomSet(test.TestThreshold+1, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))

	// PHASE: restore sk
	ec := tss.S256()
	var shares vss.Shares
	for _, key := range keys {
		shares = append(shares, &vss.Share{
			Threshold: test.TestThreshold,
			ID:        key.ShareID,
			Share:     key.Xi,
		})
	}
	sk, err := shares.ReConstruct(ec)
	assert.NoError(t, err, "reconstruct should not fail")

	pk2 := crypto.ScalarBaseMult(ec, sk)
	assert.True(t, pk2.Equals(keys[0].PubKey), "pubkey derived from sk should equal pk")
	fmt.Println(pk2.Bytes())
}

func TestRestoreSchnorrMinaSK(t *testing.T) {
	// PHASE: load keygen fixtures
	ec := tss.Pallas()
	keys, _, err := schnorr_keygen.LoadKeygenTestFixturesRandomSetWithCurve(test.TestThreshold+1, ec, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))

	// PHASE: restore sk
	var shares vss.Shares
	for _, key := range keys {
		shares = append(shares, &vss.Share{
			Threshold: test.TestThreshold,
			ID:        key.ShareID,
			Share:     key.Xi,
		})
	}
	sk, err := shares.ReConstruct(ec)
	assert.NoError(t, err, "reconstruct should not fail")

	pk2 := crypto.ScalarBaseMult(ec, sk)
	assert.True(t, pk2.Equals(keys[0].PubKey), "pubkey derived from sk should equal pk")
	fmt.Println(pk2.Bytes())
}
