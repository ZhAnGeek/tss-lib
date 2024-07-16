// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package utils

import (
	"testing"

	ecdsa_keygen "github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
	eddsa_keygen "github.com/Safulet/tss-lib-private/v2/eddsa/keygen"
	kcdsa_keygen "github.com/Safulet/tss-lib-private/v2/kcdsa/keygen"
	schnorr_keygen "github.com/Safulet/tss-lib-private/v2/schnorr/keygen"
	"github.com/Safulet/tss-lib-private/v2/test"
	"github.com/Safulet/tss-lib-private/v2/tss"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"github.com/stretchr/testify/assert"
)

func TestRestoreECDSAPrivateKey(t *testing.T) {
	ec := tss.S256()

	keys, _, err := ecdsa_keygen.LoadKeygenTestFixturesRandomSet(test.TestThreshold+1, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))
	restoredPriv, err := RestoreECDSAPrivateKey(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)

	privKey, err := restoredPriv.ToECDSAPriv()
	assert.NoError(t, err)
	assert.NotNil(t, privKey)

	rawPub := keys[0].ECDSAPub.ToECDSAPubKey()
	rawPub.Curve = ec
	assert.True(t, rawPub.IsOnCurve(rawPub.X, rawPub.Y))
	priPub := &privKey.PublicKey
	priPub.Curve = ec
	assert.True(t, priPub.IsOnCurve(priPub.X, priPub.Y))

	assert.True(t, rawPub.Equal(priPub))
}

func TestRestoreEdwardsPrivateKey(t *testing.T) {
	ec := edwards.Edwards()

	keys, _, err := eddsa_keygen.LoadKeygenTestFixturesRandomSet(test.TestThreshold+1, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))
	restoredPriv, err := RestoreEDDSAPrivateKey(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)
	priv, err := restoredPriv.ToEdwardsPriv()
	assert.NoError(t, err)
	assert.NotNil(t, priv)

	rawPub := keys[0].EDDSAPub.ToECDSAPubKey()
	rawPub.Curve = ec
	assert.True(t, rawPub.IsOnCurve(rawPub.X, rawPub.Y))
	pubInPriv := priv.PubKey().ToECDSA()
	pubInPriv.Curve = ec
	assert.True(t, pubInPriv.IsOnCurve(pubInPriv.X, pubInPriv.Y))
	assert.True(t, rawPub.Equal(pubInPriv))
}

func TestRestoreKCDSAPrivateKey(t *testing.T) {
	ec := tss.Curve25519()
	keys, _, err := kcdsa_keygen.LoadKeygenTestFixturesRandomSet(test.TestThreshold+1, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))
	restoredPriv, err := RestoreKCDSAPrivateKey(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)
}

func TestRestoreSchnorrS256PrivateKey(t *testing.T) {
	ec := tss.S256()

	keys, _, err := schnorr_keygen.LoadKeygenTestFixturesRandomSet(test.TestThreshold+1, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))
	restoredPriv, err := RestoreSchnorrPrivate(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)

	privKey, err := restoredPriv.ToECDSAPriv()
	assert.NoError(t, err)
	assert.NotNil(t, privKey)

	rawPub := keys[0].PubKey.ToECDSAPubKey()
	rawPub.Curve = ec
	assert.True(t, rawPub.IsOnCurve(rawPub.X, rawPub.Y))
	priPub := &privKey.PublicKey
	priPub.Curve = ec
	assert.True(t, priPub.IsOnCurve(priPub.X, priPub.Y))

	assert.True(t, rawPub.Equal(priPub))
}

func TestRestoreSchnorrPallasPrivateKey(t *testing.T) {
	ec := tss.Pallas()
	keys, _, err := schnorr_keygen.LoadKeygenTestFixturesRandomSetWithCurve(test.TestThreshold+1, ec, test.TestParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, test.TestThreshold+1, len(keys))
	restoredPriv, err := RestoreSchnorrPrivate(ec, test.TestThreshold, keys)
	assert.NoError(t, err)
	assert.NotNil(t, restoredPriv)
}
