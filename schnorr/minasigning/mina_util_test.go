// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package minasigning

import (
	"crypto/ecdsa"
	"crypto/rand"
	"testing"

	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fq"
	"github.com/coinbase/kryptology/pkg/signatures/schnorr/mina"
	"github.com/stretchr/testify/assert"

	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/tss"
)

func TestMinaSign(t *testing.T) {
	curve := tss.Pallas()

	priv, err := ecdsa.GenerateKey(curve, rand.Reader)
	assert.Nil(t, err)

	minaPriv := new(mina.SecretKey)
	sc := new(fq.Fq).SetBigInt(priv.D)
	minaPriv.SetFq(sc)

	msg := "123456"

	msig, err := minaPriv.SignMessage(msg)
	assert.Nil(t, err)

	err = minaPriv.GetPublicKey().VerifyMessage(msig, msg)
	assert.Nil(t, err)

	pub, err := crypto.NewECPoint(curve, priv.PublicKey.X, priv.PublicKey.Y)
	assert.Nil(t, err)

	err = MinaSchnorrVerify(pub, []byte(msg), append(msig.R.BigInt().Bytes(), msig.S.BigInt().Bytes()...))
	assert.Nil(t, err)
}
