// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mina

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

	xb := msig.R.BigInt().Bytes()
	yb := msig.S.BigInt().Bytes()
	signature := make([]byte, 64)
	copy(signature[32-len(xb):], xb)
	copy(signature[64-len(yb):], yb)

	err = SchnorrVerify(tss.Pallas(), pub, []byte(msg), signature)
	assert.Nil(t, err)
}
