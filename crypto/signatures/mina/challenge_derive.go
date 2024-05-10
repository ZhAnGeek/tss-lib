//
// Copyright Binance, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package mina

import (
	"fmt"

	curves "github.com/Safulet/tss-lib-private/crypto/pallas"
)

type MinaTSchnorrHandler struct{}

func (m MinaTSchnorrHandler) DeriveChallenge(msg []byte, pubKey curves.Point, r curves.Point) (curves.Scalar, error) {
	txn := new(Transaction)
	err := txn.UnmarshalBinary(msg)
	if err != nil {
		return nil, err
	}
	input := new(roinput).Init(3, 75)
	txn.addRoInput(input)

	pt, ok := pubKey.(*curves.PointPallas)
	if !ok {
		return nil, fmt.Errorf("invalid point")
	}
	R, ok := r.(*curves.PointPallas)
	if !ok {
		return nil, fmt.Errorf("invalid point")
	}

	pk := new(PublicKey)
	pk.value = pt.GetEp()

	sc := msgHash(pk, R.X(), input, ThreeW, MainNet)
	s := new(curves.ScalarPallas)
	s.SetFq(sc)
	return s, nil
}