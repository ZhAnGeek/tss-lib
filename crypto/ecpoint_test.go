// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package crypto_test

import (
	"encoding/hex"
	"encoding/json"
	"math/big"
	"reflect"
	"testing"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/stretchr/testify/assert"

	. "github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/edwards25519"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

func TestFlattenECPoints(t *testing.T) {
	type args struct {
		in []*ECPoint
	}
	tests := []struct {
		name    string
		args    args
		want    []*big.Int
		wantErr bool
	}{{
		name: "flatten with 2 points (happy)",
		args: args{[]*ECPoint{
			NewECPointNoCurveCheck(tss.EC(), big.NewInt(1), big.NewInt(2)),
			NewECPointNoCurveCheck(tss.EC(), big.NewInt(3), big.NewInt(4)),
		}},
		want: []*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)},
	}, {
		name: "flatten with nil point (expects err)",
		args: args{[]*ECPoint{
			NewECPointNoCurveCheck(tss.EC(), big.NewInt(1), big.NewInt(2)),
			nil,
			NewECPointNoCurveCheck(tss.EC(), big.NewInt(3), big.NewInt(4))},
		},
		want:    nil,
		wantErr: true,
	}, {
		name: "flatten with nil coordinate (expects err)",
		args: args{[]*ECPoint{
			NewECPointNoCurveCheck(tss.EC(), big.NewInt(1), big.NewInt(2)),
			NewECPointNoCurveCheck(tss.EC(), nil, big.NewInt(4))},
		},
		want:    nil,
		wantErr: true,
	}, {
		name:    "flatten with nil `in` slice",
		args:    args{nil},
		want:    nil,
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := FlattenECPoints(tt.args.in)
			if (err != nil) != tt.wantErr {
				t.Errorf("FlattenECPoints() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("FlattenECPoints() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestUnFlattenECPoints(t *testing.T) {
	type args struct {
		in []*big.Int
	}
	tests := []struct {
		name    string
		args    args
		want    []*ECPoint
		wantErr bool
	}{{
		name: "un-flatten 2 points (happy)",
		args: args{[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), big.NewInt(4)}},
		want: []*ECPoint{
			NewECPointNoCurveCheck(tss.EC(), big.NewInt(1), big.NewInt(2)),
			NewECPointNoCurveCheck(tss.EC(), big.NewInt(3), big.NewInt(4)),
		},
	}, {
		name:    "un-flatten uneven len(points) (expects err)",
		args:    args{[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3)}},
		want:    nil,
		wantErr: true,
	}, {
		name:    "un-flatten with nil coordinate (expects err)",
		args:    args{[]*big.Int{big.NewInt(1), big.NewInt(2), big.NewInt(3), nil}},
		want:    nil,
		wantErr: true,
	}, {
		name:    "flatten with nil `in` slice",
		args:    args{nil},
		want:    nil,
		wantErr: true,
	}}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := UnFlattenECPoints(tss.EC(), tt.args.in, true)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnFlattenECPoints() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("UnFlattenECPoints() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestS256EcpointJsonSerialization(t *testing.T) {
	ec := btcec.S256()
	tss.RegisterCurve("secp256k1", ec)

	pubKeyBytes, err := hex.DecodeString("03935336acb03b2b801d8f8ac5e92c56c4f6e93319901fdfffba9d340a874e2879")
	assert.NoError(t, err)
	pbk, err := btcec.ParsePubKey(pubKeyBytes)
	assert.NoError(t, err)

	point, err := NewECPoint(ec, pbk.ToECDSA().X, pbk.ToECDSA().Y)
	assert.NoError(t, err)
	bz, err := json.Marshal(point)
	assert.NoError(t, err)
	assert.True(t, len(bz) > 0)

	var umpoint ECPoint
	err = json.Unmarshal(bz, &umpoint)
	assert.NoError(t, err)

	assert.True(t, point.Equals(&umpoint))
	assert.True(t, reflect.TypeOf(point.Curve()) == reflect.TypeOf(umpoint.Curve()))
}

func TestEdwardsEcpointJsonSerialization(t *testing.T) {
	ec := tss.Edwards()
	tss.RegisterCurve("ed25519", ec)

	pubKeyBytes, err := hex.DecodeString("ae1e5bf5f3d6bf58b5c222088671fcbe78b437e28fae944c793897b26091f249")
	assert.NoError(t, err)
	pkx, pky := edwards25519.EncodedBytesToEcPoint(pubKeyBytes)
	assert.NotNil(t, pkx, "PubKey.X should not be nil")
	assert.NotNil(t, pky, "PubKey.Y should not be nil")

	point, err := NewECPoint(ec, pkx, pky)
	assert.NoError(t, err)
	bz, err := json.Marshal(point)
	assert.NoError(t, err)
	assert.True(t, len(bz) > 0)

	var umpoint ECPoint
	err = json.Unmarshal(bz, &umpoint)
	assert.NoError(t, err)

	assert.True(t, point.Equals(&umpoint))
	assert.True(t, reflect.TypeOf(point.Curve()) == reflect.TypeOf(umpoint.Curve()))
}

func TestInfinityPoint(t *testing.T) {
	for _, ec := range tss.GetAllCurvesList() {
		G, err := NewECPoint(ec, ec.Params().Gx, ec.Params().Gy)
		assert.NoError(t, err, "construct identity point")
		O, err := G.Sub(G)
		assert.True(t, O.IsInfinityPoint(), "should be infinity point")
		assert.Error(t, err, "point sub should not fail")
		O1 := G.ScalarMult(ec.Params().N)
		assert.True(t, O1.IsInfinityPoint(), "should be infinity point")
		O1 = O.ScalarMult(big.NewInt(23))
		assert.True(t, O1.IsInfinityPoint(), "should be infinity point")

		bzs := O.Bytes()
		x := new(big.Int).SetBytes(bzs[0])
		y := new(big.Int).SetBytes(bzs[1])
		x1, y1 := IntInfinityCoords(ec)
		assert.Zero(t, x.Cmp(x1), "serialize infinity point")
		assert.Zero(t, y.Cmp(y1), "serialize infinity point")
		O2, err := NewECPointFromBytes(ec, bzs[:])
		assert.NoError(t, err, "deserialize infinity point")
		assert.Nil(t, O2.X(), "infinity point coordinate should be nil")
		assert.Nil(t, O2.Y(), "infinity point coordinate should be nil")
	}
}

func OldJsonMarshal(p *ECPoint) ([]byte, error) {
	return json.Marshal(&struct {
		Coords [2]*big.Int
	}{
		Coords: [2]*big.Int{p.X(), p.Y()},
	})
}

func TestJsonUnmarshalPoint(t *testing.T) {
	ec := tss.Curve25519()
	point := ScalarBaseMult(ec, big.NewInt(667667))
	bzs, err := OldJsonMarshal(point)
	assert.NoError(t, err)
	var point2 ECPoint
	err = json.Unmarshal(bzs, &point2)
	assert.Error(t, err)

	ec = tss.P256()
	point = ScalarBaseMult(ec, big.NewInt(667667))
	bzs, err = OldJsonMarshal(point)
	assert.NoError(t, err)
	err = json.Unmarshal(bzs, &point2)
	assert.NoError(t, err)

	ec = tss.S256()
	point = ScalarBaseMult(ec, big.NewInt(667667))
	bzs, err = OldJsonMarshal(point)
	assert.NoError(t, err)
	err = json.Unmarshal(bzs, &point2)
	assert.NoError(t, err)

	ec = tss.Edwards()
	point = ScalarBaseMult(ec, big.NewInt(667667))
	bzs, err = OldJsonMarshal(point)
	assert.NoError(t, err)
	err = json.Unmarshal(bzs, &point2)
	assert.NoError(t, err)
}
