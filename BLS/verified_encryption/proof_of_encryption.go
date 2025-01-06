// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package verified_encryption

import (
	"bytes"
	syscrypto "crypto"
	"encoding/binary"
	"errors"
	"hash"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/bls12381"
	"github.com/Safulet/tss-lib-private/v2/tss"
)

const (
	Iterations         = 128
	ProofPoeBytesParts = Iterations*10 + 4
)

var (
	suite    = bls12381.GetBLSSignatureSuiteG1()
	cipherEC = tss.GetBLSCurveBySuite(suite)
)

type (
	PublicKey  = *crypto.ECPoint
	CipherText = []byte
	ProofPoe   struct {
		BigW    *crypto.ECPoint
		PK      PublicKey
		Q0      [Iterations]*crypto.ECPoint
		C0      [Iterations]CipherText
		Q1      [Iterations]*crypto.ECPoint
		C1      [Iterations]CipherText
		Xb      [Iterations]*big.Int
		AesKeyb [Iterations][]byte
		IVb     [Iterations][]byte
		Rb      [Iterations]*big.Int
	}
)

type FiatShamir struct {
	cnt     uint64
	session []byte
	hs      hash.Hash
}

func (fs *FiatShamir) Init(Session []byte) {
	fs.cnt = 0
	fs.session = Session
	fs.hs = syscrypto.SHA512_256.New()
	fs.hs.Write(Session)
}

func (fs *FiatShamir) Push(vals []*big.Int) {
	for _, val := range vals {
		if val != nil {
			fs.hs.Write(val.Bytes())
		}
	}
}

func (fs *FiatShamir) GetChallenge() *big.Int {
	bs := make([]byte, 8)
	binary.LittleEndian.PutUint64(bs, fs.cnt)
	fs.cnt = fs.cnt + 1
	fs.hs.Write(bs)
	fs.hs.Write(fs.session)
	challenge := fs.hs.Sum(nil)
	return new(big.Int).SetBytes(challenge)
}

func (fs *FiatShamir) Reset() {
	fs.hs.Reset()
	fs.cnt = 0
}

func NewProof(Session []byte, PK PublicKey, BigW *crypto.ECPoint, w *big.Int) (*ProofPoe, error) {
	ec := BigW.Curve()
	N := ec.Params().N
	x := w
	BigW_ := crypto.ScalarBaseMult(ec, x)
	if !BigW.Equals(BigW_) {
		return nil, errors.New("BigW is not compatible with w")
	}
	Proof := &ProofPoe{}
	Proof.BigW = BigW
	Proof.PK = PK

	fs := FiatShamir{}
	fs.Init(Session)
	fs.Push([]*big.Int{N, ec.Params().B, ec.Params().Gx, ec.Params().Gy, ec.Params().P})

	openXbInfos := make([][2]*big.Int, Iterations)
	openAesKeybInfos := make([][2][]byte, Iterations)
	openIvbInfos := make([][2][]byte, Iterations)
	openRbInfos := make([][2]*big.Int, Iterations)

	for iter := 0; iter < Iterations; iter++ {
		x0i := common.GetRandomPositiveInt(N)
		Q0i := crypto.ScalarBaseMult(ec, x0i)
		x1i := new(big.Int).Mod(new(big.Int).Sub(x, x0i), ec.Params().N)
		Q1i := crypto.ScalarBaseMult(ec, x1i)

		C0i, aesKey0i, iv0i, r0i, err := BLSEncryptionAndReturnRandomness(cipherEC, PK, x0i.Bytes())
		if err != nil {
			return nil, err
		}
		C1i, aesKey1i, iv1i, r1i, err := BLSEncryptionAndReturnRandomness(cipherEC, PK, x1i.Bytes())
		if err != nil {
			return nil, err
		}

		fs.Push([]*big.Int{Q0i.X(), Q0i.Y(), Q1i.X(), Q1i.Y(), new(big.Int).SetBytes(C0i.CipherText), new(big.Int).SetBytes(C1i.CipherText)})
		openXbInfos[iter][0] = x0i
		openXbInfos[iter][1] = x1i
		openAesKeybInfos[iter][0] = aesKey0i
		openAesKeybInfos[iter][1] = aesKey1i
		openIvbInfos[iter][0] = iv0i
		openIvbInfos[iter][1] = iv1i
		openRbInfos[iter][0] = r0i
		openRbInfos[iter][1] = r1i
		Proof.Q0[iter] = Q0i
		Proof.C0[iter] = C0i.CipherText
		Proof.Q1[iter] = Q1i
		Proof.C1[iter] = C1i.CipherText
	}

	challenge := fs.GetChallenge()

	for iter := 0; iter < Iterations; iter++ {
		bitNum := challenge.Bit(iter)
		Proof.Xb[iter] = openXbInfos[iter][bitNum]
		Proof.AesKeyb[iter] = openAesKeybInfos[iter][bitNum]
		Proof.IVb[iter] = openIvbInfos[iter][bitNum]
		Proof.Rb[iter] = openRbInfos[iter][bitNum]
	}

	return Proof, nil
}

func (pf *ProofPoe) Verify(Session []byte, PK PublicKey, BigW *crypto.ECPoint) bool {
	if !pf.ValidateBasic() {
		return false
	}
	if !BigW.IsOnCurve() {
		return false
	}
	ec := pf.BigW.Curve()
	if !tss.SameCurve(ec, BigW.Curve()) {
		return false
	}
	if !BigW.Equals(pf.BigW) {
		return false
	}
	if !PK.Equals(pf.PK) {
		return false
	}

	fs := FiatShamir{}
	fs.Init(Session)
	fs.Push([]*big.Int{ec.Params().N, ec.Params().B, ec.Params().Gx, ec.Params().Gy, ec.Params().P})

	for iter := 0; iter < Iterations; iter++ {
		fs.Push([]*big.Int{pf.Q0[iter].X(), pf.Q0[iter].Y(), pf.Q1[iter].X(), pf.Q1[iter].Y(),
			new(big.Int).SetBytes(pf.C0[iter]), new(big.Int).SetBytes(pf.C1[iter])})
	}

	challenge := fs.GetChallenge()
	for iter := 0; iter < Iterations; iter++ {
		ei := challenge.Bit(iter)

		aesKey := pf.AesKeyb[iter]
		iv := pf.IVb[iter]
		r := pf.Rb[iter]
		Cbi, err := BLSEncryptionWithRandomness(cipherEC, PK, pf.Xb[iter].Bytes(), aesKey, iv, r)
		if err != nil {
			return false
		}
		Qbi := crypto.ScalarBaseMult(ec, pf.Xb[iter])
		if Qbi == nil {
			return false
		}
		pfCbi := pf.C0[iter]
		pfQbi := pf.Q0[iter]
		if ei == 1 {
			pfCbi = pf.C1[iter]
			pfQbi = pf.Q1[iter]
		}
		if !bytes.Equal(Cbi.CipherText, pfCbi) {
			return false
		}
		if !Qbi.Equals(pfQbi) {
			return false
		}
		Q, err := pf.Q0[iter].Add(pf.Q1[iter])
		if err != nil {
			return false
		}
		if !BigW.Equals(Q) {
			return false
		}
	}

	return true
}

func (pf *ProofPoe) ValidateBasic() bool {
	if pf.BigW == nil {
		return false
	}
	if pf.PK == nil {
		return false
	}
	for _, Q0i := range pf.Q0 {
		if Q0i == nil {
			return false
		}
	}
	for _, C0i := range pf.C0 {
		if C0i == nil {
			return false
		}
	}
	for _, Q1i := range pf.Q1 {
		if Q1i == nil {
			return false
		}
	}
	for _, C1i := range pf.C1 {
		if C1i == nil {
			return false
		}
	}
	for _, Xbi := range pf.Xb {
		if Xbi == nil {
			return false
		}
	}
	for _, Rbi := range pf.Rb {
		if Rbi == nil {
			return false
		}
	}

	return true
}

func (pf *ProofPoe) Bytes() [ProofPoeBytesParts][]byte {
	bzs := [ProofPoeBytesParts][]byte{}
	BigWBzs := pf.BigW.Bytes()
	bzs[0] = BigWBzs[0]
	bzs[1] = BigWBzs[1]
	PKBzs := pf.PK.Bytes()
	bzs[2] = PKBzs[0]
	bzs[3] = PKBzs[1]
	loc := 4
	for i := range pf.Q0 {
		Q0iBzs := pf.Q0[i].Bytes()
		bzs[loc] = Q0iBzs[0]
		loc++
		bzs[loc] = Q0iBzs[1]
		loc++
	}
	for i := range pf.C0 {
		bzs[loc] = pf.C0[i]
		loc++
	}
	for i := range pf.Q1 {
		Q1iBzs := pf.Q1[i].Bytes()
		bzs[loc] = Q1iBzs[0]
		loc++
		bzs[loc] = Q1iBzs[1]
		loc++
	}
	for i := range pf.C1 {
		bzs[loc] = pf.C1[i]
		loc++
	}
	for i := range pf.Xb {
		bzs[loc] = pf.Xb[i].Bytes()
		loc++
	}
	for i := range pf.AesKeyb {
		bzs[loc] = pf.AesKeyb[i]
		loc++
	}
	for i := range pf.IVb {
		bzs[loc] = pf.IVb[i]
		loc++
	}
	for i := range pf.Rb {
		bzs[loc] = pf.Rb[i].Bytes()
		loc++
	}

	return bzs
}
