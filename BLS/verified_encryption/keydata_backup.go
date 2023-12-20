// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package verified_encryption

import (
	"bytes"
	"context"
	"errors"
	"math/big"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/crypto/vss"
	ecdsa_keygen "github.com/Safulet/tss-lib-private/ecdsa/keygen"
	eddsa_keygen "github.com/Safulet/tss-lib-private/eddsa/keygen"
	"github.com/Safulet/tss-lib-private/test"
	"github.com/Safulet/tss-lib-private/tss"
)

type (
	KeyDataBackup struct {
		Ks         []*big.Int
		BigXj      []*crypto.ECPoint
		PK         *crypto.ECPoint
		Digest     []byte
		Index      int
		BackupOfXi *ProofPoe
	}
)

func createKeyDataBackup(Session []byte, CipherPK PublicKey, ks []*big.Int, bigXj []*crypto.ECPoint,
	publicKey *crypto.ECPoint, shareID *big.Int, xi *big.Int) (*KeyDataBackup, error) {

	ctx := context.Background()

	backup := KeyDataBackup{}
	backup.Ks = ks
	backup.BigXj = bigXj
	backup.PK = publicKey
	var err error
	pax := len(ks)
	modQ := common.ModInt(publicKey.Curve().Params().N)
	bigWs := make([]*crypto.ECPoint, pax)
	for j := 0; j < pax; j++ {
		bigWj := bigXj[j]
		for c := 0; c < pax; c++ {
			if j == c {
				continue
			}
			if ks[j].Cmp(ks[c]) == 0 {
				return nil, errors.New("duplicated items in ks")
			}
			q := modQ.Mul(ks[c], modQ.ModInverse(new(big.Int).Sub(ks[c], ks[j])))
			bigWj = bigWj.ScalarMult(q)
		}
		bigWs[j] = bigWj
	}
	publicKeyRef := bigWs[0]
	for i := 1; i < len(bigWs); i++ {
		publicKeyRef, err = publicKeyRef.Add(bigWs[i])
		if err != nil {
			return nil, errors.New("compute sum bigXj[]")
		}
	}
	if !publicKeyRef.Equals(publicKey) {
		return nil, errors.New("publicKey is not according to bigXj[]")
	}
	var toHash [][]byte
	for i := range backup.Ks {
		toHash = append(toHash, backup.Ks[i].Bytes())
	}
	for i := range backup.BigXj {
		bzs := backup.BigXj[i].Bytes()
		toHash = append(toHash, bzs[:]...)
	}
	bzs := backup.PK.Bytes()
	toHash = append(toHash, bzs[:]...)
	digest := common.SHA512_256(ctx, toHash...)
	backup.Digest = digest
	found := false
	for i := range backup.Ks {
		if shareID.Cmp(backup.Ks[i]) == 0 {
			found = true
			backup.Index = i
		}
	}
	if !found {
		return nil, errors.New("ShareID not in Ks")
	}
	poe, err := NewProof(Session, CipherPK, bigXj[backup.Index], xi)
	if err != nil {
		return nil, err
	}
	backup.BackupOfXi = poe

	return &backup, nil
}

func CreateKeyDataBackupECDSA(Session []byte, CipherPK PublicKey, data ecdsa_keygen.LocalPartySaveData) (*KeyDataBackup, error) {
	return createKeyDataBackup(Session, CipherPK, data.Ks, data.BigXj, data.ECDSAPub, data.LocalSecrets.ShareID, data.LocalSecrets.Xi)
}

func CreateKeyDataBackupEDDSA(Session []byte, CipherPK PublicKey, data eddsa_keygen.LocalPartySaveData) (*KeyDataBackup, error) {
	return createKeyDataBackup(Session, CipherPK, data.Ks, data.BigXj, data.EDDSAPub, data.LocalSecrets.ShareID, data.LocalSecrets.Xi)
}

func VerifyKeyDataBackup(Session []byte, CipherPK PublicKey, backup *KeyDataBackup, i int) bool {
	ctx := context.Background()
	var err error
	pax := len(backup.Ks)
	modQ := common.ModInt(backup.PK.Curve().Params().N)
	bigWs := make([]*crypto.ECPoint, pax)
	for j := 0; j < pax; j++ {
		bigWj := backup.BigXj[j]
		for c := 0; c < pax; c++ {
			if j == c {
				continue
			}
			if backup.Ks[j].Cmp(backup.Ks[c]) == 0 {
				return false
			}
			q := modQ.Mul(backup.Ks[c], modQ.ModInverse(new(big.Int).Sub(backup.Ks[c], backup.Ks[j])))
			bigWj = bigWj.ScalarMult(q)
		}
		bigWs[j] = bigWj
	}
	publicKeyRef := bigWs[0]
	for i := 1; i < len(bigWs); i++ {
		publicKeyRef, err = publicKeyRef.Add(bigWs[i])
		if err != nil {
			return false
		}
	}
	if !publicKeyRef.Equals(backup.PK) {
		return false
	}
	if backup.Index != i {
		return false
	}
	if !backup.BigXj[backup.Index].Equals(backup.BackupOfXi.BigW) {
		return false
	}
	var toHash [][]byte
	for i := range backup.Ks {
		toHash = append(toHash, backup.Ks[i].Bytes())
	}
	for i := range backup.BigXj {
		bzs := backup.BigXj[i].Bytes()
		toHash = append(toHash, bzs[:]...)
	}
	bzs := backup.PK.Bytes()
	toHash = append(toHash, bzs[:]...)
	digest := common.SHA512_256(ctx, toHash...)
	if bytes.Compare(backup.Digest, digest) != 0 {
		return false
	}

	ok := backup.BackupOfXi.Verify(Session, CipherPK, backup.BackupOfXi.BigW)
	if !ok {
		return false
	}
	return true
}

func RestorePrivateKeyECDSA(keys []ecdsa_keygen.LocalPartySaveData) (*big.Int, error) {
	ec := keys[0].ECDSAPub.Curve()
	var shares vss.Shares
	for _, key := range keys {
		shares = append(shares, &vss.Share{
			Threshold: test.TestThreshold,
			ID:        key.ShareID,
			Share:     key.Xi,
		})
	}
	sk, err := shares.ReConstruct(ec)
	if err != nil {
		return nil, err
	}

	pk2 := crypto.ScalarBaseMult(ec, sk)
	if !pk2.Equals(keys[0].ECDSAPub) {
		return nil, errors.New("sk reconstructed is not correct")
	}

	return sk, nil
}

func RestorePrivateKeyEDDSA(keys []eddsa_keygen.LocalPartySaveData) (*big.Int, error) {
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
	if err != nil {
		return nil, err
	}

	pk2 := crypto.ScalarBaseMult(ec, sk)
	if !pk2.Equals(keys[0].PubKey) {
		return nil, errors.New("sk reconstructed is not correct")
	}

	return sk, nil
}
