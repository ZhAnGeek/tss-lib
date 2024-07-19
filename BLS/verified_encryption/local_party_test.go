// Copyright © 2019 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package verified_encryption

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"math/big"
	"sync/atomic"
	"testing"

	"github.com/Safulet/tss-lib-private/v2/BLS/decryption"
	"github.com/Safulet/tss-lib-private/v2/BLS/keygen"
	"github.com/Safulet/tss-lib-private/v2/common"
	ecdsa_keygen "github.com/Safulet/tss-lib-private/v2/ecdsa/keygen"
	eddsa_keygen "github.com/Safulet/tss-lib-private/v2/eddsa/keygen"
	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/Safulet/tss-lib-private/v2/test"
	"github.com/Safulet/tss-lib-private/v2/tss"
	"github.com/stretchr/testify/assert"
)

const (
	testParticipants = test.TestParticipants
	testThreshold    = test.TestThreshold
)

func setUp(level string) {
	if err := log.SetLogLevel(level); err != nil {
		panic(err)
	}
}

func TestBLSEncryption(t *testing.T) {
	keys, ePIDs, err := keygen.LoadKeygenTestFixturesRandomSet(cipherEC, testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(ePIDs))

	pk := keys[0].PubKey
	msg := []byte("hello world")

	encrypted, aesKey, iv, r, err := BLSEncryptionAndReturnRandomness(cipherEC, pk, msg)
	assert.NoError(t, err)
	fmt.Println(new(big.Int).SetBytes(encrypted.CipherText))
	encrypted, err = BLSEncryptionWithRandomness(cipherEC, pk, msg, aesKey, iv, r)
	assert.NoError(t, err)
	fmt.Println(new(big.Int).SetBytes(encrypted.CipherText))
}

func TestBackupECDSA(t *testing.T) {
	setUp(log.DebugLevel)
	keys, ePIDs, err := keygen.LoadKeygenTestFixturesRandomSet(cipherEC, testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(ePIDs))

	cipherPk := keys[0].PubKey
	cName, ok := tss.GetCurveName(cipherPk.Curve())
	assert.True(t, ok)
	fmt.Println("cipherPK curve:", cName)

	// party 0 create backup of his ecdsa wallet
	wallets, _, err := ecdsa_keygen.LoadKeygenTestFixtures(testThreshold + 1)
	assert.NoError(t, err, "should load ecdsa keygen fixtures")
	wallet := wallets[0]
	Session := []byte("test session")
	backup, err := CreateKeyDataBackupECDSA(Session, cipherPk, wallet)
	assert.NoError(t, err, "should create wallet backup")
	assert.NotNil(t, backup, "should create wallet backup")

	var totalBzs []byte
	bzs := backup.BackupOfXi.Bytes()
	for i := range bzs {
		totalBzs = append(totalBzs, bzs[i]...)
	}
	fmt.Println("size of backup.poe:", len(totalBzs))
	// party 1 check backup.Digest == localDigest
	correctDigest := computeLocalDigestECDSA(wallets[1])
	assert.Zero(t, bytes.Compare(correctDigest, backup.Digest), "backup digest should be equal")
	// party 1 check backup from party 0
	idx := 0
	valid := VerifyKeyDataBackup(Session, cipherPk, backup, idx)
	assert.True(t, valid, "backup should be valid")

	wallet0RestoredWithoutPreParams, err := RestoreFromKeyDataBackupECDSA(backup)
	assert.NoError(t, err, "restore from backup should not fail")
	fmt.Println(wallet0RestoredWithoutPreParams.LocalSecrets.Xi.String())
	assert.Zero(t, wallet.LocalSecrets.Xi.Cmp(wallet0RestoredWithoutPreParams.LocalSecrets.Xi), "should restore to same wallet key share")

	wallets[0] = *wallet0RestoredWithoutPreParams
	privateKey, err := RestorePrivateKeyECDSA(wallets)
	fmt.Println("private key:", privateKey.String())
}

func TestBackupEDDSA(t *testing.T) {
	setUp(log.DebugLevel)
	keys, ePIDs, err := keygen.LoadKeygenTestFixturesRandomSet(cipherEC, testThreshold+1, testParticipants)
	assert.NoError(t, err, "should load keygen fixtures")
	assert.Equal(t, testThreshold+1, len(keys))
	assert.Equal(t, testThreshold+1, len(ePIDs))

	cipherPk := keys[0].PubKey

	// party 0 create backup of his ecdsa wallet
	wallets, _, err := eddsa_keygen.LoadKeygenTestFixtures(testThreshold + 1)
	assert.NoError(t, err, "should load ecdsa keygen fixtures")
	wallet := wallets[0]
	Session := []byte("test session")
	backup, err := CreateKeyDataBackupEDDSA(Session, cipherPk, wallet)
	assert.NoError(t, err, "should create wallet backup")
	assert.NotNil(t, backup, "should create wallet backup")

	var totalBzs []byte
	bzs := backup.BackupOfXi.Bytes()
	for i := range bzs {
		totalBzs = append(totalBzs, bzs[i]...)
	}
	fmt.Println("size of backup.poe:", len(totalBzs))
	// party 1 check backup.Digest == localDigest
	correctDigest := computeLocalDigestEDDSA(wallets[1])
	assert.Zero(t, bytes.Compare(correctDigest, backup.Digest), "backup digest should be equal")
	// party 1 check backup from party 0
	idx := 0
	valid := VerifyKeyDataBackup(Session, cipherPk, backup, idx)
	assert.True(t, valid, "backup should be valid")

	wallet0RestoredWithoutPreParams, err := RestoreFromKeyDataBackupEDDSA(backup)
	assert.NoError(t, err, "restore from backup should not fail")
	fmt.Println(wallet0RestoredWithoutPreParams.LocalSecrets.Xi.String())
	assert.Zero(t, wallet.LocalSecrets.Xi.Cmp(wallet0RestoredWithoutPreParams.LocalSecrets.Xi), "should restore to same wallet key share")

	wallets[0] = *wallet0RestoredWithoutPreParams
	assert.True(t, tss.SameCurve(tss.Edwards(), wallets[0].PubKey.Curve()), "not curve edwards")
	privateKey, err := RestorePrivateKeyEDDSA(wallets)
	assert.NoError(t, err)
	fmt.Println("private key:", privateKey.String())
}

func RestoreFromKeyDataBackupECDSA(backup *KeyDataBackup) (*ecdsa_keygen.LocalPartySaveData, error) {
	ec := backup.BigXj[0].Curve()
	keydata := ecdsa_keygen.LocalPartySaveData{}
	keydata.Ks = backup.Ks
	keydata.BigXj = backup.BigXj
	keydata.ECDSAPub = backup.PK
	keydata.LocalSecrets.ShareID = keydata.Ks[backup.Index]

	// decrypt keydata.LocalSecrets.Xi
	x0, err := decryptFromDecryptionProtocol(backup.BackupOfXi.C0[0])
	if err != nil || x0 == nil {
		return nil, err
	}
	x1, err := decryptFromDecryptionProtocol(backup.BackupOfXi.C1[0])
	if err != nil || x1 == nil {
		return nil, err
	}
	x := new(big.Int).Add(x0, x1)
	x = new(big.Int).Mod(x, ec.Params().N)
	keydata.LocalSecrets.Xi = x

	return &keydata, nil
}

func RestoreFromKeyDataBackupEDDSA(backup *KeyDataBackup) (*eddsa_keygen.LocalPartySaveData, error) {
	ec := backup.BigXj[0].Curve()
	keydata := eddsa_keygen.LocalPartySaveData{}
	keydata.Ks = backup.Ks
	keydata.BigXj = backup.BigXj
	keydata.EDDSAPub = backup.PK
	keydata.PubKey = backup.PK
	keydata.LocalSecrets.ShareID = keydata.Ks[backup.Index]

	// decrypt keydata.LocalSecrets.Xi
	x0, err := decryptFromDecryptionProtocol(backup.BackupOfXi.C0[0])
	if err != nil || x0 == nil {
		return nil, err
	}
	x1, err := decryptFromDecryptionProtocol(backup.BackupOfXi.C1[0])
	if err != nil || x1 == nil {
		return nil, err
	}
	x := new(big.Int).Add(x0, x1)
	x = new(big.Int).Mod(x, ec.Params().N)
	keydata.LocalSecrets.Xi = x

	return &keydata, nil
}

func decryptFromDecryptionProtocol(C CipherText) (*big.Int, error) {
	ctx := context.Background()
	setUp(log.ErrorLevel)
	keys, ePIDs, err := keygen.LoadKeygenTestFixturesRandomSet(cipherEC, testThreshold+1, testParticipants)
	if err != nil {
		return nil, errors.New("not load keys")
	}

	// this run of bls-decrypt only cipher owner should get result (by message control)
	var x *big.Int
	// run bls-decrypt for C0
	parties := make([]*decryption.LocalParty, 0, len(ePIDs))
	updater := test.SharedPartyUpdater
	decP2pCtx := tss.NewPeerContext(ePIDs)
	decErrCh := make(chan *tss.Error, len(ePIDs))
	decOutCh := make(chan tss.Message, len(ePIDs))
	decEndCh := make(chan decryption.DecryptedData, len(ePIDs))
	// init the parties
	for i := 0; i < len(ePIDs); i++ {
		params := tss.NewParameters(cipherEC, decP2pCtx, ePIDs[i], len(ePIDs), testThreshold, false, 0)
		P := decryption.NewLocalParty(ctx, C, params, keys[i], decOutCh, decEndCh).(*decryption.LocalParty)
		parties = append(parties, P)
		go func(P *decryption.LocalParty) {
			if err := P.Start(ctx); err != nil {
				decErrCh <- err
			}
		}(P)
	}

	var ended int32
decryptC:
	for {
		select {
		case err := <-decErrCh:
			return nil, err

		case msg := <-decOutCh:
			dest := msg.GetTo()
			if dest == nil {
				for _, P := range parties {
					if P.PartyID().Index == msg.GetFrom().Index {
						continue
					}
					go updater(ctx, P, msg, decErrCh)
				}
			} else {
				if dest[0].Index == msg.GetFrom().Index {
					return nil, errors.New("msg to himself")
				}
				go updater(ctx, parties[dest[0].Index], msg, decErrCh)
			}

		case res := <-decEndCh:
			atomic.AddInt32(&ended, 1)
			if atomic.LoadInt32(&ended) == int32(len(ePIDs)) {
				x = new(big.Int).SetBytes(res.ClearText)
				break decryptC
			}
		}
	}

	return x, nil
}

func computeLocalDigestECDSA(key ecdsa_keygen.LocalPartySaveData) []byte {
	ctx := context.Background()
	var toHash [][]byte
	for i := range key.Ks {
		toHash = append(toHash, key.Ks[i].Bytes())
	}
	for i := range key.BigXj {
		bzs := key.BigXj[i].Bytes()
		toHash = append(toHash, bzs[:]...)
	}
	bzs := key.ECDSAPub.Bytes()
	toHash = append(toHash, bzs[:]...)
	digest := common.SHA512_256(ctx, toHash...)

	return digest
}

func computeLocalDigestEDDSA(key eddsa_keygen.LocalPartySaveData) []byte {
	ctx := context.Background()
	var toHash [][]byte
	for i := range key.Ks {
		toHash = append(toHash, key.Ks[i].Bytes())
	}
	for i := range key.BigXj {
		bzs := key.BigXj[i].Bytes()
		toHash = append(toHash, bzs[:]...)
	}
	bzs := key.PubKey.Bytes()
	toHash = append(toHash, bzs[:]...)
	digest := common.SHA512_256(ctx, toHash...)

	return digest
}
