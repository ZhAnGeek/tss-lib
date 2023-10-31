package hkd

import (
	"crypto/elliptic"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/Safulet/tss-lib-private/crypto"
	"github.com/Safulet/tss-lib-private/tss"
	"github.com/stretchr/testify/require"
)

const (
	testBLSG1FixtureDirFormat            = "/test/_bls_fixtures_g1"
	testBLSG2FixtureDirFormat            = "/test/_bls_fixtures_g2"
	testECDSASecp256k1FixtureDirFormat   = "/test/_ecdsa_fixtures_1_3"
	testEDDSAFixtureDirFormat            = "/test/_eddsa_fixtures_1_3"
	testSchnorrSecp256k1FixtureDirFormat = "/test/_schnorr_fixtures_1_3"
	testSchnorrPallasFixtureDirFormat    = "/test/_pallas_fixtures_1_3"

	ecdsaDeltaHex            = "3fedff8d4929d2ee4914f6de4aeca332fc4e27ca75e78730165eb9543668c7f4" // nolint:gosec
	eddsaDeltaHex            = "0ee630e9906f7c55035f9e4699431447c810f41b1b0e1e21e2b20074e0b6ce71" // nolint:gosec
	schnorrSecp256k1DeltaHex = "7f84dbbb7461245eddd32fe3d759a9e0d606c421d511569a9fa10ebfff9d1e2f" // nolint:gosec
	schnorrPallasDeltaHex    = "10b38a9afc7b46a0bab1904468d7870f329921b676fdff73d0f23bc6e8bcad5e" // nolint:gosec
)

type TestLocalPartySaveData struct {
	PubKey   *crypto.ECPoint
	ECDSAPub *crypto.ECPoint
	EDDSAPub *crypto.ECPoint
}

func TestDeriveHardenedChildPublicKey(t *testing.T) {

	ecdsaDelta, err := hex.DecodeString(ecdsaDeltaHex)
	require.Nil(t, err)
	eddsaDelta, err := hex.DecodeString(eddsaDeltaHex)
	require.Nil(t, err)
	schnorrSecp256k1Delta, err := hex.DecodeString(schnorrSecp256k1DeltaHex)
	require.Nil(t, err)
	schnorrPallasDelta, err := hex.DecodeString(schnorrPallasDeltaHex)
	require.Nil(t, err)

	testCases := []struct {
		name      string
		curve     elliptic.Curve
		dirFormat string
		delta     []byte
	}{
		{
			name:      "secp256k1 hkd public key",
			curve:     tss.S256(),
			dirFormat: testECDSASecp256k1FixtureDirFormat,
			delta:     ecdsaDelta,
		},
		{
			name:      "ed25519 hkd public key",
			curve:     tss.Edwards(),
			dirFormat: testEDDSAFixtureDirFormat,
			delta:     eddsaDelta,
		},
		{
			name:      "schnorr-secp256k1 hkd public key",
			curve:     tss.S256(),
			dirFormat: testSchnorrSecp256k1FixtureDirFormat,
			delta:     schnorrSecp256k1Delta,
		},
		{
			name:      "schnorr-pallas hkd public key",
			curve:     tss.Pallas(),
			dirFormat: testSchnorrPallasFixtureDirFormat,
			delta:     schnorrPallasDelta,
		},
	}
	for _, testCase := range testCases {
		t.Run(testCase.name, func(t *testing.T) {
			_, callerFileName, _, _ := runtime.Caller(0)
			srcDirName := filepath.Dir(callerFileName)
			t.Log(srcDirName)
			keydataPath := fmt.Sprintf("%s/../../%s/keygen_data_0.json", srcDirName, testCase.dirFormat)
			keyDataByte, err := os.ReadFile(keydataPath)
			require.Nil(t, err)
			var keyData TestLocalPartySaveData
			require.Nil(t, json.Unmarshal(keyDataByte, &keyData))

			var ecPoint *crypto.ECPoint

			if keyData.PubKey != nil {
				ecPoint = keyData.PubKey
			} else if keyData.ECDSAPub != nil {
				ecPoint = keyData.ECDSAPub
			} else if keyData.EDDSAPub != nil {
				ecPoint = keyData.EDDSAPub
			}

			require.NotNil(t, ecPoint)

			_, hkdErr := DeriveHardenedChildPublicKey(testCase.curve, ecPoint, testCase.delta)
			require.Nil(t, hkdErr)
		})
	}
}
