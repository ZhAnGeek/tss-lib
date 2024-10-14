//
// These functions are compatible with the “G2Curve” function defined in IETF-draft
// https://tools.ietf.org/pdf/draft-irtf-cfrg-bls-signature-04.pdf.

package bls12381

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/hmac"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"fmt"
	"math/big"
	"strconv"

	"github.com/Safulet/tss-lib-private/v2/common"
	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
)

type fe [6]uint64

// modulus = p
var (
	HmacSize = 32
	modulus  = fe{0xb9feffffffffaaab, 0x1eabfffeb153ffff, 0x6730d2a0f6b0f624, 0x64774b84f38512bf, 0x4b1ba7b6434bacd7, 0x1a0111ea397fe69a}
)

func (fe *fe) big() *big.Int {
	return new(big.Int).SetBytes(fe.bytes())
}

func (fe *fe) bytes() []byte {
	out := make([]byte, 48)
	var a int
	for i := 0; i < 6; i++ {
		a = 48 - i*8
		out[a-1] = byte(fe[i])
		out[a-2] = byte(fe[i] >> 8)
		out[a-3] = byte(fe[i] >> 16)
		out[a-4] = byte(fe[i] >> 24)
		out[a-5] = byte(fe[i] >> 32)
		out[a-6] = byte(fe[i] >> 40)
		out[a-7] = byte(fe[i] >> 48)
		out[a-8] = byte(fe[i] >> 56)
	}
	return out
}

const (
	PublicKeySizeG2 = 96
	PublicKeySizeG1 = 48
	PrivateKeySize  = 32
	SignatureSizeG1 = 48
	SignatureSizeG2 = 96
	AesKeySize      = 32
	Sha256SumSize   = 32
	PointG1Size     = 96
	PointG2Size     = 192
)

var (
	zero = big.NewInt(0)
)

type PublicKey []byte

type PrivateKey []byte

func Sign(suite []byte, privateKey PrivateKey, message []byte) []byte {
	if bytes.Equal(suite, GetBLSSignatureSuiteG1()) {
		size := SignatureSizeG1 * 2
		signature := make([]byte, size)
		signG1(signature, privateKey, message)
		return signature
	}
	if bytes.Equal(suite, GetBLSSignatureSuiteG2()) {
		size := SignatureSizeG2 * 2
		signature := make([]byte, size)
		signG2(signature, privateKey, message)
		return signature
	}
	return nil
}

func signG1(signature, privateKey, message []byte) {
	privateKey, err := PadToLengthBytesInPlace(privateKey, PrivateKeySize)
	if err != nil {
		panic(err)
	}
	if l := len(privateKey); l != PrivateKeySize {
		panic("bls12381:bad private key length" + strconv.Itoa(l))
	}
	g1 := bls.NewG1()
	sk := new(big.Int).SetBytes(privateKey)
	dig, err := HashToPointG1(message)
	if err != nil {
		panic("bls12381: invalid message hashing into G1Curve")
	}

	G1MulScalarMont(dig, dig, sk)
	copy(signature[:SignatureSizeG1*2], g1.ToBytes(dig))
}

func signG2(signature, privateKey, message []byte) {
	privateKey, err := PadToLengthBytesInPlace(privateKey, PrivateKeySize)
	if err != nil {
		panic(err)
	}
	if l := len(privateKey); l != PrivateKeySize {
		panic("bls12381:bad private key length" + strconv.Itoa(l))
	}
	g2 := bls.NewG2()
	sk := new(big.Int).SetBytes(privateKey)
	dig, err := HashToPointG2(message)
	if err != nil {
		panic("bls12381: invalid message hashing into G2Curve")
	}

	G2MulScalarMont(dig, dig, sk)
	copy(signature[:SignatureSizeG2*2], g2.ToBytes(dig))
}

func Verify(suite []byte, publicKey PublicKey, message, sig []byte) bool {
	if bytes.Equal(suite, GetBLSSignatureSuiteG1()) {
		return verifyG1(publicKey, message, sig)
	}
	if bytes.Equal(suite, GetBLSSignatureSuiteG2()) {
		return verifyG2(publicKey, message, sig)
	}
	return false
}

func verifyG1(publicKey PublicKey, message, sig []byte) bool {
	pk, err := bls.NewG2().FromBytes(publicKey)
	if err != nil {
		return false
	}

	g1 := bls.NewG1()
	dig, err := HashToPointG1(message)
	if err != nil {
		panic("bls12381: invalid message hashing into G1Curve")
	}
	sig, err = PadToLengthBytesInPlace(sig, PublicKeySizeG1*2)
	if err != nil {
		return false
	}
	signature, err := g1.FromBytes(sig)
	if err != nil {
		return false
	}

	c1 := bls.NewPairingEngine()
	r1 := c1.AddPair(dig, pk).Result()

	c2 := bls.NewPairingEngine()
	g2 := bls.NewG2()
	p2 := g2.One()
	r2 := c2.AddPair(signature, p2).Result()

	if !g2.InCorrectSubgroup(pk) {
		return false
	}
	if !g1.InCorrectSubgroup(signature) {
		return false
	}

	return r1.Equal(r2)
}

func verifyG2(publicKey PublicKey, message, sig []byte) bool {
	pk, err := bls.NewG1().FromBytes(publicKey)
	if err != nil {
		return false
	}

	g2 := bls.NewG2()
	dig, err := HashToPointG2(message)
	if err != nil {
		panic("bls12381: invalid message hashing into G2Curve")
	}
	sig, err = PadToLengthBytesInPlace(sig, PublicKeySizeG2*2)
	if err != nil {
		return false
	}

	signature, err := g2.FromBytes(sig)
	if err != nil {
		return false
	}

	c1 := bls.NewPairingEngine()
	r1 := c1.AddPair(pk, dig).Result()

	c2 := bls.NewPairingEngine()
	g1 := bls.NewG1()
	p2 := g1.One()
	r2 := c2.AddPair(p2, signature).Result()

	if !g1.InCorrectSubgroup(pk) {
		return false
	}
	if !g2.InCorrectSubgroup(signature) {
		return false
	}

	return r1.Equal(r2)
}

func VerifyDecryptShareSignatureSuiteG1(share []byte, Yi *bls.PointG2, U *bls.PointG2, W *bls.PointG1, H *bls.PointG1) error {
	g2 := bls.NewG2()
	g1 := bls.NewG1()
	fst := bls.NewPairingEngine()
	snd := bls.NewPairingEngine()
	Ui, err := g2.FromBytes(share[:PointG2Size])
	if err != nil {
		return err
	}
	if g2.IsZero(Ui) || !g2.InCorrectSubgroup(Ui) {
		return fmt.Errorf("ui is not valid, could be infinity or wrong subgroup")
	}
	Wi, err := g1.FromBytes(share[PointG2Size:])
	if err != nil {
		return err
	}
	if g1.IsZero(Wi) || !g1.InCorrectSubgroup(Wi) {
		return fmt.Errorf("Wi is not valid, could be infinity or wrong subgroup")
	}
	fst.AddPair(W, Ui)
	snd.AddPair(Wi, U)

	if !fst.Result().Equal(snd.Result()) {
		return errors.New("U verification failed, please recheck U integrity")
	}

	fst2 := bls.NewPairingEngine()
	snd2 := bls.NewPairingEngine()

	fst2.AddPair(W, Yi)
	snd2.AddPair(H, Ui)

	if !fst2.Result().Equal(snd2.Result()) {
		return errors.New("Y verification failed, please recheck Y integrity")
	}

	return nil
}

func VerifyDecryptShareSignatureSuiteG2(share []byte, Yi *bls.PointG1, U *bls.PointG1, W *bls.PointG2, H *bls.PointG2) error {
	g2 := bls.NewG2()
	g1 := bls.NewG1()
	fst := bls.NewPairingEngine()
	snd := bls.NewPairingEngine()
	Ui, err := g1.FromBytes(share[:PointG1Size])
	if err != nil {
		return err
	}
	if g1.IsZero(Ui) || !g1.InCorrectSubgroup(Ui) {
		return fmt.Errorf("ui is not valid, could be infinity or wrong subgroup")
	}
	Wi, err := g2.FromBytes(share[PointG1Size:])
	if err != nil {
		return err
	}
	if g2.IsZero(Wi) || !g2.InCorrectSubgroup(Wi) {
		return fmt.Errorf("Wi is not valid, could be infinity or wrong subgroup")
	}
	fst.AddPair(Ui, W)
	snd.AddPair(U, Wi)

	if !fst.Result().Equal(snd.Result()) {
		return errors.New("U verification failed, please recheck U integrity")
	}

	fst2 := bls.NewPairingEngine()
	snd2 := bls.NewPairingEngine()

	fst2.AddPair(Yi, W)
	snd2.AddPair(Ui, H)

	if !fst2.Result().Equal(snd2.Result()) {
		return errors.New("Y verification failed, please recheck Y integrity")
	}

	return nil
}

func Decrypt(suite []byte, shares [][]byte, cipherText []byte, yig2 []*bls.PointG2, yig1 []*bls.PointG1) ([]byte, error) {
	if bytes.Equal(suite, GetBLSSignatureSuiteG1()) {
		iv := cipherText[:aes.BlockSize]
		cipherText = cipherText[aes.BlockSize:]
		U, V, W, err := getUVWFromCipherTextSignatureSuiteG1(cipherText)
		if err != nil {
			return nil, err
		}
		H, err := hashToGroupG2(U, V)
		if err != nil {
			return nil, err
		}
		if err = VerifyCipherTextSignatureSuiteG1(U, V, W); err != nil {
			return nil, err
		}

		for i, share := range shares {
			if err := VerifyDecryptShareSignatureSuiteG1(share, yig2[i], U, W, H); err != nil {
				return nil, err
			}
		}

		combined, err := combineSharesSignatureSuiteG1(shares)
		if err != nil {
			return nil, err
		}

		combinedSha256 := g2ToBytes(combined)

		for i, b := range V {
			combinedSha256[i] ^= b
		}

		aesKey := combinedSha256
		encrypedMessage := cipherText[PointG2Size+PointG1Size+Sha256SumSize:]
		pureMsg := make([]byte, len(encrypedMessage)-32)
		copy(pureMsg, encrypedMessage[:len(encrypedMessage)-32])

		hmacActual := hmac.New(sha256.New, iv).Sum(pureMsg)
		if !hmac.Equal(encrypedMessage, hmacActual) {
			return nil, fmt.Errorf("not authenticated")
		}
		aesCipher, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, err
		}
		message := make([]byte, 0)
		decrypter, err := cipher.NewGCM(aesCipher)
		if err != nil {
			return nil, err
		}
		return decrypter.Open(message, iv[:decrypter.NonceSize()], pureMsg, []byte{})
	}

	if bytes.Equal(suite, GetBLSSignatureSuiteG2()) {
		iv := cipherText[:aes.BlockSize]
		cipherText = cipherText[aes.BlockSize:]
		U, V, W, err := getUVWFromCipherTextSignatureSuiteG2(cipherText)
		if err != nil {
			return nil, err
		}
		H, err := hashToGroupG1(U, V)
		if err != nil {
			return nil, err
		}
		if err = VerifyCipherTextSignatureSuiteG2(U, V, W); err != nil {
			return nil, err
		}

		for i, share := range shares {
			if err := VerifyDecryptShareSignatureSuiteG2(share, yig1[i], U, W, H); err != nil {
				return nil, err
			}
		}

		combined, err := combineSharesSignatureSuiteG2(shares)
		if err != nil {
			return nil, err
		}

		combinedSha256 := g1ToBytes(combined)

		for i, b := range V {
			combinedSha256[i] ^= b
		}

		aesKey := combinedSha256
		encrypedMessage := cipherText[PointG2Size+PointG1Size+Sha256SumSize:]
		pureMsg := make([]byte, len(encrypedMessage)-32)
		copy(pureMsg, encrypedMessage[:len(encrypedMessage)-32])

		hmacActual := hmac.New(sha256.New, iv).Sum(pureMsg)
		if !hmac.Equal(encrypedMessage, hmacActual) {
			return nil, fmt.Errorf("not authenticated")
		}
		aesCipher, err := aes.NewCipher(aesKey)
		if err != nil {
			return nil, err
		}
		message := make([]byte, 0)
		decrypter, err := cipher.NewGCM(aesCipher)
		if err != nil {
			return nil, err
		}
		return decrypter.Open(message, iv[:decrypter.NonceSize()], pureMsg, []byte{})
	}

	return nil, fmt.Errorf("no suite")
}

func combineSharesSignatureSuiteG1(shares [][]byte) (*bls.PointG2, error) {
	sharePoints := make([]*bls.PointG2, len(shares))
	g2 := bls.NewG2()
	for i := 0; i < len(shares); i++ {
		point, err := g2.FromBytes(shares[i][:PointG2Size])
		if err != nil {
			return nil, err
		}
		sharePoints[i] = point
	}
	ret := g2.Zero()
	for _, point := range sharePoints {
		g2.Add(ret, ret, point)
	}
	return ret, nil
}

func combineSharesSignatureSuiteG2(shares [][]byte) (*bls.PointG1, error) {
	sharePoints := make([]*bls.PointG1, len(shares))
	g1 := bls.NewG1()
	for i := 0; i < len(shares); i++ {
		point, err := g1.FromBytes(shares[i][:PointG1Size])
		if err != nil {
			return nil, err
		}
		sharePoints[i] = point
	}
	ret := g1.Zero()
	for _, point := range sharePoints {
		g1.Add(ret, ret, point)
	}
	return ret, nil
}

func VerifyCipherTextSignatureSuiteG1(U *bls.PointG2, V []byte, W *bls.PointG1) error {
	H, err := hashToGroupG2(U, V)
	if err != nil {
		return err
	}
	g2 := bls.NewG2()
	g1 := bls.NewG1()
	if g1.IsZero(H) || !g1.InCorrectSubgroup(H) {
		return fmt.Errorf("H generate by U,V is not valid")
	}
	fst := bls.NewPairingEngine()
	snd := bls.NewPairingEngine()
	fst.AddPair(W, g2.One())
	snd.AddPair(H, U)

	if !fst.Result().Equal(snd.Result()) {
		return errors.New("decrypted failed for validation")
	}

	return nil
}

func VerifyCipherTextSignatureSuiteG2(U *bls.PointG1, V []byte, W *bls.PointG2) error {
	H, err := hashToGroupG1(U, V)
	if err != nil {
		return err
	}
	g2 := bls.NewG2()
	g1 := bls.NewG1()
	if g2.IsZero(H) || !g2.InCorrectSubgroup(H) {
		return fmt.Errorf("H generate by U,V is not valid")
	}
	fst := bls.NewPairingEngine()
	snd := bls.NewPairingEngine()
	fst.AddPair(g1.One(), W)
	snd.AddPair(U, H)

	if !fst.Result().Equal(snd.Result()) {
		return errors.New("decrypted failed for validation")
	}

	return nil
}

func DecryptShare(suite []byte, privateKey PrivateKey, cipherText []byte) ([]byte, error) {
	if bytes.Equal(suite, GetBLSSignatureSuiteG1()) {
		cipherText = cipherText[aes.BlockSize:]
		U, V, W, err := getUVWFromCipherTextSignatureSuiteG1(cipherText)
		if err != nil {
			return nil, err
		}
		if err := VerifyCipherTextSignatureSuiteG1(U, V, W); err != nil {
			return nil, err
		}
		g2 := bls.NewG2()
		g1 := bls.NewG1()

		var share *bls.PointG2 = new(bls.PointG2)
		var wi *bls.PointG1 = new(bls.PointG1)
		secret := new(big.Int).SetBytes(privateKey)
		share = G2MulScalarMont(share, U, secret)
		wi = G1MulScalarMont(wi, W, secret)

		bts := make([]byte, 0)
		bts = append(bts, g2.ToBytes(share)...)
		bts = append(bts, g1.ToBytes(wi)...)
		return bts, nil
	} else if bytes.Equal(suite, GetBLSSignatureSuiteG2()) {
		cipherText = cipherText[aes.BlockSize:]
		U, V, W, err := getUVWFromCipherTextSignatureSuiteG2(cipherText)
		if err != nil {
			return nil, err
		}
		if err := VerifyCipherTextSignatureSuiteG2(U, V, W); err != nil {
			return nil, err
		}
		g2 := bls.NewG2()
		g1 := bls.NewG1()

		var share *bls.PointG1 = new(bls.PointG1)
		var wi *bls.PointG2 = new(bls.PointG2)
		secret := new(big.Int).SetBytes(privateKey)
		share = G1MulScalarMont(share, U, secret)
		wi = G2MulScalarMont(wi, W, secret)

		bts := make([]byte, 0)
		bts = append(bts, g1.ToBytes(share)...)
		bts = append(bts, g2.ToBytes(wi)...)
		return bts, nil
	}

	return nil, fmt.Errorf("not suite")
}

func Encrypt(suite []byte, publicKey PublicKey, message []byte) ([]byte, error) {
	encryptedMessage := make([]byte, aes.BlockSize+PointG2Size+PointG1Size+Sha256SumSize+len(message)+16+HmacSize)
	_, _, _, err := encrypt(suite, encryptedMessage, publicKey, message, nil, nil, nil)
	return encryptedMessage, err
}

func EncryptAndReturnRandomness(suite []byte, publicKey PublicKey, message []byte) ([]byte, []byte, []byte, *big.Int, error) {
	encryptedMessage := make([]byte, aes.BlockSize+PointG2Size+PointG1Size+Sha256SumSize+len(message)+16+HmacSize)
	aseKey, iv, r, err := encrypt(suite, encryptedMessage, publicKey, message, nil, nil, nil)
	return encryptedMessage, aseKey, iv, r, err
}

func EncryptWithRandomness(suite []byte, publicKey PublicKey, message, aesKey, iv []byte, r *big.Int) ([]byte, error) {
	encryptedMessage := make([]byte, aes.BlockSize+PointG2Size+PointG1Size+Sha256SumSize+len(message)+16+HmacSize)
	_, _, _, err := encrypt(suite, encryptedMessage, publicKey, message, aesKey, iv, r)
	return encryptedMessage, err
}

func getUVWFromCipherTextSignatureSuiteG1(cipherText []byte) (*bls.PointG2, []byte, *bls.PointG1, error) {
	if len(cipherText) < PointG2Size+Sha256SumSize+PointG1Size {
		return nil, nil, nil, fmt.Errorf("cipherText is not valid length, length is %v, expect %v", len(cipherText), PointG2Size+Sha256SumSize+PointG1Size)
	}
	UBytes := cipherText[:PointG2Size]
	VBytes := cipherText[PointG2Size : PointG2Size+Sha256SumSize]
	WBytes := cipherText[PointG2Size+Sha256SumSize : PointG2Size+Sha256SumSize+PointG1Size]

	g2 := bls.NewG2()
	g1 := bls.NewG1()
	UPoint, err := g2.FromBytes(UBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	WPoint, err := g1.FromBytes(WBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	return UPoint, VBytes, WPoint, nil
}

func getUVWFromCipherTextSignatureSuiteG2(cipherText []byte) (*bls.PointG1, []byte, *bls.PointG2, error) {
	if len(cipherText) < PointG2Size+Sha256SumSize+PointG1Size {
		return nil, nil, nil, fmt.Errorf("cipherText is not valid length, length is %v, expect %v", len(cipherText), PointG2Size+Sha256SumSize+PointG1Size)
	}
	UBytes := cipherText[:PointG1Size]
	VBytes := cipherText[PointG1Size : PointG1Size+Sha256SumSize]
	WBytes := cipherText[PointG1Size+Sha256SumSize : PointG1Size+Sha256SumSize+PointG2Size]

	g1 := bls.NewG1()
	g2 := bls.NewG2()
	UPoint, err := g1.FromBytes(UBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	WPoint, err := g2.FromBytes(WBytes)
	if err != nil {
		return nil, nil, nil, err
	}
	return UPoint, VBytes, WPoint, nil
}

func encryptWithAes(message, aesKey, iv []byte) ([]byte, []byte, []byte) {
	var err error
	if aesKey == nil {
		aesKey, err = common.GetRandomBytes(AesKeySize)
	}
	if err != nil {
		panic("aes key gen failed")
	}
	aesCipher, err := aes.NewCipher(aesKey)
	if iv == nil {
		iv, err = common.GetRandomBytes(aes.BlockSize)
	}
	if err != nil {
		panic("aes key gen failed")
	}
	encrypter, err := cipher.NewGCM(aesCipher)
	if err != nil {
		panic("create gcm failed")
	}

	out := make([]byte, 0)
	res := encrypter.Seal(out, iv[:encrypter.NonceSize()], message, []byte{})

	hmInputs := make([]byte, len(message)+encrypter.Overhead())
	copy(hmInputs, res)
	hm := hmac.New(sha256.New, iv)
	hmBytes := hm.Sum(hmInputs)
	return aesKey, hmBytes, iv
}

func g1ToBytes(point *bls.PointG1) []byte {
	g1 := bls.NewG1()
	PksBytes := sha256.Sum256(g1.ToBytes(point))
	return PksBytes[:]
}

func g2ToBytes(point *bls.PointG2) []byte {
	g2 := bls.NewG2()
	PksBytes := sha256.Sum256(g2.ToBytes(point))
	return PksBytes[:]
}

func hashToGroupG1(point *bls.PointG1, message []byte) (*bls.PointG2, error) {
	g1Hash := g1ToBytes(point)
	g1HashFirst4 := g1Hash[:4]
	concatStr := append(g1HashFirst4, message...)
	h := sha512.Sum512(concatStr)
	messageDigest := make([]byte, 96)

	h1 := new(big.Int).SetBytes(h[:])
	md := new(big.Int).Mod(h1, modulus.big()) // less than modulus, with at most 48 bytes
	md.FillBytes(messageDigest)

	g2 := bls.NewG2()
	g2Point, err := g2.MapToCurve(messageDigest)
	if err != nil {
		return nil, err
	}
	return g2Point, nil
}

func hashToGroupG2(point *bls.PointG2, message []byte) (*bls.PointG1, error) {
	g2Hash := g2ToBytes(point)
	g2HashFirst4 := g2Hash[:4]
	concatStr := append(g2HashFirst4, message...)
	h := sha512.Sum512(concatStr)
	messageDigest := make([]byte, 48)

	h1 := new(big.Int).SetBytes(h[:48])
	md := new(big.Int).Mod(h1, modulus.big()) // less than modulus, with at most 48 bytes
	md.FillBytes(messageDigest)

	g1 := bls.NewG1()
	g1Point, err := g1.MapToCurve(messageDigest)
	if err != nil {
		return nil, err
	}
	return g1Point, nil
}

func encryptAesKey(suite []byte, publicKey PublicKey, message []byte, r *big.Int) ([]byte, *big.Int, error) {
	if bytes.Equal(suite, GetBLSSignatureSuiteG1()) {
		pk, err := bls.NewG2().FromBytes(publicKey)
		if err != nil {
			return nil, nil, err
		}

		if r == nil {
			r = zero
			for {
				r = common.GetRandomPositiveInt(modulus.big())
				if r.Cmp(zero) != 0 {
					break
				}
			}
		}

		var U = new(bls.PointG2)
		var Y = new(bls.PointG2)
		var W = new(bls.PointG1)
		var H = new(bls.PointG1)
		var V []byte = make([]byte, Sha256SumSize)
		g2 := bls.NewG2()
		U = g2.One()
		U = G2MulScalarMont(U, U, r)
		Y = G2MulScalarMont(Y, pk, r)

		// Y's hash to 256-bit sha256 sum
		rPksBytes := g2ToBytes(Y)

		// aes's key to 256-bit aes key
		AesBytes := message

		if len(AesBytes) != len(rPksBytes) || len(rPksBytes) != Sha256SumSize {
			return nil, nil, errors.New("aes bytes size not equal to pks bytes size")
		}

		for i := 0; i < len(AesBytes); i++ {
			V[i] = rPksBytes[i] ^ AesBytes[i]
		}

		g1 := bls.NewG1()
		H, err = hashToGroupG2(U, V)
		if err != nil {
			return nil, nil, err
		}
		W = G1MulScalarMont(W, H, r)

		// cipher bytes first 192 bytes U, denotes r * P
		// cipher bytes second 32 bytes V, denotes G(r * pk * P) ^ aes
		// cipher bytes third 96  bytes W, denotes r * H(U, V)
		// assumption: sum(lamda_i * sk_i) = pk
		// validation: e(W, P) = e(r * H, P) = e(r * P, H) = e(U, H)
		// recovery: V ^ G(sum(lamda_i * sk_i) * U) = G(r * pk * P) ^ aes ^ G(r * pk * P) = aes

		cipherBytes := g2.ToBytes(U)
		cipherBytes = append(cipherBytes, V...)
		cipherBytes = append(cipherBytes, g1.ToBytes(W)...)
		return cipherBytes, r, nil
	}

	if bytes.Equal(suite, GetBLSSignatureSuiteG2()) {
		pk, err := bls.NewG1().FromBytes(publicKey)
		if err != nil {
			return nil, nil, err
		}

		if r == nil {
			r = zero
			for {
				r = common.GetRandomPositiveInt(modulus.big())
				if r.Cmp(zero) != 0 {
					break
				}
			}
		}

		var U = new(bls.PointG1)
		var Y = new(bls.PointG1)
		var W = new(bls.PointG2)
		var H = new(bls.PointG2)
		var V []byte = make([]byte, Sha256SumSize)
		g1 := bls.NewG1()
		U = g1.One()
		U = G1MulScalarMont(U, U, r)
		Y = G1MulScalarMont(Y, pk, r)

		// Y's hash to 256-bit sha256 sum
		rPksBytes := g1ToBytes(Y)

		// aes's key to 256-bit aes key
		AesBytes := message

		if len(AesBytes) != len(rPksBytes) || len(rPksBytes) != Sha256SumSize {
			return nil, nil, errors.New("aes bytes size not equal to pks bytes size")
		}

		for i := 0; i < len(AesBytes); i++ {
			V[i] = rPksBytes[i] ^ AesBytes[i]
		}

		g2 := bls.NewG2()
		H, err = hashToGroupG1(U, V)
		if err != nil {
			return nil, nil, err
		}
		W = G2MulScalarMont(W, H, r)

		// cipher bytes first 192 bytes U, denotes r * P
		// cipher bytes second 32 bytes V, denotes G(r * pk * P) ^ aes
		// cipher bytes third 96  bytes W, denotes r * H(U, V)
		// assumption: sum(lamda_i * sk_i) = pk
		// validation: e(W, P) = e(r * H, P) = e(r * P, H) = e(U, H)
		// recovery: V ^ G(sum(lamda_i * sk_i) * U) = G(r * pk * P) ^ aes ^ G(r * pk * P) = aes

		cipherBytes := g1.ToBytes(U)
		cipherBytes = append(cipherBytes, V...)
		cipherBytes = append(cipherBytes, g2.ToBytes(W)...)
		return cipherBytes, r, nil
	}

	return nil, nil, fmt.Errorf("no suite")
}

func encrypt(suite []byte, cipherText, publicKey, message, aesKey, iv []byte, r *big.Int) ([]byte, []byte, *big.Int, error) {
	var hmacBytes []byte
	aesKey, hmacBytes, iv = encryptWithAes(message, aesKey, iv)
	encryptedAes, r, err := encryptAesKey(suite, publicKey, aesKey, r)
	if err != nil {
		return nil, nil, nil, err
	}

	copy(cipherText, iv)
	copy(cipherText[aes.BlockSize:], encryptedAes)
	copy(cipherText[aes.BlockSize+PointG2Size+Sha256SumSize+PointG1Size:], hmacBytes)
	return aesKey, iv, r, nil
}

func PadToLengthBytesInPlace(src []byte, length int) ([]byte, error) {
	if len(src) > length {
		return nil, fmt.Errorf("can not pad to src length %v for %v", len(src), length)
	}
	oriLen := len(src)
	if oriLen < length {
		for i := 0; i < length-oriLen; i++ {
			src = append([]byte{0}, src...)
		}
	}
	return src, nil
}

// PadToLengthBytesInPlacePKCSS7
// ref: https://stackoverflow.com/questions/13572253/what-kind-of-padding-should-aes-use
func PadToLengthBytesInPlacePKCSS7(src []byte, length int) []byte {
	oriLen := len(src)
	oriLenLeft := oriLen % length
	padded := byte(length - oriLenLeft)
	paddedBytes := make([]byte, int(padded))
	for i := range paddedBytes {
		paddedBytes[i] = padded
	}
	return append(src, paddedBytes...)
}

// RemovePadToLengthBytesInPlacePKCSS7
// 255 15 15 15 15 15 15 15 15 15 15 15 15 15 15 15  -> 255
// ref: https://stackoverflow.com/questions/13572253/what-kind-of-padding-should-aes-use
func RemovePadToLengthBytesInPlacePKCSS7(src []byte, length int) ([]byte, error) {
	for i := len(src) - 1; i >= len(src)-length; i-- {
		if i < len(src)-1 && src[i] != src[i+1] {
			return nil, fmt.Errorf("wrong padding")
		}
		if int(src[i]) == len(src)-i {
			return src[:i], nil
		}

		if int(src[i]) < len(src)-i {
			return nil, fmt.Errorf("wrong padding")
		}
	}
	return src, nil
}

// G2MulScalarMont multiplies a point by given scalar value in big.Int and assigns the result to point at first argument.
func G2MulScalarMont(c, p *bls.PointG2, e *big.Int) *bls.PointG2 {
	g := bls.NewG2()
	R0 := g.Zero()
	R1 := &bls.PointG2{}
	R1.Set(p)
	l := e.BitLen()
	for i := l - 1; i >= 0; i-- {
		if e.Bit(i) == 0 {
			g.Add(R1, R0, R1)
			g.Add(R0, R0, R0)
		} else {
			g.Add(R0, R0, R1)
			g.Add(R1, R1, R1)
		}
	}
	c.Set(R0)

	return R0
}

// G1MulScalarMont multiplies a point by given scalar value in big.Int and assigns the result to point at first argument.
func G1MulScalarMont(c, p *bls.PointG1, e *big.Int) *bls.PointG1 {
	g := bls.NewG1()
	R0 := g.Zero()
	R1 := &bls.PointG1{}
	R1.Set(p)
	l := e.BitLen()
	for i := l - 1; i >= 0; i-- {
		if e.Bit(i) == 0 {
			g.Add(R1, R0, R1)
			g.Add(R0, R0, R0)
		} else {
			g.Add(R0, R0, R1)
			g.Add(R1, R1, R1)
		}
	}
	c.Set(R0)

	return R0
}
