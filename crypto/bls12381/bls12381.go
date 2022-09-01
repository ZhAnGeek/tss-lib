//
// These functions are compatible with the “BLS12381” function defined in IETF-draft
// https://tools.ietf.org/pdf/draft-irtf-cfrg-bls-signature-04.pdf.

package bls12381

import (
	"crypto"
	"crypto/aes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"errors"
	"io"
	"math/big"
	"strconv"

	"github.com/Safulet/tss-lib-private/common"
	bls "github.com/ethereum/go-ethereum/crypto/bls12381"
)

type fe [6]uint64

// modulus = p
var modulus = fe{0xb9feffffffffaaab, 0x1eabfffeb153ffff, 0x6730d2a0f6b0f624, 0x64774b84f38512bf, 0x4b1ba7b6434bacd7, 0x1a0111ea397fe69a}

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
	PublicKeySize  = 96
	PrivateKeySize = 32
	SignatureSize  = 48
	SeedSize       = 32
	AesKeySize     = 32
	Sha256SumSize  = 32
	PointG1Size    = 96
	PointG2Size    = 192
)

var (
	zero = big.NewInt(0)
)

type PublicKey []byte

type PrivateKey []byte

func (priv PrivateKey) Public() crypto.PublicKey {
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, priv[32:])
	return PublicKey(publicKey)
}

func GenerateKey(rand io.Reader) (PublicKey, PrivateKey, error) {
	if rand == nil {
		rand = cryptorand.Reader
	}
	seed := make([]byte, SeedSize)
	if _, err := io.ReadFull(rand, seed); err != nil {
		return nil, nil, err
	}

	privateKey := NewKeyFromSeed(seed)
	publicKey := make([]byte, PublicKeySize)
	copy(publicKey, privateKey[32:])

	return publicKey, privateKey, nil
}

func NewKeyFromSeed(seed []byte) PrivateKey {
	privateKey := make([]byte, PrivateKeySize)
	newKeyFromSeed(privateKey, seed)
	return privateKey
}

func newKeyFromSeed(privateKey, seed []byte) {
	if l := len(seed); l != SeedSize {
		panic("bls12381:bad seed length:" + strconv.Itoa(l))
	}
	h := sha256.Sum256(seed)
	s := new(big.Int).SetBytes(h[:])
	// h converted as big.int
	g1 := bls.NewG1()
	A := g1.MulScalar(&bls.PointG1{}, g1.One(), s)

	publicKey := bls.NewG1().ToBytes(A)

	copy(privateKey, seed)
	copy(privateKey[32:], publicKey)

}

func Sign(privateKey PrivateKey, message []byte) []byte {
	signature := make([]byte, SignatureSize*2)
	sign(signature, privateKey, message)
	return signature
}

func sign(signature, privateKey, message []byte) {
	privateKey = PadToLengthBytesInPlace(privateKey, 32)
	if l := len(privateKey); l != PrivateKeySize {
		panic("bls12381:bad private key length" + strconv.Itoa(l))
	}
	g1 := bls.NewG1()
	h := sha512.Sum512(message)
	messageDigest := make([]byte, 48)
	copy(messageDigest, h[:48])

	h1 := new(big.Int).SetBytes(messageDigest)
	md := new(big.Int).Mod(h1, modulus.big()) // less than modulus, with at most 32 bytes

	dig, err := g1.MapToCurve(md.Bytes())
	if err != nil {
		panic("bls12381: invalid message hashing into G1")
	}
	sk := new(big.Int).SetBytes(privateKey)

	g1.MulScalar(dig, dig, sk)
	copy(signature[:SignatureSize*2], g1.ToBytes(dig))
}

func Verify(publicKey PublicKey, message, sig []byte) bool {
	pk, err := bls.NewG2().FromBytes(publicKey)
	if err != nil {
		return false
	}

	g1 := bls.NewG1()
	h := sha512.Sum512(message)
	messageDigest := make([]byte, 48)
	copy(messageDigest, h[:48])

	h1 := new(big.Int).SetBytes(messageDigest)
	md := new(big.Int).Mod(h1, modulus.big()) // less than modulus, with at most 32 bytes

	dig, _ := g1.MapToCurve(md.Bytes())
	sig = PadToLengthBytesInPlace(sig, 96)
	signature, _ := g1.FromBytes(sig)

	c1 := bls.NewPairingEngine()
	r1 := c1.AddPair(dig, pk).Result()

	c2 := bls.NewPairingEngine()
	g2 := bls.NewG2()
	p2 := g2.One()
	r2 := c2.AddPair(signature, p2).Result()

	return r1.Equal(r2)
}

func VerifyDecryptShare(share []byte, Yi *bls.PointG2, U *bls.PointG2, W *bls.PointG1) error {
	g2 := bls.NewG2()
	g1 := bls.NewG1()
	fst := bls.NewPairingEngine()
	snd := bls.NewPairingEngine()
	Ui, err := g2.FromBytes(share[:PointG2Size])
	if err != nil {
		return err
	}
	Wi, err := g1.FromBytes(share[PointG2Size:])
	if err != nil {
		return err
	}
	fst.AddPair(W, Ui)
	snd.AddPair(Wi, U)

	if !fst.Result().Equal(snd.Result()) {
		return errors.New("U verification failed, please recheck U integrity")
	}

	fst2 := bls.NewPairingEngine()
	snd2 := bls.NewPairingEngine()

	fst2.AddPair(W, Yi)
	snd2.AddPair(Wi, g2.One())

	if !fst2.Result().Equal(snd2.Result()) {
		return errors.New("Y verification failed, please recheck Y integrity")
	}

	return nil
}

func Decrypt(shares [][]byte, cipherText []byte, yi []*bls.PointG2) ([]byte, error) {
	U, V, W := getUVWFromCipherText(cipherText)
	if err := VerifyCipherText(U, V, W); err != nil {
		return nil, err
	}

	for i, share := range shares {
		if err := VerifyDecryptShare(share, yi[i], U, W); err != nil {
			return nil, err
		}
	}

	combined, err := combineShares(shares)
	if err != nil {
		return nil, err
	}

	combinedSha256 := g2ToBytes(combined)

	for i, b := range V {
		combinedSha256[i] ^= b
	}

	aesKey := combinedSha256
	encrypedMessage := cipherText[PointG2Size+PointG1Size+Sha256SumSize:]
	cipher, err := aes.NewCipher(aesKey)
	if err != nil {
		return nil, err
	}
	message := make([]byte, len(encrypedMessage))
	cipher.Decrypt(message, encrypedMessage)
	return message, nil
}

func combineShares(shares [][]byte) (*bls.PointG2, error) {
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

func VerifyCipherText(U *bls.PointG2, V []byte, W *bls.PointG1) error {
	H, err := hashToGroup(U, V)
	if err != nil {
		return err
	}
	g2 := bls.NewG2()
	fst := bls.NewPairingEngine()
	snd := bls.NewPairingEngine()
	fst.AddPair(W, g2.One())
	snd.AddPair(H, U)

	if !fst.Result().Equal(snd.Result()) {
		return errors.New("decrypted failed for validation")
	}

	return nil
}

func DecryptShare(privateKey PrivateKey, cipherText []byte) ([]byte, error) {
	U, V, W := getUVWFromCipherText(cipherText)
	if err := VerifyCipherText(U, V, W); err != nil {
		return nil, err
	}
	g2 := bls.NewG2()
	g1 := bls.NewG1()

	var share *bls.PointG2 = new(bls.PointG2)
	var wi *bls.PointG1 = new(bls.PointG1)
	secret := new(big.Int).SetBytes(privateKey)
	share = g2.MulScalar(share, U, secret)
	wi = g1.MulScalar(wi, W, secret)

	bytes := make([]byte, 0)
	bytes = append(bytes, g2.ToBytes(share)...)
	bytes = append(bytes, g1.ToBytes(wi)...)
	return bytes, nil
}

func Encrypt(publicKey PublicKey, message []byte) ([]byte, error) {
	message = PadToLengthBytesInPlace(message, aes.BlockSize)
	encryptedMessage := make([]byte, PointG2Size+PointG1Size+Sha256SumSize+len(message))
	err := encrypt(encryptedMessage, publicKey, message)
	return encryptedMessage, err
}

func getUVWFromCipherText(cipherText []byte) (*bls.PointG2, []byte, *bls.PointG1) {
	UBytes := cipherText[:PointG2Size]
	VBytes := cipherText[PointG2Size : PointG2Size+Sha256SumSize]
	WBytes := cipherText[PointG2Size+Sha256SumSize : PointG2Size+Sha256SumSize+PointG1Size]

	g2 := bls.NewG2()
	g1 := bls.NewG1()
	UPoint, err := g2.FromBytes(UBytes)
	if err != nil {
		panic(err.Error())
	}
	WPoint, err := g1.FromBytes(WBytes)
	if err != nil {
		panic(err.Error())
	}
	return UPoint, VBytes, WPoint
}

func encryptWithAes(message []byte) ([]byte, []byte) {
	aesKey, err := common.GetRandomBytes(AesKeySize)
	if err != nil {
		panic("aes key gen failed")
	}
	aesCipher, err := aes.NewCipher(aesKey)

	out := make([]byte, len(message))
	aesCipher.Encrypt(out, message)
	return aesKey, out
}

func g2ToBytes(point *bls.PointG2) []byte {
	g2 := bls.NewG2()
	PksBytes := sha256.Sum256(g2.ToBytes(point))
	return PksBytes[:]
}

func hashToGroup(point *bls.PointG2, message []byte) (*bls.PointG1, error) {
	g2Hash := g2ToBytes(point)
	g2HashFirst4 := g2Hash[:4]
	concatStr := append(g2HashFirst4, message...)
	finalHash := sha256.Sum256(concatStr)
	finalHashBytes := PadToLengthBytesInPlace(finalHash[:], 48)
	g1 := bls.NewG1()
	g1Point, err := g1.MapToCurve(finalHashBytes[:48])
	if err != nil {
		return nil, err
	}
	return g1Point, nil
}

func encryptAesKey(publicKey PublicKey, message []byte) ([]byte, error) {
	pk, err := bls.NewG2().FromBytes(publicKey)
	if err != nil {
		return nil, err
	}

	var r *big.Int = zero
	for {
		r = common.GetRandomPositiveInt(modulus.big())
		if r.Cmp(zero) != 0 {
			break
		}
	}

	var U = new(bls.PointG2)
	var Y = new(bls.PointG2)
	var W = new(bls.PointG1)
	var H = new(bls.PointG1)
	var V []byte = make([]byte, Sha256SumSize)
	g2 := bls.NewG2()
	U = g2.One()
	U = g2.MulScalar(U, U, r)
	Y = g2.MulScalar(Y, pk, r)

	// Y's hash to 256-bit sha256 sum
	rPksBytes := g2ToBytes(Y)

	// aes's key to 256-bit aes key
	AesBytes := message

	if len(AesBytes) != len(rPksBytes) || len(rPksBytes) != Sha256SumSize {
		return nil, errors.New("aes bytes size not equal to pks bytes size")
	}

	for i := 0; i < len(AesBytes); i++ {
		V[i] = rPksBytes[i] ^ AesBytes[i]
	}

	g1 := bls.NewG1()
	H, err = hashToGroup(U, V)
	if err != nil {
		return nil, err
	}
	W = g1.MulScalar(W, H, r)

	// cipher bytes first 192 bytes U, denotes r * P
	// cipher bytes second 32 bytes V, denotes G(r * pk * P) ^ aes
	// cipher bytes third 96  bytes W, denotes r * H(U, V)
	// assumption: sum(lamda_i * sk_i) = pk
	// validation: e(W, P) = e(r * H, P) = e(r * P, H) = e(U, H)
	// recovery: V ^ G(sum(lamda_i * sk_i) * U) = G(r * pk * P) ^ aes ^ G(r * pk * P) = aes

	cipherBytes := g2.ToBytes(U)
	cipherBytes = append(cipherBytes, V...)
	cipherBytes = append(cipherBytes, g1.ToBytes(W)...)
	return cipherBytes, nil
}

func encrypt(cipherText, publicKey, message []byte) error {
	aesKey, encryptedMessage := encryptWithAes(message)
	encryptedAes, err := encryptAesKey(publicKey, aesKey)
	if err != nil {
		return err
	}

	copy(cipherText, encryptedAes)
	copy(cipherText[PointG2Size+Sha256SumSize+PointG1Size:], encryptedMessage)
	return nil
}

func PadToLengthBytesInPlace(src []byte, length int) []byte {
	oriLen := len(src)
	if oriLen < length {
		for i := 0; i < length-oriLen; i++ {
			src = append([]byte{0}, src...)
		}
	}
	return src
}
