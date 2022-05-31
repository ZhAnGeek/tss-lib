// Copyright © Swingby

package ckd

import (
	"bytes"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"math/big"

	"github.com/binance-chain/tss-lib/common"
	"github.com/binance-chain/tss-lib/crypto"
	"github.com/binance-chain/tss-lib/tss"
	"github.com/btcsuite/btcd/btcec"
	"github.com/btcsuite/btcutil/base58"
	"github.com/decred/dcrd/dcrec/edwards/v2"
	"golang.org/x/crypto/ed25519"
	"golang.org/x/crypto/ripemd160"
)

type ExtendedKey struct {
	PublicKey  crypto.ECPoint
	Depth      uint8
	ChildIndex uint32
	ChainCode  []byte // 32 bytes
	ParentFP   []byte // parent fingerprint
	Version    []byte
}

// For more information about child key derivation see https://github.com/binance-chain/tss-lib/issues/104
// https://github.com/bitcoin/bips/blob/master/bip-0032.mediawiki .
// The functions below do not implement the full BIP-32 specification. As mentioned in the Jira ticket above,
// we only use non-hardened derived keys.

// For more information about child key derivation on Ed25519, see
// https://ieeexplore.ieee.org/document/7966967

const (

	// HardenedKeyStart hardened key starts.
	HardenedKeyStart = 0x80000000 // 2^31

	// max Depth
	maxDepth = 1<<8 - 1

	PubKeyBytesLenCompressed = 33

	pubKeyCompressed byte = 0x2

	serializedKeyLen = 78

	// MinSeedBytes is the minimum number of bytes allowed for a seed to
	// a master node.
	MinSeedBytes = 16 // 128 bits

	// MaxSeedBytes is the maximum number of bytes allowed for a seed to
	// a master node.
	MaxSeedBytes = 64 // 512 bits
)

// Extended public key serialization, defined in BIP32
func (k *ExtendedKey) String() string {
	// version(4) || depth(1) || parentFP (4) || childinde(4) || chaincode (32) || key(33) || checksum(4)
	var childNumBytes [4]byte
	binary.BigEndian.PutUint32(childNumBytes[:], k.ChildIndex)

	serializedBytes := make([]byte, 0, serializedKeyLen+4)
	serializedBytes = append(serializedBytes, k.Version...)
	serializedBytes = append(serializedBytes, k.Depth)
	serializedBytes = append(serializedBytes, k.ParentFP...)
	serializedBytes = append(serializedBytes, childNumBytes[:]...)
	serializedBytes = append(serializedBytes, k.ChainCode...)
	pubKeyBytes := serializeCompressed(k.PublicKey.X(), k.PublicKey.Y())
	serializedBytes = append(serializedBytes, pubKeyBytes...)

	checkSum := doubleHashB(serializedBytes)[:4]
	serializedBytes = append(serializedBytes, checkSum...)
	return base58.Encode(serializedBytes)
}

// NewExtendedKeyFromString returns a new extended key from a base58-encoded extended key
func NewExtendedKeyFromString(key string, curve elliptic.Curve) (*ExtendedKey, error) {
	// version(4) || depth(1) || parentFP (4) || childinde(4) || chaincode (32) || key(33) || checksum(4)

	decoded := base58.Decode(key)
	if len(decoded) != serializedKeyLen+4 {
		return nil, errors.New("invalid extended key")
	}

	// Split the payload and checksum up and ensure the checksum matches.
	payload := decoded[:len(decoded)-4]
	checkSum := decoded[len(decoded)-4:]
	expectedCheckSum := doubleHashB(payload)[:4]
	if !bytes.Equal(checkSum, expectedCheckSum) {
		return nil, errors.New("invalid extended key")
	}

	// Deserialize each of the payload fields.
	version := payload[:4]
	depth := payload[4:5][0]
	parentFP := payload[5:9]
	childNum := binary.BigEndian.Uint32(payload[9:13])
	chainCode := payload[13:45]
	keyData := payload[45:78]

	var pubKeyPoint crypto.ECPoint
	if c, ok := curve.(*btcec.KoblitzCurve); ok {
		// Ensure the public key parses correctly and is actually on the secp256k1 curve.
		pk, err := btcec.ParsePubKey(keyData, c)
		if err != nil {
			return nil, err
		}
		pubKey, err := crypto.NewECPoint(curve, pk.X, pk.Y)
		if err != nil {
			return nil, err
		}
		pubKeyPoint = *pubKey
	} else {
		px, py := elliptic.Unmarshal(curve, keyData)
		if px == nil {
			return nil, errors.New("unmarshal public key error")
		}
		pubKey, err := crypto.NewECPoint(curve, px, py)
		if err != nil {
			return nil, errors.New("unmarshal public key error")
		}
		pubKeyPoint = *pubKey
	}

	return &ExtendedKey{
		PublicKey:  pubKeyPoint,
		Depth:      depth,
		ChildIndex: childNum,
		ChainCode:  chainCode,
		ParentFP:   parentFP,
		Version:    version,
	}, nil
}

func doubleHashB(b []byte) []byte {
	first := sha256.Sum256(b)
	second := sha256.Sum256(first[:])
	return second[:]
}

func calcHash(buf []byte, hasher hash.Hash) []byte {
	hasher.Write(buf)
	return hasher.Sum(nil)
}

func hash160(buf []byte) []byte {
	return calcHash(calcHash(buf, sha256.New()), ripemd160.New())
}

func isOdd(a *big.Int) bool {
	return a.Bit(0) == 1
}

// PaddedAppend append src to dst, if less than size padding 0 at start
func paddedAppend(dst []byte, srcPaddedSize int, src []byte) []byte {
	return append(dst, paddedBytes(srcPaddedSize, src)...)
}

// PaddedBytes padding byte array to size length
func paddedBytes(size int, src []byte) []byte {
	offset := size - len(src)
	tmp := src
	if offset > 0 {
		tmp = make([]byte, size)
		copy(tmp[offset:], src)
	}
	return tmp
}

// SerializeCompressed serializes a public key 33-byte compressed format
func serializeCompressed(publicKeyX *big.Int, publicKeyY *big.Int) []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubKeyCompressed
	if isOdd(publicKeyY) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(b, 32, publicKeyX.Bytes())
}

func DeriveChildKeyFromHierarchy(indicesHierarchy []uint32, pk *ExtendedKey, mod *big.Int, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	var k = pk
	var err error
	var childKey *ExtendedKey
	mod_ := common.ModInt(mod)
	ilNum := big.NewInt(0)
	for index := range indicesHierarchy {
		ilNumOld := ilNum
		ilNum, childKey, err = DeriveChildKey(indicesHierarchy[index], k, curve)
		if err != nil {
			return nil, nil, err
		}
		k = childKey
		ilNum = mod_.Add(ilNum, ilNumOld)
	}
	return ilNum, k, nil
}

// DeriveChildKey Derive a child key from the given parent key. The function returns "IL" ("I left"), per BIP-32 spec. It also
// returns the derived child key.
func DeriveChildKey(index uint32, pk *ExtendedKey, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	if index >= HardenedKeyStart {
		return nil, nil, errors.New("the index must be non-hardened")
	}
	if pk.Depth == maxDepth {
		return nil, nil, errors.New("cannot derive key beyond max depth")
	}

	cname, ok := tss.GetCurveName(curve)
	if !ok {
		return nil, nil, errors.New("get curve name failed")
	}

	pkPublicKeyBytes := serializeCompressed(pk.PublicKey.X(), pk.PublicKey.Y())

	data := make([]byte, 37)
	copy(data, pkPublicKeyBytes)
	binary.BigEndian.PutUint32(data[33:], index)
	if cname == tss.Ed25519 {
		data = append([]byte{2}, data...)
	}

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, pk.ChainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:32]
	childChainCode := ilr[32:]
	if cname == tss.Ed25519 {
		data[0] = byte(3)
		hmac512 := hmac.New(sha512.New, pk.ChainCode)
		hmac512.Write(data)
		ci := hmac512.Sum(nil)
		childChainCode = ci[32:]
	}
	ilNum := new(big.Int).SetBytes(il)
	ilNum = new(big.Int).Mod(ilNum, curve.Params().N)

	if ilNum.Cmp(curve.Params().N) >= 0 || ilNum.Sign() == 0 {
		// falling outside the valid range for curve private keys
		err := errors.New("invalid derived key")
		common.Logger.Error("error deriving child key")
		return nil, nil, err
	}

	deltaG := crypto.ScalarBaseMult(curve, ilNum)
	if deltaG.X().Sign() == 0 || deltaG.Y().Sign() == 0 {
		err := errors.New("invalid child")
		common.Logger.Error("error invalid child")
		return nil, nil, err
	}
	if cname == tss.Ed25519 {
		deltaG = deltaG.EightInvEight()
	}

	childCryptoPk, err := pk.PublicKey.Add(deltaG)
	if err != nil {
		common.Logger.Error("error adding delta G to parent key")
		return nil, nil, err
	}
	if cname == tss.Ed25519 {
		childCryptoPk = childCryptoPk.EightInvEight()
	}

	childPk := &ExtendedKey{
		PublicKey:  *childCryptoPk,
		Depth:      pk.Depth + 1,
		ChildIndex: index,
		ChainCode:  childChainCode,
		ParentFP:   hash160(pkPublicKeyBytes)[:4],
		Version:    pk.Version,
	}
	return ilNum, childPk, nil
}

func DeriveChildPubKeyOfEddsa(index uint32, pk *ExtendedKey) (*big.Int, *ExtendedKey, error) {
	if index >= HardenedKeyStart {
		return nil, nil, errors.New("the index must be non-hardened")
	}
	if pk.Depth == maxDepth {
		return nil, nil, errors.New("cannot derive key beyond max depth")
	}
	curve := edwards.Edwards()

	cryptoPk, err := crypto.NewECPoint(curve, pk.PublicKey.X(), pk.PublicKey.Y())
	if err != nil {
		common.Logger.Error("error getting pubkey from extendedkey")
		return nil, nil, err
	}

	pubKeyBytes := edwards.PublicKey{
		Curve: edwards.Edwards(),
		X:     pk.PublicKey.X(),
		Y:     pk.PublicKey.Y(),
	}.Serialize()

	data := make([]byte, 37)
	data[0] = 0x2
	copy(data[1:33], pubKeyBytes)
	binary.LittleEndian.PutUint32(data[33:], index)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, pk.ChainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)

	il28 := new(big.Int).SetBytes(reverseBytes(ilr[:28])) // little endian to big endian
	ilNum := new(big.Int).Mul(il28, big.NewInt(8))

	modInt := common.ModInt(curve.Params().N)
	ilNum = modInt.Add(big.NewInt(0), ilNum)

	deltaG := crypto.ScalarBaseMult(curve, ilNum)
	if deltaG.X().Sign() == 0 || deltaG.Y().Sign() == 0 {
		err = errors.New("invalid child")
		common.Logger.Error("error invalid child")
		return nil, nil, err
	}
	childCryptoPk, err := cryptoPk.Add(deltaG)
	if err != nil {
		common.Logger.Error("error adding delta G to parent key")
		return nil, nil, err
	}

	// derive child chain code
	data[0] = 0x3
	hmac512 = hmac.New(sha512.New, pk.ChainCode)
	hmac512.Write(data)
	ilr = hmac512.Sum(nil)
	childChainCode := ilr[32:]

	childPk := &ExtendedKey{
		PublicKey:  *childCryptoPk,
		Depth:      pk.Depth + 1,
		ChildIndex: index,
		ChainCode:  childChainCode,
		Version:    pk.Version,
	}
	return ilNum, childPk, nil
}

func DeriveChildPrivateKeyOfEddsa(index uint32, chainCode []byte, privKey *edwards.PrivateKey) ([]byte, *ecdsa.PublicKey, []byte, error) {
	if index >= HardenedKeyStart {
		return nil, nil, nil, errors.New("the index must be non-hardened")
	}
	curve := edwards.Edwards()

	// extended private key of 32+32 bytes
	kl := privKey.Serialize()[:]
	kr := privKey.PubKey().Serialize()[:]

	// serialize as little-endian 32-byte string
	pkPublicKeyBytes := make([]byte, 1, PubKeyBytesLenCompressed)
	pkPublicKeyBytes[0] = 0x2
	pubKeyBytes := edwards.PublicKey{
		Curve: curve,
		X:     privKey.PubKey().X,
		Y:     privKey.PubKey().Y,
	}.Serialize()
	pkPublicKeyBytes = paddedAppend(pkPublicKeyBytes, 32, pubKeyBytes)

	data := make([]byte, 37)
	copy(data, pkPublicKeyBytes)
	binary.LittleEndian.PutUint32(data[33:], index)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, chainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)

	// left
	childKl := add28Mul8(kl, ilr[:32])
	delta := new(big.Int).SetBytes(reverseBytes(childKl[:32]))

	modInt := common.ModInt(curve.Params().N)
	delta = modInt.Add(big.NewInt(0), delta)

	cPrivKey, cPubKey, err := edwards.PrivKeyFromScalar(delta.Bytes())
	if err != nil {
		fmt.Printf("err:%+v", err)
		return nil, nil, nil, err
	}
	fmt.Printf("cPrivKey:     %x\n", cPrivKey.Serialize())
	fmt.Printf("cPubKey:      %x\n", cPubKey.Serialize())
	sig, _ := cPrivKey.Sign([]byte("message"))
	verified := ed25519.Verify(cPubKey.Serialize(), []byte("message"), sig.Serialize())
	fmt.Printf("verified:%+v\n", verified)

	// right
	childKr := add256Bits(kr, ilr[32:])

	// derive child chain code
	data[0] = 0x3
	hmac512 = hmac.New(sha512.New, chainCode)
	hmac512.Write(data)
	ilr = hmac512.Sum(nil)
	childChainCode := ilr[32:]

	// child public key
	deltaG := crypto.ScalarBaseMult(curve, delta)

	extPrivKey := make([]byte, 64)
	copy(extPrivKey[:32], childKl[:])
	copy(extPrivKey[32:], childKr[:])
	return extPrivKey, deltaG.ToECDSAPubKey(), childChainCode, nil
}

func AddPrivKeyScalar(privKeyScalar, delta *big.Int, curve elliptic.Curve) *big.Int {
	if delta == nil {
		return privKeyScalar
	}
	newPrivKeyScalar := big.NewInt(0).Add(privKeyScalar, delta)
	newPrivKeyScalar = new(big.Int).Mod(newPrivKeyScalar, curve.Params().N)

	return newPrivKeyScalar
}

func GenerateSeed(length uint8) ([]byte, error) {
	// Per [BIP32], the seed must be in range [MinSeedBytes, MaxSeedBytes].
	if length < MinSeedBytes || length > MaxSeedBytes {
		return nil, errors.New("invalid seed length")
	}

	buf := make([]byte, length)
	_, err := rand.Read(buf)
	if err != nil {
		return nil, err
	}

	return buf, nil
}

func add28Mul8(kl, zl []byte) *[32]byte {
	var carry uint16 = 0
	var out [32]byte

	for i := 0; i < 28; i++ {
		r := uint16(kl[i]) + uint16(zl[i])<<3 + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}

	for i := 28; i < 32; i++ {
		r := uint16(kl[i]) + carry
		out[i] = byte(r & 0xff)
		carry = r >> 8
	}

	return &out
}

// reverseBytes switch between big endian & little endian
func reverseBytes(input []byte) []byte {
	out := make([]byte, len(input))
	l := len(input)
	for i := range input {
		out[l-i-1] = input[i]
	}
	return out
}

// add256Bits add bytes of little endian
func add256Bits(kr, zr []byte) *[32]byte {
	var carry uint16 = 0
	var out [32]byte

	for i := 0; i < 32; i++ {
		r := uint16(kr[i]) + uint16(zr[i]) + carry
		out[i] = byte(r)
		carry = r >> 8
	}

	return &out
}
