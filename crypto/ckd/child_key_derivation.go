// Copyright © Swingby

package ckd

import (
	"bytes"
	"context"
	"crypto/elliptic"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/binary"
	"errors"
	"hash"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/crypto/edwards25519"
	"github.com/Safulet/tss-lib-private/v2/crypto/secp256k1"
	"github.com/Safulet/tss-lib-private/v2/log"
	"github.com/Safulet/tss-lib-private/v2/tss"

	"github.com/btcsuite/btcd/btcec/v2"
	"github.com/btcsuite/btcutil/base58"
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

// For more information about child key derivation see https://github.com/Safulet/tss-lib-private/issues/104
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
	pubKeyBytes := SerializeCompressed(k.PublicKey.X(), k.PublicKey.Y())
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
	if _, ok := curve.(*secp256k1.Secp256k1Curve); ok {
		// Ensure the public key parses correctly and is actually on the secp256k1 curve.
		pk, err := btcec.ParsePubKey(keyData)
		if err != nil {
			return nil, err
		}
		pubKey, err := crypto.NewECPoint(curve, pk.X(), pk.ToECDSA().Y)
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
func SerializeCompressed(publicKeyX *big.Int, publicKeyY *big.Int) []byte {
	b := make([]byte, 0, PubKeyBytesLenCompressed)
	format := pubKeyCompressed
	if isOdd(publicKeyY) {
		format |= 0x1
	}
	b = append(b, format)
	return paddedAppend(b, 32, publicKeyX.Bytes())
}

func DeriveChildKeyFromHierarchyForSchnorr(ctx context.Context, indicesHierarchy []uint32, pk *ExtendedKey, mod *big.Int, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	ilNum, extKey, err := DeriveChildKeyFromHierarchy(ctx, indicesHierarchy, pk, mod, curve)
	if err != nil {
		return nil, nil, err
	}
	if extKey.PublicKey.Y().Bit(0) == 1 {
		cPk := extKey.PublicKey.Neg()
		extKey.PublicKey = *cPk
	}
	return ilNum, extKey, err
}

func DeriveChildKeyFromHierarchy(ctx context.Context, indicesHierarchy []uint32, pk *ExtendedKey, mod *big.Int, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	var k = pk
	var err error
	var childKey *ExtendedKey
	mod_ := common.ModInt(mod)
	ilNum := big.NewInt(0)
	var deriveFunc func(context.Context, uint32, *ExtendedKey, elliptic.Curve) (*big.Int, *ExtendedKey, error)
	cname, ok := tss.GetCurveName(curve)
	if !ok {
		return nil, nil, errors.New("get curve name failed")
	}
	if cname == tss.Ed25519 {
		deriveFunc = DeriveChildKeyOfEddsa
	} else {
		deriveFunc = DeriveChildKeyOfEcdsa
	}

	for index := range indicesHierarchy {
		ilNumOld := ilNum
		ilNum, childKey, err = deriveFunc(ctx, indicesHierarchy[index], k, curve)
		if err != nil {
			return nil, nil, err
		}
		k = childKey
		ilNum = mod_.Add(ilNum, ilNumOld)
	}
	return ilNum, k, nil
}

// DeriveChildKeyOfEcdsa Derive a child key from the given parent key. The function returns "IL" ("I left"), per BIP-32 spec. It also
// returns the derived child key.
func DeriveChildKeyOfEcdsa(ctx context.Context, index uint32, pk *ExtendedKey, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	if index >= HardenedKeyStart {
		return nil, nil, errors.New("the index must be non-hardened")
	}
	if pk.Depth >= maxDepth {
		return nil, nil, errors.New("cannot derive key beyond max depth")
	}

	pkPublicKeyBytes := SerializeCompressed(pk.PublicKey.X(), pk.PublicKey.Y())

	data := make([]byte, 37)
	copy(data, pkPublicKeyBytes)
	binary.BigEndian.PutUint32(data[33:], index)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, pk.ChainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)
	il := ilr[:32]
	childChainCode := ilr[32:]
	ilNum := new(big.Int).SetBytes(il)

	// Pallas order 0x40000000000000000000000000000000224698fc0994a8dd8c46eb2100000001
	// where the 1st byte 0100
	// set to zero the first two bits to ensure ilNum falls in range
	if tss.SameCurve(curve, tss.Pallas()) {
		ilNum = new(big.Int).SetBit(ilNum, 255, 0)
		ilNum = new(big.Int).SetBit(ilNum, 254, 0)
	}

	// refering to https://www.zkdocs.com/docs/zkdocs/protocol-primitives/random-sampling/#rejection-sampling
	if tss.SameCurve(curve, tss.StarkCurve()) {
		ilNum = common.RejectionSampleFixedBitLen(tss.StarkCurve().Params().N, ilNum)
	}

	if ilNum.Cmp(curve.Params().N) >= 0 || ilNum.Sign() == 0 {
		// falling outside the valid range for curve private keys
		err := errors.New("invalid derived key")
		log.Error(ctx, "error deriving child key")
		return nil, nil, err
	}

	deltaG := crypto.ScalarBaseMult(curve, ilNum)
	if deltaG.X().Sign() == 0 || deltaG.Y().Sign() == 0 {
		err := errors.New("invalid child")
		log.Error(ctx, "error invalid child")
		return nil, nil, err
	}

	childCryptoPk, err := pk.PublicKey.Add(deltaG)
	if err != nil {
		log.Error(ctx, "error adding delta G to parent key")
		return nil, nil, err
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

func DeriveChildKeyOfEddsa(ctx context.Context, index uint32, pk *ExtendedKey, curve elliptic.Curve) (*big.Int, *ExtendedKey, error) {
	if index >= HardenedKeyStart {
		return nil, nil, errors.New("the index must be non-hardened")
	}
	if pk.Depth >= maxDepth {
		return nil, nil, errors.New("cannot derive key beyond max depth")
	}

	cryptoPk, err := crypto.NewECPoint(curve, pk.PublicKey.X(), pk.PublicKey.Y())
	if err != nil {
		log.Error(ctx, "error getting pubkey from extendedkey")
		return nil, nil, err
	}

	pubKeyBytes := edwards25519.EcPointToEncodedBytes(pk.PublicKey.X(), pk.PublicKey.Y())[:]

	data := make([]byte, 37)
	data[0] = 0x2
	copy(data[1:33], pubKeyBytes)
	binary.LittleEndian.PutUint32(data[33:], index)

	// I = HMAC-SHA512(Key = chainCode, Data=data)
	hmac512 := hmac.New(sha512.New, pk.ChainCode)
	hmac512.Write(data)
	ilr := hmac512.Sum(nil)

	il28 := new(big.Int).SetBytes(common.ReverseBytes(ilr[:28])) // little endian to big endian
	ilNum := new(big.Int).Mul(il28, big.NewInt(8))

	deltaG := crypto.ScalarBaseMult(curve, ilNum)

	if deltaG.X().Sign() == 0 || deltaG.Y().Sign() == 0 || ilNum.Cmp(curve.Params().N) >= 0 {
		err = errors.New("invalid child")
		log.Error(ctx, "error invalid child")
		return nil, nil, err
	}
	childCryptoPk, err := cryptoPk.Add(deltaG)
	if err != nil {
		log.Error(ctx, "error adding delta G to parent key")
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

// DeriveTweakedKey Derive a child key from the given parent key.
// returns tweakDelta
func DeriveTweakedKey(pk *crypto.ECPoint, keyDerivationDelta *big.Int, inputs []byte) (*big.Int, *crypto.ECPoint, error) {
	if pk == nil || !pk.IsOnCurve() {
		return nil, nil, errors.New("invalid public key")
	}
	ec := pk.Curve()
	if keyDerivationDelta.Cmp(common.Zero) == -1 {
		return nil, nil, errors.New("child key derivation delta should not less than zero")
	}
	if keyDerivationDelta.Cmp(ec.Params().N) != -1 {
		return nil, nil, errors.New("child key derivation delta should not be greater than curve order")
	}

	cDelta := crypto.ScalarBaseMult(ec, keyDerivationDelta)
	cPK, err := pk.Add(cDelta)
	if err != nil {
		return nil, nil, err
	}
	if cPK.Y().Bit(0) == 1 {
		cPK = cPK.Neg()
	}

	bzs := cPK.X().Bytes()
	bzs = append(bzs, inputs...)
	tBz := common.TaggedHash256([]byte("TapTweak"), bzs)
	t := new(big.Int).SetBytes(tBz)
	if t.Cmp(ec.Params().N) != -1 {
		return nil, nil, errors.New("invalid tweak")
	}
	tDelta := crypto.ScalarBaseMult(ec, t)
	dPK, err := cPK.Add(tDelta)
	if err != nil {
		return nil, nil, err
	}
	return t, dPK, nil
}

func TweakedPublickKeyFromRootKey(rootPK *crypto.ECPoint, childDelta *big.Int, tweakDelta *big.Int) (*crypto.ECPoint, error) {
	if rootPK == nil || !rootPK.IsOnCurve() {
		return nil, errors.New("invalid public key")
	}
	ec := rootPK.Curve()
	if childDelta.Cmp(common.Zero) == -1 {
		return nil, errors.New("child key derivation delta should not less than zero")
	}
	if childDelta.Cmp(ec.Params().N) != -1 {
		return nil, errors.New("child key derivation delta should not be greater than curve order")
	}
	if tweakDelta.Cmp(common.Zero) == -1 {
		return nil, errors.New("tweak key delta should not less than zero")
	}
	if tweakDelta.Cmp(ec.Params().N) != -1 {
		return nil, errors.New("tweak key delta should not be greater than curve order")
	}

	cDelta := crypto.ScalarBaseMult(ec, childDelta)
	cPK, err := rootPK.Add(cDelta)
	if err != nil {
		return nil, err
	}
	if cPK.Y().Bit(0) == 1 {
		cPK = cPK.Neg()
	}
	tDelta := crypto.ScalarBaseMult(ec, tweakDelta)
	dPK, err := cPK.Add(tDelta)
	if err != nil {
		return nil, err
	}
	return dPK, nil
}
