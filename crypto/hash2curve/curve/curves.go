package curve

import (
	"math/big"

	GF "github.com/Safulet/tss-lib-private/v2/crypto/hash2curve/field"
	C "github.com/armfazh/tozan-ecc/curve"
)

type ID string

const (
	P256             ID = "P256"
	Curve25519       ID = "Curve25519"
	Edwards25519     ID = "Edwards25519"
	EdBLS12377       ID = "EdBls12377"
	SECP256K1        ID = "SECP256K1"
	SECP256K1_3ISO   ID = "SECP256K1_3ISO"
	BLS12381G1       ID = "BLS12381G1"
	BLS12381G1_11ISO ID = "BLS12381G1_11ISO"
	BLS12381G2       ID = "BLS12381G2"
	BLS12381G2_3ISO  ID = "BLS12381G2_3ISO"
)

// Get returns a specific instance of an elliptic curve.
func (id ID) Get() C.EllCurve {
	switch id {
	case P256:
		f := GF.P256.Get()
		return C.Weierstrass.New(string(id), f,
			f.Elt("-3"),
			f.Elt("0x5ac635d8aa3a93e7b3ebbd55769886bc651d06b0cc53b0f63bce3c3e27d2604b"),
			str2bigInt("0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551"),
			big.NewInt(1))
	case SECP256K1:
		f := GF.P256K1.Get()
		return C.Weierstrass.New(string(id), f,
			f.Zero(),
			f.Elt("7"),
			str2bigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
			big.NewInt(1))
	case SECP256K1_3ISO:
		f := GF.P256K1.Get()
		return C.Weierstrass.New(string(id), f,
			f.Elt("0x3f8731abdd661adca08a5558f0f5d272e953d363cb6f0e5d405447c01a444533"),
			f.Elt("1771"),
			str2bigInt("0xfffffffffffffffffffffffffffffffebaaedce6af48a03bbfd25e8cd0364141"),
			big.NewInt(1))
	case Curve25519:
		f := GF.P25519.Get()
		return C.Montgomery.New(string(id), f,
			f.Elt("486662"),
			f.One(),
			str2bigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
			big.NewInt(8))
	case Edwards25519:
		f := GF.P25519.Get()
		return C.TwistedEdwards.New(string(id), f,
			f.Elt("-1"),
			f.Elt("0x52036cee2b6ffe738cc740797779e89800700a4d4141d8ab75eb4dca135978a3"),
			str2bigInt("0x1000000000000000000000000000000014def9dea2f79cd65812631a5cf5d3ed"),
			big.NewInt(8))
	case EdBLS12377:
		f := GF.EDBLS12377.Get()
		return C.TwistedEdwards.New(string(id), f,
			f.Elt("-1"),
			f.Elt("0xbcd"),
			str2bigInt("0x4aad957a68b2955982d1347970dec005293a3afc43c8afeb95aee9ac33fd9ff"),
			big.NewInt(4))
	case BLS12381G1:
		f := GF.BLS12381G1.Get()
		return C.Weierstrass.New(string(id), f,
			f.Zero(),
			f.Elt(4),
			str2bigInt("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"),
			str2bigInt("0xd201000000010001"))
	case BLS12381G1_11ISO:
		f := GF.BLS12381G1.Get()
		return C.Weierstrass.New(string(id), f,
			f.Elt("0x144698a3b8e9433d693a02c96d4982b0ea985383ee66a8d8e8981aefd881ac98936f8da0e0f97f5cf428082d584c1d"),
			f.Elt("0x12e2908d11688030018b12e8753eee3b2016c1f0f24f4070a0b9c14fcef35ef55a23215a316ceaa5d1cc48e98e172be0"),
			str2bigInt("0x73eda753299d7d483339d80809a1d80553bda402fffe5bfeffffffff00000001"),
			str2bigInt("0xd201000000010001"))
	case BLS12381G2:
		f := GF.BLS12381G2.Get()
		return C.Weierstrass.New(string(id), f,
			f.Zero(),
			f.Elt([]interface{}{4, 4}),
			str2bigInt("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"),
			str2bigInt("0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551"))
	case BLS12381G2_3ISO:
		f := GF.BLS12381G2.Get()
		return C.Weierstrass.New(string(id), f,
			f.Elt([]interface{}{0, 240}),
			f.Elt([]interface{}{1012, 1012}),
			str2bigInt("0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab"),
			str2bigInt("0xbc69f08f2ee75b3584c6a0ea91b352888e2a8e9145ad7689986ff031508ffe1329c2f178731db956d82bf015d1212b02ec0ec69d7477c1ae954cbc06689f6a359894c0adebbf6b4e8020005aaa95551"))
	default:
		panic("curve not supported")
	}
}

func str2bigInt(s string) *big.Int {
	n := new(big.Int)
	if _, ok := n.SetString(s, 0); !ok {
		panic("error setting the number")
	}
	return n
}
