package field

import F "github.com/armfazh/tozan-ecc/field"

// ID is an identifier of a well-known finite field.
type ID string

const (
	P25519     ID = "2^255-19"
	P256       ID = "2^256-2^224+2^192+2^96-1"
	P256K1     ID = "2^256-2^32-977"
	BLS12381G1 ID = "BLS12381G1"
	BLS12381G2 ID = "BLS12381G2"
	EDBLS12377 ID = "EDBLS12377"
)

// Get returns an implementation of a field corresponding to the identifier.
func (id ID) Get() F.Field {
	switch id {
	case P25519:
		return F.NewFp(string(id), "57896044618658097711785492504343953926634992332820282019728792003956564819949")
	case P256:
		return F.NewFp(string(id), "115792089210356248762697446949407573530086143415290314195533631308867097853951")
	case P256K1:
		return F.NewFp(string(id), "115792089237316195423570985008687907853269984665640564039457584007908834671663")
	case BLS12381G1:
		return F.NewFp(string(id), "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab")
	case BLS12381G2:
		return F.NewFp2(string(id), "0x1a0111ea397fe69a4b1ba7b6434bacd764774b84f38512bf6730d2a0f6b0f6241eabfffeb153ffffb9feffffffffaaab")
	case EDBLS12377:
		return F.NewFp(string(id), "8444461749428370424248824938781546531375899335154063827935233455917409239041")
	default:
		panic("field not supported")
	}
}
