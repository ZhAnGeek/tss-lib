package hash2curve

import (
	"crypto"
	_ "crypto/sha256" // To link the sha256 module
	_ "crypto/sha512" // To link the sha512 module
	"fmt"

	C "github.com/Safulet/tss-lib-private/v2/crypto/hash2curve/curve"
	M "github.com/Safulet/tss-lib-private/v2/crypto/hash2curve/mapping"
)

// SuiteID is the identifier of supported hash to curve suites.
type SuiteID string

const (
	P256_XMDSHA256_SSWU_RO_         SuiteID = "P256_XMD:SHA-256_SSWU_RO_"
	Curve25519_XMDSHA512_ELL2_RO_   SuiteID = "curve25519_XMD:SHA-512_ELL2_RO_"
	Edwards25519_XMDSHA512_ELL2_RO_ SuiteID = "edwards25519_XMD:SHA-512_ELL2_RO_"
	EdBLS12377_XMDSHA512_ELL2_RO_   SuiteID = "edbls12377_XMD:SHA-512_ELL2_RO_"
	Secp256k1_XMDSHA256_SSWU_RO_    SuiteID = "secp256k1_XMD:SHA-256_SSWU_RO_"
	BLS12381G1_XMDSHA256_SSWU_RO_   SuiteID = "BLS12381G1_XMD:SHA-256_SSWU_RO_"
	BLS12381G2_XMDSHA256_SSWU_RO_   SuiteID = "BLS12381G2_XMD:SHA-256_SSWU_RO_"
)

// Get returns a HashToPoint based on the SuiteID, otherwise returns an error
// if the SuiteID is not supported or invalid.
func (id SuiteID) Get(dst []byte) (HashToPoint, error) {
	if s, ok := supportedSuitesID[id]; ok {
		E := s.E.Get()
		m := s.Map.Get(E)
		exp, err := s.Exp.Get(dst, s.K)
		if err != nil {
			return nil, err
		}
		e := &encoding{
			E: E,
			Field: &fieldEncoding{
				F:   E.Field(),
				Exp: exp,
				L:   s.L,
			},
			Mapping: m,
		}
		if s.RO {
			return &hashToCurve{e}, nil
		}
		return &encodeToCurve{e}, nil
	}
	return nil, fmt.Errorf("Suite: %v not supported", id)
}

type params struct {
	ID  SuiteID
	E   C.ID
	K   uint
	Exp ExpanderDesc
	Map M.MapDescriptor
	L   uint
	RO  bool
}

type MapperParams struct{ *params }

func (id SuiteID) register(s *params) {
	s.ID = id
	supportedSuitesID[id] = *s
}

var supportedSuitesID map[SuiteID]params

func init() {
	supportedSuitesID = make(map[SuiteID]params)
	sha256 := ExpanderDesc{XMD, uint(crypto.SHA256)}
	sha512 := ExpanderDesc{XMD, uint(crypto.SHA512)}

	P256_XMDSHA256_SSWU_RO_.register(&params{E: C.P256, K: 128, Exp: sha256, Map: M.MapDescriptor{ID: M.SSWU, Z: -10}, L: 48, RO: true})
	Curve25519_XMDSHA512_ELL2_RO_.register(&params{E: C.Curve25519, K: 128, Exp: sha512, Map: M.MapDescriptor{ID: M.ELL2, Z: 2}, L: 48, RO: true})
	Edwards25519_XMDSHA512_ELL2_RO_.register(&params{E: C.Edwards25519, K: 128, Exp: sha512, Map: M.MapDescriptor{ID: M.ELL2, Z: 2}, L: 48, RO: true})
	EdBLS12377_XMDSHA512_ELL2_RO_.register(&params{E: C.EdBLS12377, K: 128, Exp: sha512, Map: M.MapDescriptor{ID: M.ELL2, Z: 2}, L: 48, RO: true})
	Secp256k1_XMDSHA256_SSWU_RO_.register(&params{E: C.SECP256K1, K: 128, Exp: sha256, Map: M.MapDescriptor{ID: M.SSWU, Z: -11, Iso: C.GetSECP256K1Isogeny}, L: 48, RO: true})
	BLS12381G1_XMDSHA256_SSWU_RO_.register(&params{E: C.BLS12381G1, K: 128, Exp: sha256, Map: M.MapDescriptor{ID: M.SSWU, Z: 11, Iso: C.GetBLS12381G1Isogeny}, L: 64, RO: true})
	BLS12381G2_XMDSHA256_SSWU_RO_.register(&params{E: C.BLS12381G2, K: 128, Exp: sha256, Map: M.MapDescriptor{ID: M.SSWU, Z: []interface{}{-2, -1}, Iso: C.GetBLS12381G2Isogeny}, L: 64, RO: true})
}

func GetSuiteByID(id SuiteID) (*MapperParams, error) {
	s, ok := supportedSuitesID[id]
	if ok {
		return &MapperParams{params: &s}, nil
	} else {
		return nil, fmt.Errorf("Suite: %v not supported", id)
	}
}
