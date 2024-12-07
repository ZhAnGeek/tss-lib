package mapping

import (
	"fmt"

	"github.com/Safulet/tss-lib-private/v2/crypto/hash2curve/curve"
	C "github.com/armfazh/tozan-ecc/curve"
	GF "github.com/armfazh/tozan-ecc/field"
)

type teEll2 struct {
	E C.T
	C.RationalMap
	MapToCurve
}

func (m teEll2) String() string { return fmt.Sprintf("Edwards Elligator2 for E: %v", m.E) }

func newTEEll2(e C.T) MapToCurve {
	var rat C.RationalMap
	var ell2Map MapToCurve
	switch curve.ID(e.Name) {
	case curve.Edwards25519:
		rat = curve.FromTe2Mt25519()
		ell2Map = newMTEll2(rat.Codomain().(C.M))
	case curve.EdBLS12377:
		rat = e.ToWeierstrassC()
		ell2Map = newWCEll2s(rat.Codomain().(C.WC), e)
	default:
		rat = e.ToWeierstrassC()
		ell2Map = newWCEll2(rat.Codomain().(C.WC))
	}
	return &teEll2{e, rat, ell2Map}
}

func (m *teEll2) Map(u GF.Elt) C.Point { return m.Pull(m.MapToCurve.Map(u)) }
