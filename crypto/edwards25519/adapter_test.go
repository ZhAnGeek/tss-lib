package edwards25519

import (
	"filippo.io/edwards25519"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestNewPoint(t *testing.T) {
	ec := Edwards25519()
	P, err := NewPoint(ec.Params().Gx, ec.Params().Gy)
	assert.NoError(t, err)
	x, y := ToAffine(P)
	assert.Equal(t, 0, x.Cmp(ec.Params().Gx))
	assert.Equal(t, 0, y.Cmp(ec.Params().Gy))
}

func TestIdentity(t *testing.T) {
	ec := Edwards25519()
	I, err := NewPoint(nil, nil)
	assert.NoError(t, err)
	x, y := ToAffine(I)
	assert.Equal(t, 0, x.Cmp(big.NewInt(0)))
	assert.Equal(t, 0, y.Cmp(big.NewInt(1)))

	I2, err := NewPoint(big.NewInt(0), big.NewInt(1))
	assert.NoError(t, err)
	assert.Equal(t, 1, I.Equal(I2))

	G, err := NewPoint(ec.Params().Gx, ec.Params().Gy)
	assert.NoError(t, err)
	x2, y2 := ec.Add(big.NewInt(0), big.NewInt(1), ec.Params().Gx, ec.Params().Gy)
	G2 := edwards25519.NewIdentityPoint()
	G2.Add(G, I)
	x22, y22 := ToAffine(G2)
	assert.Equal(t, 0, x2.Cmp(x22))
	assert.Equal(t, 0, y2.Cmp(y22))
}

func TestDouble(t *testing.T) {
	ec := Edwards25519()
	I, err := NewPoint(nil, nil)
	assert.NoError(t, err)

	I2 := edwards25519.NewIdentityPoint().Add(I, I)
	x2, y2 := ToAffine(I2)

	x, y := ec.Double(big.NewInt(0), big.NewInt(1))
	assert.Equal(t, 0, x.Cmp(x2))
	assert.Equal(t, 0, y.Cmp(y2))

	G, err := NewPoint(ec.Params().Gx, ec.Params().Gy)
	assert.NoError(t, err)

	G2 := edwards25519.NewIdentityPoint().Add(G, G)
	x2, y2 = ToAffine(G2)

	x, y = ec.Double(ec.Params().Gx, ec.Params().Gy)
	assert.Equal(t, 0, x.Cmp(x2))
	assert.Equal(t, 0, y.Cmp(y2))

	x, y = ec.ScalarBaseMult(big.NewInt(2).Bytes())
	assert.Equal(t, 0, x.Cmp(x2))
	assert.Equal(t, 0, y.Cmp(y2))

	x, y = ec.ScalarMult(ec.Params().Gx, ec.Params().Gy, big.NewInt(2).Bytes())
	assert.Equal(t, 0, x.Cmp(x2))
	assert.Equal(t, 0, y.Cmp(y2))

}
