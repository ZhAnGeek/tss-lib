package common

import (
	"context"
	"encoding/hex"
	"github.com/stretchr/testify/assert"
	"math/big"
	"testing"
)

func TestHashFunc(t *testing.T) {
	ctx := context.Background()
	h1Input := [][]byte{[]byte("1111111111111111"), []byte("222222222222")}
	h1 := SHA512_256(ctx, h1Input...)
	expectedH1, _ := hex.DecodeString("d6f1c29e1ea369f70eecdde55143b8ad9d95aced0d015dcce49dfe598f53edfc")
	assert.Equal(t, h1, expectedH1, "hash should be same")

	tag := []byte("qwertyuiopasdfghjklzxcvbnm")
	h1Tag := SHA512_256_TAGGED(ctx, tag, h1Input...)
	expectedH1Tag, _ := hex.DecodeString("0d7174c37605607f358844a9b867f60db4f5b9ef26ce93e1c77722d84b458730")
	assert.Equal(t, h1Tag, expectedH1Tag, "hash should be same")

	h1InputBigInt := make([]*big.Int, len(h1Input))
	for i := range h1Input {
		h1InputBigInt[i] = new(big.Int).SetBytes(h1Input[i])
	}
	h2 := SHA512_256i(ctx, h1InputBigInt...)
	assert.Equal(t, h2, new(big.Int).SetBytes(expectedH1))

	h2Tag := SHA512_256i_TAGGED(ctx, tag, h1InputBigInt...)
	assert.Equal(t, h2Tag, new(big.Int).SetBytes(expectedH1Tag))
}
