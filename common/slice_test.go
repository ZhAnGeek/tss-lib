// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package common

import (
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestPadToLengthBytesInPlace(t *testing.T) {
	data := make([]byte, 1)
	data[0] = 1
	expectLength := 32
	data = PadToLengthBytesInPlace(data, expectLength)

	// data length == expectLength
	assert.True(t, len(data) == expectLength)
	// last element is 1 as line 17
	assert.True(t, data[31] == 1)
	// 0...31 elements is 0
	for i := 0; i < 31; i++ {
		assert.True(t, data[i] == 0)
	}
}
