//
// Copyright Binance, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package curves

import (
	"sync"
)

type mockReader struct {
	index int
	seed  []byte
}

var mockRngInitonce sync.Once
var mockRng mockReader

func newMockReader() {
	mockRng.index = 0
	mockRng.seed = make([]byte, 32)
	for i := range mockRng.seed {
		mockRng.seed[i] = 1
	}
}

func testRng() *mockReader {
	mockRngInitonce.Do(newMockReader)
	return &mockRng
}

func (m *mockReader) Read(p []byte) (n int, err error) {
	limit := len(m.seed)
	for i := range p {
		p[i] = m.seed[m.index]
		m.index += 1
		m.index %= limit
	}
	n = len(p)
	err = nil
	return
}
