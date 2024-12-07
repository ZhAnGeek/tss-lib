package bhp

import (
	"bytes"
	"hash"
)

type hasher struct {
	buf *bytes.Buffer
	bhp *bhpHasher
}

// Sum returns the BHP hash of the input bytes.
// use NumberOfWindows=3 and WindowSize=57 by default
func Sum(b []byte) []byte {
	h, _ := New(3, 57)
	h.Write(b)
	return h.Sum(nil)
}

// New returns a new hash.Hash computing the BHP hash.
func New(numWindows, windowSize int) (hash.Hash, error) {
	var bhp bhpHasher
	err := bhp.Setup(numWindows, windowSize, "TSSLIB")
	return &hasher{
		buf: bytes.NewBuffer([]byte{}),
		bhp: &bhp,
	}, err
}

// Write (via the embedded io.Writer interface) adds more data to the running hash.
func (h *hasher) Write(p []byte) (n int, err error) {
	return h.buf.Write(p)
}

// Sum returns the BHP digest of the data.
func (h *hasher) Sum(b []byte) []byte {
	hash, err := h.bhp.Hash(h.buf.Bytes())
	if err != nil {
		panic(err)
	}
	return append(b, hash...)
}

// Reset resets the Hash to its initial state.
func (h *hasher) Reset() {
	h.buf.Reset()
}

// Size returns the number of bytes Sum will return.
func (h *hasher) Size() int {
	return h.bhp.OutputSize()
}

// BlockSize returns the hash block size.
func (h *hasher) BlockSize() int {
	return h.bhp.BlockSize()
}
