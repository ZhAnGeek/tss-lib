// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package mina

import (
	"encoding/binary"
	"fmt"

	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fp"
	"github.com/coinbase/kryptology/pkg/core/curves/native/pasta/fq"
	"github.com/coinbase/kryptology/pkg/signatures/schnorr/mina"
)

// Handles the packing of bits and fields according to Mina spec
type Roinput struct {
	fields []*fp.Fp
	bits   *mina.BitVector
}

var conv = map[bool]int{
	true:  1,
	false: 0,
}

func (r *Roinput) Init(fields int, bytes int) *Roinput {
	r.fields = make([]*fp.Fp, 0, fields)
	r.bits = mina.NewBitVector(make([]byte, bytes), 0)
	return r
}

func (r *Roinput) Clone() *Roinput {
	t := new(Roinput)
	t.fields = make([]*fp.Fp, len(r.fields))
	for i, f := range r.fields {
		t.fields[i] = new(fp.Fp).Set(f)
	}
	buffer := r.bits.Bytes()
	data := make([]byte, len(buffer))
	copy(data, buffer)
	t.bits = mina.NewBitVector(data, r.bits.Length())
	return t
}

func (r *Roinput) AddFp(fp *fp.Fp) {
	r.fields = append(r.fields, fp)
}

func (r *Roinput) AddFq(fq *fq.Fq) {
	scalar := fq.ToRaw()
	// Mina handles fields as 255 bit numbers
	// with each field we lose a bit
	for i := 0; i < 255; i++ {
		limb := i / 64
		idx := i % 64
		b := (scalar[limb] >> idx) & 1
		r.bits.Append(byte(b))
	}
}

func (r *Roinput) AddBit(b bool) {
	r.bits.Append(byte(conv[b]))
}

func (r *Roinput) AddBytes(input []byte) {
	for _, b := range input {
		for i := 0; i < 8; i++ {
			r.bits.Append((b >> i) & 1)
		}
	}
}

func (r *Roinput) AddUint32(x uint32) {
	for i := 0; i < 32; i++ {
		r.bits.Append(byte((x >> i) & 1))
	}
}

func (r *Roinput) AddUint64(x uint64) {
	for i := 0; i < 64; i++ {
		r.bits.Append(byte((x >> i) & 1))
	}
}

func (r Roinput) Bytes() []byte {
	out := make([]byte, (r.bits.Length()+7)/8+32*len(r.fields))
	res := mina.NewBitVector(out, 0)
	// Mina handles fields as 255 bit numbers
	// with each field we lose a bit
	for _, f := range r.fields {
		buf := f.ToRaw()
		for i := 0; i < 255; i++ {
			limb := i / 64
			idx := i % 64
			b := (buf[limb] >> idx) & 1
			res.Append(byte(b))
		}
	}
	for i := 0; i < r.bits.Length(); i++ {
		res.Append(r.bits.Element(i))
	}
	return out
}

func (r Roinput) Fields() []*fp.Fp {
	fields := make([]*fp.Fp, 0, len(r.fields)+r.bits.Length()/256)
	for _, f := range r.fields {
		fields = append(fields, new(fp.Fp).Set(f))
	}
	const maxChunkSize = 254
	bitsConsumed := 0
	bitIdx := 0

	for bitsConsumed < r.bits.Length() {
		var chunk [4]uint64

		remaining := r.bits.Length() - bitsConsumed
		var chunkSizeInBits int
		if remaining > maxChunkSize {
			chunkSizeInBits = maxChunkSize
		} else {
			chunkSizeInBits = remaining
		}

		for i := 0; i < chunkSizeInBits; i++ {
			limb := i >> 6
			idx := i & 0x3F
			b := r.bits.Element(bitIdx)
			chunk[limb] |= uint64(b) << idx
			bitIdx++
		}
		fields = append(fields, new(fp.Fp).SetRaw(&chunk))
		bitsConsumed += chunkSizeInBits
	}

	return fields
}

func (r *Roinput) ToRawBytes() []byte {
	raw := make([]byte, 4)

	// fields
	binary.LittleEndian.PutUint32(raw[:4], uint32(len(r.fields)))
	for _, f := range r.fields {
		b := f.Bytes()
		raw = append(raw, b[:]...)
	}

	// bits
	lenBs := make([]byte, 4)
	binary.LittleEndian.PutUint32(lenBs[:], uint32(r.bits.Length()))
	raw = append(raw, lenBs...)
	raw = append(raw, r.bits.Bytes()...)

	return raw
}

func (r *Roinput) RecoverRaw(raw []byte) error {
	if len(raw) < 4 {
		return fmt.Errorf("raw bytes is invalid")
	}

	fieldLen := int(binary.LittleEndian.Uint32(raw[:4]))
	fbyteLen := fieldLen * 32
	if len(raw[4:]) < fbyteLen {
		return fmt.Errorf("raw bytes is invalid")
	}
	fields := make([]*fp.Fp, fieldLen)
	var err error
	start := 4
	for i := range fields {
		var b [32]byte
		copy(b[:], raw[start:start+32])
		fields[i], err = new(fp.Fp).SetBytes(&b)
		if err != nil {
			return err
		}
		start += 32
	}

	if len(raw) < start+4 {
		return fmt.Errorf("raw bytes is invalid")
	}
	l := int(binary.LittleEndian.Uint32(raw[start : start+4]))
	maxBitLen := len(raw[start+4:]) * 8
	minBitLen := maxBitLen - 7
	if l < minBitLen || l > maxBitLen {
		return fmt.Errorf("raw bytes is invalid")
	}
	bits := mina.NewBitVector(raw[start+4:], l)

	r.fields = fields
	r.bits = bits
	return nil
}
