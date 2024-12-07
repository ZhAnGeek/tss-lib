package bls12377

import "fmt"

func PadToLengthBytesInPlace(src []byte, length int) ([]byte, error) {
	if len(src) > length {
		return nil, fmt.Errorf("can not pad to src length %v for %v", len(src), length)
	}
	oriLen := len(src)
	if oriLen < length {
		for i := 0; i < length-oriLen; i++ {
			src = append([]byte{0}, src...)
		}
	}
	return src, nil
}
