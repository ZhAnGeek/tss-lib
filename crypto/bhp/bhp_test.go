package bhp

import (
	"testing"
)

func TestBHP(t *testing.T) {

	bhp, err := New(3, 57)
	if err != nil {
		t.Error(err)
	}
	input := []byte("Hello World")
	_, err = bhp.Write(input)
	if err != nil {
		t.Error(err)
	}

	outputHash1 := bhp.Sum(nil)
	outputHash2 := Sum(input)

	for i := range outputHash1 {
		if outputHash1[i] != outputHash2[i] {
			t.Error("fail on getting same hash for exact input")
		}
	}
}
