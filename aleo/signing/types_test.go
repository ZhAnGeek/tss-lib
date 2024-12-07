// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing_test

import (
	"encoding/json"
	"fmt"
	"testing"

	"github.com/Safulet/tss-lib-private/v2/aleo/signing"
	"github.com/stretchr/testify/assert"
)

func TestUnmarshal(t *testing.T) {
	raw := `{"signer":"aleo1mhtp5enrhgx2za9m09eg5pk4a463fp6ujs8rrmnxv98k7eq9yvpqv0xn66","function_id":"16971ebf5dbe0bc0521b080ae7b00fdf4eb358156d4ef1157fe65e4f2d432209","inputs":[{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":0,"input_type":"constant"},{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":1,"input_type":"public"},{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":2,"input_type":"private"},{"fields":["ee4ba6a9b6bc4f50fec93cdf92850296999d09c515c13e6e452aac9cc926b40d"],"index":3,"input_type":"record"},{"fields":["bbad35ccc6741942e976f3e4140daadbeb280eb9281d62dccdc29edec80a4604","f0020000d0bdad95b97d85b5bdd5b9d1050310c010000000000000c00109580e","d538035a887f2bd032612b90779609c59f9c525faee2ecf0fabd479400000000"],"index":4,"input_type":"external_record"}]}`
	var inputs signing.RInputs
	err := json.Unmarshal([]byte(raw), &inputs)
	assert.NoError(t, err)

	fmt.Println(inputs)
}
