// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"encoding/json"
	"fmt"
	"math/big"
	"testing"

	"github.com/Safulet/tss-lib-private/v2/crypto"
	"github.com/Safulet/tss-lib-private/v2/tss"
	"github.com/stretchr/testify/assert"
)

func TestComputeChallenge(t *testing.T) {
	ec := tss.EdBls12377()
	tvk, _ := new(big.Int).SetString("1663103998198483556172318632947444915298815778882100275952791028047054849162", 10)
	_gRx, _ := new(big.Int).SetString("2331092841542275673402812521897678300455118721879747779359204108111649610999", 10)
	_gRy, _ := new(big.Int).SetString("7790129533119026124003956471979771518436133960687074069803900715979642465401", 10)
	gR, _ := crypto.NewECPoint(ec, _gRx, _gRy)
	_pkSigx, _ := new(big.Int).SetString("4195866295966889185791453683727482306744478641612416810811602161049524435416", 10)
	_pkSigy, _ := new(big.Int).SetString("6822585840883381031774840144921029490873813264714289213294055598249645541122", 10)
	pkSig, _ := crypto.NewECPoint(ec, _pkSigx, _pkSigy)
	_prSigx, _ := new(big.Int).SetString("3616649401986417739602556431441077085751226996755363820872718960574471715134", 10)
	_prSigy, _ := new(big.Int).SetString("3545406330044058190785473621322141320079676276854717810727910148147922475667", 10)
	prSig, _ := crypto.NewECPoint(ec, _prSigx, _prSigy)

	signInputsStr := `{"signer":"aleo1mhtp5enrhgx2za9m09eg5pk4a463fp6ujs8rrmnxv98k7eq9yvpqv0xn66","function_id":"16971ebf5dbe0bc0521b080ae7b00fdf4eb358156d4ef1157fe65e4f2d432209","is_root":false,"inputs":[{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":0,"input_type":"constant"},{"fields":["0680d1bdad95b97d85b5bdd5b9d16902d0000830040000000000000000000000","0000000001000000000000000000000000000000000000000000000000000000"],"index":1,"input_type":"public"},{"fields":["bbad35ccc6741942e976f3e4140daadbeb280eb9281d62dccdc29edec80a4604","f0020000d0bdad95b97d85b5bdd5b9d1050310c010000000000000c00109580e","d538035a887f2bd032612b90779609c59f9c525faee2ecf0fabd479400000000"],"index":2,"input_type":"external_record"}]}`
	var signInputs RInputs
	err := json.Unmarshal([]byte(signInputsStr), &signInputs)
	assert.NoError(t, err)
	cha := ComputeChallenge(tvk, gR, pkSig, prSig, signInputs)
	fmt.Println("challenge:", cha)

	expected, ok := new(big.Int).SetString("1027060676979417574703743673772708569181447007371612634748055887658255675999", 10)
	assert.True(t, ok)
	assert.Zero(t, expected.Cmp(cha))
}

func TestComputeFunctionID(t *testing.T) {
	networkID := big.NewInt(0)
	programID := "token.aleo"
	functionName := "transfer"
	ret := computeFunctionID(networkID, programID, functionName)
	fmt.Println("ret:", ret)
}

func TestToFields(t *testing.T) {
	inputs := []string{"60018bbdb5a99dbea1adbdab9d8b96400b00100c20000000000000000000000000000008"}
	ret := toFields(inputs[0])
	fmt.Println("ret:", ret)
}

func TestToAddress(t *testing.T) {
	ec := tss.EdBls12377()
	x, _ := new(big.Int).SetString("966502560882496505477033789750380321143849446189826487120017086806551615197", 10)
	y, _ := new(big.Int).SetString("5987688235928665266882163321979084778662874839083753556735349867846368433782", 10)
	p, err := crypto.NewECPoint(ec, x, y)
	assert.NoError(t, err)
	addr, err := ToAddress(p)
	assert.NoError(t, err)
	assert.Equal(t, "aleo1mhtp5enrhgx2za9m09eg5pk4a463fp6ujs8rrmnxv98k7eq9yvpqv0xn66", addr)

	x, _ = new(big.Int).SetString("4226122011757053937871959034729048222687601818542835418135072409080620458124", 10)
	y, _ = new(big.Int).SetString("7337717904611926698582241552445855069717681336139157472110427007390158089384", 10)
	p, err = crypto.NewECPoint(ec, x, y)
	assert.NoError(t, err)
	addr, err = ToAddress(p)
	assert.NoError(t, err)
	assert.Equal(t, "aleo13sswzun3wyf36xpvwv7skfhg4r9fp8hkp08y36qyt47fs70x2uystjyswu", addr)
}
