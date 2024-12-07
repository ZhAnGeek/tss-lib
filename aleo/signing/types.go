// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package signing

import (
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"

	"github.com/Safulet/tss-lib-private/v2/common"
)

type InputStr struct {
	Fields    []string
	Index     int
	InputType string `json:"input_type"`
}

type RInputsStr struct {
	Signer     string
	FunctionID string `json:"function_id"`
	IsRoot     string `json:"is_root"`
	Inputs     []InputStr
}

type Input struct {
	Fields    []*big.Int
	Index     int
	InputType InputType
}

type RInputs struct {
	Signer     string
	FunctionID *big.Int
	IsRoot     bool
	Inputs     []Input
}

func (m *RInputs) UnmarshalJSON(data []byte) error {
	var res RInputsStr
	err := json.Unmarshal(data, &res)
	if err != nil {
		return err
	}
	m.Signer = res.Signer
	v, err := hex.DecodeString(res.FunctionID)
	val := new(big.Int).SetBytes(common.ReverseBytes(v))
	m.FunctionID = val
	if res.IsRoot == "" {
		m.IsRoot = true // set default "true"
	} else {
		if res.IsRoot == "false" {
			m.IsRoot = false
		} else {
			m.IsRoot = true
		}
	}

	m.Inputs = make([]Input, len(res.Inputs))
	for i := range res.Inputs {
		m.Inputs[i].Index = res.Inputs[i].Index
		typ := InputType(res.Inputs[i].InputType)
		if typ != ConstantInputType && typ != PublicInputType && typ != PrivateInputType && typ != RecordInputType && typ != ExternalRecordInputType {
			panic(errors.New(fmt.Sprintf("type unknown %s", typ)))
		}
		m.Inputs[i].InputType = typ
		m.Inputs[i].Fields = make([]*big.Int, len(res.Inputs[i].Fields))
		for j := range res.Inputs[i].Fields {
			bzs, err := hex.DecodeString(res.Inputs[i].Fields[j])
			if err != nil {
				return err
			}
			m.Inputs[i].Fields[j] = new(big.Int).SetBytes(common.ReverseBytes(bzs))
		}

	}
	return nil
}

// RequestOutDump stores RequestOut test only
type RequestOutDump struct {
	Challenge string `json:"challenge"`
	Response  string `json:"response"`
	SkTag     string `json:"sk_tag"`
	Tvk       string `json:"tvk"`
	Tcm       string `json:"tcm"`
	Scm       string `json:"scm"`
}

type InputType string

const (
	ConstantInputType       InputType = "constant"
	PublicInputType         InputType = "public"
	PrivateInputType        InputType = "private"
	RecordInputType         InputType = "record"
	ExternalRecordInputType InputType = "external_record"
)

func (InputType) Values() []InputType {
	return []InputType{
		ConstantInputType,
		PublicInputType,
		PrivateInputType,
		RecordInputType,
		ExternalRecordInputType,
	}
}
