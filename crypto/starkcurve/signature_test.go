package starkcurve

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io/ioutil"
	"math/big"
	"os"
	"testing"

	"github.com/Safulet/tss-lib-private/common"
	"github.com/consensys/gnark-crypto/ecc/stark-curve/fp"
	hash "github.com/consensys/gnark-crypto/ecc/stark-curve/pedersen-hash"
	"github.com/stretchr/testify/assert"
)

func dataFile() (map[string]interface{}, error) {
	file, err := os.Open("signature_test_data.json")
	if err != nil {
		return nil, err
	}
	defer file.Close()

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		return nil, err
	}

	var data map[string]interface{}
	err = json.Unmarshal(byteValue, &data)
	if err != nil {
		return nil, err
	}
	return data, nil
}

func TestSignatureVerified(t *testing.T) {
	data, err := dataFile()
	if err != nil {
		panic(err)
	}
	// transfer := readTransferData(data)

	privateKey, _ := new(big.Int).SetString(data["private_key"].(string)[2:], 16)
	X, Y := Stark().ScalarBaseMult(privateKey.Bytes())
	assert.True(t, Stark().IsOnCurve(X, Y))
	YNeg := new(big.Int).Neg(Y)

	fmt.Println(hex.EncodeToString(X.Bytes()))
	messages := data["messages"].([]interface{})

	for _, msg := range messages {
		message := msg.(map[string]interface{})
		r, _ := new(big.Int).SetString(message["r"].(string), 10)
		s, _ := new(big.Int).SetString(message["s"].(string), 10)

		// msg := getMsg(big.NewInt(1), transfer.SenderVaultID, transfer.ReceiverVaultID, transfer.Amount, big.NewInt(0), transfer.Token, transfer.ReceiverPublicKey, transfer.Nonce, transfer.ExpirationTimestamp)
		msg, _ := new(big.Int).SetString(message["hash"].(string)[2:], 16)
		result, err := Stark().Verify(msg, r, s, X, Y)

		assert.Nil(t, err)
		assert.True(t, result)

		result, err = Stark().Verify(msg, r, s, X, YNeg)
		assert.Nil(t, err)
		assert.True(t, result)
	}
}

func TestYCoordinate(t *testing.T) {
	stark := Stark()
	priv := stark.getRandomPrivateKey()
	pubx, puby := stark.ScalarBaseMult(priv.Bytes())

	fmt.Println(pubx, puby)
	y := stark.GetYCoordinate(pubx)

	yNeg := new(big.Int).Neg(y)
	yNegMod := yNeg.Mod(yNeg, stark.P)

	assert.Equal(t, true, puby.Cmp(y) == 0 || puby.Cmp(yNegMod) == 0)
}

func TestVerifySizeFailure(t *testing.T) {
	msg := new(big.Int).Exp(big.NewInt(2), big.NewInt(N_ELEMENT_BITS_ECDSA), nil)
	max_msg := msg.Sub(msg, big.NewInt(1))

	r := new(big.Int).Exp(big.NewInt(2), big.NewInt(N_ELEMENT_BITS_ECDSA), nil)
	max_r := msg.Sub(r, big.NewInt(1))
	max_s := new(big.Int).Sub(Stark().N, big.NewInt(2))

	privKey := Stark().getRandomPrivateKey()
	x, y := Stark().ScalarBaseMult(privKey.Bytes())

	_, err := Stark().Verify(new(big.Int).Add(max_msg, big.NewInt(1)), max_r, max_s, x, y)
	assert.ErrorContains(t, err, "hash exceeds the range (0, EcdsaMax)")

	_, err = Stark().Verify(max_msg, new(big.Int).Add(max_r, big.NewInt(1)), max_s, x, y)
	assert.ErrorContains(t, err, "r exceeds the range (0, EcdsaMax)")

	_, err = Stark().Verify(max_msg, max_r, new(big.Int).Add(max_s, big.NewInt(1)), x, y)
	assert.ErrorContains(t, err, "w exceeds the range (0, EcdsaMax)")

	_, err = Stark().Verify(max_msg, max_r, new(big.Int).Add(max_s, big.NewInt(2)), x, y)
	assert.ErrorContains(t, err, "s exceeds the range (0, N)")
}

func TestECDSASignature(t *testing.T) {
	priv := Stark().getRandomPrivateKey()
	pubx, puby := Stark().ScalarBaseMult(priv.Bytes())
	msg := common.GetRandomPositiveInt(new(big.Int).Exp(big.NewInt(2), big.NewInt(251), nil))
	msg = msg.Sub(msg, big.NewInt(1))
	r, s, err := Stark().Sign(priv, msg)

	assert.Nil(t, err)

	verified, err := Stark().Verify(msg, r, s, pubx, puby)
	assert.True(t, verified)
	assert.Nil(t, err)
}

func TestPedersenHash(t *testing.T) {
	input1, _ := new(big.Int).SetString("3d937c035c878245caf64531a5756109c53068da139362728feb561405371cb", 16)
	input2, _ := new(big.Int).SetString("208a0a10250e382e1e4bbe2880906c2791bf6275695e02fbbc6aeff9cd8b31a", 16)

	input1FP := new(fp.Element)
	input2FP := new(fp.Element)

	input1FP.SetInterface(input1)
	input2FP.SetInterface(input2)

	output, _ := new(big.Int).SetString("30e480bed5fe53fa909cc0f8c4d99b8f9f2c016be4c41e13a4848797979c662", 16)
	outputFP := new(fp.Element)

	outputFP.SetInterface(output)

	outputHash := hash.Pedersen(input1FP, input2FP)
	assert.Equal(t, outputHash.String(), outputFP.String())

	input21, _ := new(big.Int).SetString("58f580910a6ca59b28927c08fe6c43e2e303ca384badc365795fc645d479d45", 16)
	input22, _ := new(big.Int).SetString("78734f65a067be9bdb39de18434d71e79f7b6466a4b66bbd979ab9e7515fe0b", 16)

	input1FP.SetInterface(input21)
	input2FP.SetInterface(input22)

	output2, _ := new(big.Int).SetString("68cc0b76cddd1dd4ed2301ada9b7c872b23875d5ff837b3a87993e0d9996b87", 16)
	outputFP.SetInterface(output2)

	outputHash = hash.Pedersen(input1FP, input2FP)
	assert.Equal(t, outputHash.String(), outputFP.String())
}

func CalcMsgHash(t *testing.T, InstructionType, SenderVaultID, ReceiverVaultID, Amount0, Amount1, Token, ReceiverPublicKey, Nonce, ExpirationTimestamp *big.Int) *big.Int {
	packedMessage := big.NewInt(0)
	packedMessage.Mul(InstructionType, big.NewInt(1<<31))
	packedMessage.Add(packedMessage, SenderVaultID)
	packedMessage.Mul(packedMessage, big.NewInt(1<<31))
	packedMessage.Add(packedMessage, ReceiverVaultID)
	packedMessage.Mul(packedMessage, new(big.Int).Exp(big.NewInt(2), big.NewInt(63), nil))
	packedMessage.Add(packedMessage, Amount0)
	packedMessage.Mul(packedMessage, new(big.Int).Exp(big.NewInt(2), big.NewInt(63), nil))
	packedMessage.Add(packedMessage, Amount1)
	packedMessage.Mul(packedMessage, big.NewInt(1<<31))
	packedMessage.Add(packedMessage, Nonce)
	packedMessage.Mul(packedMessage, big.NewInt(1<<22))
	packedMessage.Add(packedMessage, ExpirationTimestamp)

	fmt.Println(packedMessage)

	assert.Equal(t, packedMessage.Cmp(Stark().N), -1)

	token0Fp := new(fp.Element)
	token0Fp.SetInterface(Token)

	publicKeyFp := new(fp.Element)
	publicKeyFp.SetInterface(ReceiverPublicKey)

	packedMessageFp := new(fp.Element)
	packedMessageFp.SetInterface(packedMessage)

	first := hash.Pedersen(token0Fp, publicKeyFp)
	second := hash.Pedersen(&first, packedMessageFp)

	return second.BigInt(new(big.Int))
}

func TestTransferMsg(t *testing.T) {
	file, err := os.Open("transaction_test_data.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err)
	}

	var data TestData
	err = json.Unmarshal(byteValue, &data)

	amount, _ := new(big.Int).SetString(data.TransferOrder.Amount, 10)
	token, _ := new(big.Int).SetString(data.TransferOrder.Token[2:], 16)
	targetPublicKey, _ := new(big.Int).SetString(data.TransferOrder.TargetPublicKey[2:], 16)

	msgHash := CalcMsgHash(t, big.NewInt(1),
		big.NewInt(data.TransferOrder.SenderVaultID),
		big.NewInt(data.TransferOrder.TargetVaultID),
		amount,
		big.NewInt(0),
		token,
		targetPublicKey,
		big.NewInt(data.TransferOrder.Nonce),
		big.NewInt(data.TransferOrder.ExpirationTimestamp))

	tMsgHash, _ := new(big.Int).SetString(data.MetaData.TransferOrder.MessageHash[2:], 16)
	assert.Equal(t, tMsgHash.Bytes(), msgHash.Bytes())
}

func TestTransferSigningExample(t *testing.T) {
	file, err := os.Open("transaction_test_data.json")
	if err != nil {
		panic(err)
	}

	defer file.Close()

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err)
	}

	var data TestData
	err = json.Unmarshal(byteValue, &data)

	amount, _ := new(big.Int).SetString(data.TransferOrder.Amount, 10)
	token, _ := new(big.Int).SetString(data.TransferOrder.Token[2:], 16)
	targetPublicKey, _ := new(big.Int).SetString(data.TransferOrder.TargetPublicKey[2:], 16)

	msgHash := CalcMsgHash(t, big.NewInt(1),
		big.NewInt(data.TransferOrder.SenderVaultID),
		big.NewInt(data.TransferOrder.TargetVaultID),
		amount,
		big.NewInt(0),
		token,
		targetPublicKey,
		big.NewInt(data.TransferOrder.Nonce),
		big.NewInt(data.TransferOrder.ExpirationTimestamp))

	priv := data.MetaData.PartyAOrder.PrivateKey
	privKey, _ := new(big.Int).SetString(priv[2:], 16)
	pkx, pky := Stark().ScalarBaseMult(privKey.Bytes())

	r, s, err := Stark().Sign(privKey, msgHash)

	assert.Nil(t, err)
	valid, err := Stark().Verify(msgHash, r, s, pkx, pky)
	assert.True(t, valid)
}

func TestPubKeyPreComputed(t *testing.T) {
	file, err := os.Open("key_precomputed.json")
	if err != nil {
		panic(err)
	}
	defer file.Close()

	byteValue, err := ioutil.ReadAll(file)
	if err != nil {
		panic(err)
	}

	var data map[string]interface{}
	err = json.Unmarshal(byteValue, &data)

	for priv, pub := range data {
		privs, _ := new(big.Int).SetString(priv[2:], 16)
		pubx, _ := Stark().ScalarBaseMult(privs.Bytes())
		pubkey, _ := new(big.Int).SetString(pub.(string)[2:], 16)
		assert.Equal(t, pubkey.Bytes(), pubx.Bytes())
	}
}
