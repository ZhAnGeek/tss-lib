package common

import (
	"encoding/hex"
	"fmt"
	"testing"

	"github.com/agl/ed25519/edwards25519"
	"golang.org/x/crypto/ed25519"
)

// Verify checks whether the message has a valid signature.
func Verify(publicKey [32]byte, message []byte, signature []byte) bool {

	publicKey[31] &= 0x7F

	/* Convert the Curve25519 public key into an Ed25519 public key.  In
	particular, convert Curve25519's "montgomery" x-coordinate into an
	Ed25519 "edwards" y-coordinate:
	ed_y = (mont_x - 1) / (mont_x + 1)
	NOTE: mont_x=-1 is converted to ed_y=0 since fe_invert is mod-exp
	Then move the sign bit into the pubkey from the signature.
	*/

	var edY, one, montX, montXMinusOne, montXPlusOne edwards25519.FieldElement
	edwards25519.FeFromBytes(&montX, &publicKey)
	edwards25519.FeOne(&one)
	edwards25519.FeSub(&montXMinusOne, &montX, &one)
	edwards25519.FeAdd(&montXPlusOne, &montX, &one)
	edwards25519.FeInvert(&montXPlusOne, &montXPlusOne)
	edwards25519.FeMul(&edY, &montXMinusOne, &montXPlusOne)

	var A_ed [32]byte
	edwards25519.FeToBytes(&A_ed, &edY)

	A_ed[31] |= signature[63] & 0x80
	signature[63] &= 0x7F

	return ed25519.Verify(ed25519.PublicKey(A_ed[:]), message, signature)
}

func TestBHP1(t *testing.T) {
	pkHex := "ab7e717d4a163b7d9a1d8071dfe9dcf8cdcd1cea3339b6356be84d887e322c64"
	pk, err := hex.DecodeString(pkHex)
	if err != nil {
		panic(fmt.Sprintf("Failed to decode message: %v", err))
	}
	var pkBytes [32]byte
	copy(pkBytes[:], pk)

	messageHex := "05edce9d9c415ca78cb7252e72c2c4a554d3eb29485a0e1d503118d1a82d99fb4a"
	message, err := hex.DecodeString(messageHex)
	if err != nil {
		panic(fmt.Sprintf("Failed to decode message: %v", err))
	}

	signatureHex := "5de88ca9a89b4a115da79109c67c9c7464a3e4180274f1cb8c63c2984e286dfbede82deb9dcd9fae0bfbb821569b3d9001bd8130cd11d486cef047bd60b86e88"
	signature, err := hex.DecodeString(signatureHex)
	if err != nil {
		panic(fmt.Sprintf("Failed to decode signature: %v", err))
	}

	// 5. 验证签名
	valid := Verify(pkBytes, message, signature)

	// 6. 输出结果
	fmt.Printf("Original signature verification result: %v\n", valid)

}
