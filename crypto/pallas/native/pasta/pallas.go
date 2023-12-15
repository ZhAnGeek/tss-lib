//
// Copyright Binance, Inc. All Rights Reserved.
//
// SPDX-License-Identifier: Apache-2.0
//

package pasta

func ReverseScalarBytes(inBytes []byte) []byte {
	outBytes := make([]byte, len(inBytes))

	for i, j := 0, len(inBytes)-1; j >= 0; i, j = i+1, j-1 {
		outBytes[i] = inBytes[j]
	}

	return outBytes
}
