// Copyright © 2019-2021 Binance
//
// This file is part of Binance. The full Binance copyright notice, including
// terms governing use, modification, and redistribution, is contained in the
// file LICENSE at the root of the source code distribution tree.

package postkeygen

import (
	"fmt"
	"path/filepath"
	"runtime"

	"github.com/Safulet/tss-lib-private/test"
)

const (
	testFixtureDirFormat  = "%s/../../test/_ecdsa_fixtures_%d_%d"
	testFixtureFileFormat = "keygen_data_%d.json"
)

func makeTestFixtureFilePath(partyIndex int) string {
	_, callerFileName, _, _ := runtime.Caller(0)
	srcDirName := filepath.Dir(callerFileName)
	fixtureDirName := fmt.Sprintf(testFixtureDirFormat, srcDirName, test.TestThreshold, test.TestParticipants)
	return fmt.Sprintf("%s/"+testFixtureFileFormat, fixtureDirName, partyIndex)
}
