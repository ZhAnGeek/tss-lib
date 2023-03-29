module github.com/Safulet/tss-lib-private

go 1.15

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412
	github.com/btcsuite/btcd v0.21.0-beta.0.20201114000516-e9c7a5ac6401
	github.com/btcsuite/btcutil v1.0.2
	github.com/coinbase/kryptology v1.8.0
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.2
	github.com/ethereum/go-ethereum v1.10.16
	github.com/hashicorp/go-multierror v1.1.1
	github.com/pkg/errors v0.9.1
	github.com/roasbeef/btcd v0.0.0-20180418012700-a03db407e40d
	github.com/stretchr/testify v1.7.0
	go.uber.org/zap v1.19.1
	golang.org/x/crypto v0.0.0-20210711020723-a769d52b0f97
	google.golang.org/protobuf v1.27.1
)

replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
