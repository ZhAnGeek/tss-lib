module github.com/Safulet/tss-lib-private

go 1.15

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412
	github.com/btcsuite/btcd v0.22.3
	github.com/btcsuite/btcutil v1.0.3-0.20201208143702-a53e38424cce
	github.com/coinbase/kryptology v1.8.0
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.2
	github.com/ethereum/go-ethereum v1.10.22
	github.com/hashicorp/go-multierror v1.1.1
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.7.2
	go.uber.org/zap v1.19.1
	golang.org/x/crypto v0.1.0
	google.golang.org/protobuf v1.27.1
)

replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
