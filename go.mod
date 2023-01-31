module github.com/Safulet/tss-lib-private

go 1.19

require (
	github.com/agl/ed25519 v0.0.0-20170116200512-5312a6153412
	github.com/btcsuite/btcd v0.23.4
	github.com/btcsuite/btcd/btcec/v2 v2.3.2
	github.com/btcsuite/btcutil v1.0.2
	github.com/decred/dcrd/dcrec/edwards/v2 v2.0.2
	github.com/ethereum/go-ethereum v1.10.16
	github.com/hashicorp/go-multierror v1.1.1
	github.com/pkg/errors v0.9.1
	github.com/stretchr/testify v1.8.0
	go.uber.org/zap v1.19.1
	golang.org/x/crypto v0.5.0
	google.golang.org/protobuf v1.27.1
)

require (
	github.com/btcsuite/btcd/chaincfg/chainhash v1.0.1 // indirect
	github.com/davecgh/go-spew v1.1.1 // indirect
	github.com/decred/dcrd/dcrec/secp256k1/v4 v4.0.1 // indirect
	github.com/hashicorp/errwrap v1.0.0 // indirect
	github.com/pmezard/go-difflib v1.0.0 // indirect
	go.uber.org/atomic v1.7.0 // indirect
	go.uber.org/multierr v1.6.0 // indirect
	golang.org/x/sys v0.4.0 // indirect
	gopkg.in/yaml.v3 v3.0.1 // indirect
)

replace github.com/agl/ed25519 => github.com/binance-chain/edwards25519 v0.0.0-20200305024217-f36fc4b53d43
