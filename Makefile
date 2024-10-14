MODULE = github.com/Safulet/tss-lib-private
PACKAGES = $(shell go list ./... | grep -v '/vendor/')

all: protob test

########################################
### Protocol Buffers
### Build protoc docker image for generating protobuf files
build_protoc_docker:
	docker build -t protoc-build -f Dockerfile .

protob_docker: build_protoc_docker
	@echo "--> Building Protocol Buffers"
	@for protocol in bls-decryption bls-encryption bls-keygen bls-resharing bls-signing derivekey ecdsa-keygen ecdsa-postkeygen ecdsa-presigning ecdsa-resharing ecdsa-signing ecdsa-shared-secret ecdsa-keyshare-affine-transform eddsa-resharing eddsa-signing frost-keygen kcdsa-keygen kcdsa-resharing kcdsa-signing message schnorr-resharing schnorr-signing signature; do \
		echo "Generating $$protocol.pb.go" ; \
		docker run --rm -v $(PWD):/binance/tsslib/v2 protoc-build protoc -I/ --go_out=/binance/tsslib/v2 /binance/tsslib/v2/protob/$$protocol.proto ; \
	done

build: protob
	go fmt ./...

########################################
### Testing

test_unit:
	@echo "--> Running Unit Tests"
	@echo "!!! WARNING: This will take a long time :)"
	go clean -testcache
	go test -timeout 60m $(PACKAGES)

test_unit_race:
	@echo "--> Running Unit Tests (with Race Detection)"
	@echo "!!! WARNING: This will take a long time :)"
	go clean -testcache
	go test -timeout 60m -race $(PACKAGES)

test:
	make test_unit

########################################
### Pre Commit

pre_commit: build test

########################################

# To avoid unintended conflicts with file names, always add to .PHONY
# # unless there is a reason not to.
# # https://www.gnu.org/software/make/manual/html_node/Phony-Targets.html
.PHONY: protob build test_unit test_unit_race test
