.PHONY: all build test clean contracts-install contracts-build contracts-test \
        resolver-build resolver-test deploy-localhost seed-localhost chain \
        bindings zk-setup demo presentation fmt race cover

all: build

build: contracts-build resolver-build

test: contracts-test resolver-test

contracts-install:
	cd contracts && npm install

contracts-build:
	cd contracts && npx hardhat compile

contracts-test:
	cd contracts && npx hardhat test

chain:
	cd contracts && npx hardhat node

deploy-localhost:
	cd contracts && npx hardhat run scripts/deploy.ts --network localhost

deploy-sepolia:
	cd contracts && npx hardhat run scripts/deploy.ts --network sepolia

seed-localhost:
	cd contracts && npx hardhat run scripts/seed.ts --network localhost

bindings:
	scripts/gen-bindings.sh

# Dev-only Groth16 ceremony: regenerates resolver/internal/zk/artifacts,
# contracts/contracts/ZKVerifier.sol and the hardhat proof fixture.
zk-setup:
	cd resolver && go run ./cmd/zkgen

# Full local end-to-end demo: chain + contracts + resolver + CLIs (HLD §4.4).
demo:
	./scripts/demo.sh

# 1-click live presentation launcher (keeps running with dashboard + site + extension).
start:
	./ddns start

presentation:
	./ddns start

dashboard:
	./ddns dashboard

site:
	./ddns open example

resolver-build:
	cd resolver && go build -buildvcs=false -o bin/ ./...

resolver-test:
	cd resolver && go vet ./... && go test ./...

# Format Go sources (matches the CI gofmt gate).
fmt:
	cd resolver && gofmt -w .

# Run the Go suite under the race detector (mirrors CI).
race:
	cd resolver && go test -race ./...

# Resolver logic coverage: internal/ packages across the whole suite,
# excluding the generated contract bindings (mirrors the CI summary).
cover:
	cd resolver && go test -coverpkg=./internal/... -coverprofile=coverage.out ./... \
		&& grep -v 'internal/chain/bindings/' coverage.out > coverage.filtered \
		&& go tool cover -func=coverage.filtered | tail -1 \
		&& rm -f coverage.filtered

clean:
	rm -rf contracts/artifacts contracts/cache contracts/typechain-types resolver/bin
