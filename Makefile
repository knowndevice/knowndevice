.PHONY: check test build demo fmt

check:
	bash scripts/ci_local.sh all

test:
	bash scripts/ci_local.sh test

build:
	bash scripts/ci_local.sh build

demo: build
	bin/knowndevice simulate --scenario rotation
	bin/knowndevice simulate --scenario acl-denied

fmt:
	gofmt -w cmd internal adapters api sdk examples
