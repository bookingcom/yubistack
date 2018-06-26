LDFLAGS ?= -w -s -X main.BuildDate=$(shell date +%F)
PREFIX ?= /usr

all: build
build: yubistack
install: $(PREFIX)/bin/yubistack
install.yubiksm: $(PREFIX)/bin/yubiksm

.PHONY: yubistack
yubistack:
	@go build  -ldflags '$(LDFLAGS)' -o $@ cmd/yubistack/*.go

.PHONY: yubiksm
yubiksm: $(SRC_FILES)
	@go build -ldflags '$(LDFLAGS)' -o $@ cmd/yubiksm/*.go

.PHONY: yubival
yubival: $(SRC_FILES)
	@go build -ldflags '$(LDFLAGS)' -o $@ cmd/yubival/*.go

$(PREFIX)/bin/yubistack: yubistack
	install -p -D -m 0750 $< $@

$(PREFIX)/bin/yubiksm: yubiksm
	install -p -D -m 0750 $< $@

$(PREFIX)/bin/yubival: yubival
	install -p -D -m 0750 $< $@

.PHONY: clean
clean:
	rm -f yubiksm yubistack yubival coverage.out

.PHONY: coverage.out
coverage.out:
	@go test -v -cover -coverprofile $(@) ./pkg/...

.PHONY: cover
cover: coverage.out
	@go tool cover -func $<

.PHONY: vet
vet:
	@go vet ./cmd/... ./pkg/...

.PHONY: fmt
fmt:
	@test -z "$$(gofmt -d ./ | tee /dev/stderr)"

.PHONY: lint
lint:
	@golangci-lint run --exclude-use-default=false ./...

.PHONY: test
test: cover vet fmt lint

.PHONY: examples
examples: examples.ykksm examples.ykval examples.ykauth examples.ykstack

.PHONY: examples.ykksm
examples.ykksm:
	@./examples/ykksm/test.sh

.PHONY: examples.ykval
examples.ykval:
	@./examples/ykval/test.sh

.PHONY: examples.ykauth
examples.ykauth:
	@./examples/ykauth/test.sh

.PHONY: examples.ykstack
examples.ykstack:
	@./examples/ykstack/test.sh
