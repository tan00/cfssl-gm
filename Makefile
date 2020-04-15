VERSION := "v1.0"
LDFLAGS := "-s -w  -X github.com/cloudflare/cfssl/cli/version.version=$(VERSION)"

export GOFLAGS := -mod=vendor
export GOPROXY := off

.PHONY: all
all: bin/cfssl  bin/cfssljson bin/mkbundle bin/multirootca

bin/%: $(shell find . -type f -name '*.go')
	@mkdir -p $(dir $@)
	go build -ldflags $(LDFLAGS) -o $@ ./cmd/$(@F)



.PHONY: install
install:
	cp bin/*  dist/

.PHONY: clean
clean:
	rm -f bin/* 


