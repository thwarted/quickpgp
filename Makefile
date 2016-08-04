quickpgp: $(shell find src -type f -name "*.go")
	GOPATH=$(shell pwd ) go build -v src/quickpgp.go

clean:
	rm -v quickpgp

.PHONY: clean
