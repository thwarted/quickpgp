quickpgp: $(shell find src -type f)
	GOPATH=$(shell pwd ) go build src/quickpgp.go
