GOPATH=$(shell pwd)
SOURCEDIR=.
SOURCES := $(shell find $(SOURCEDIR) -name '*.go')

BINARY=./bin

LDFLAGS=

.DEFAULT_GOAL: $(BINARY)

$(BINARY): $(SOURCES)
	go build ${LDFLAGS} -o ${BINARY} bitbucket.com/cyberGo/main

.PHONY: install
install:
	go install ${LDFLAGS} bitbucket.com/cyberGo/main

run:
	go run src/bitbucket.com/cyberGo/main/main.go

.PHONY: clean
clean:
	rm -rf ${BINARY}
