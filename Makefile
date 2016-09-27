GOPATH=$(shell pwd)
SOURCEDIR=.
SOURCES := $(shell find $(SOURCEDIR) -name '*.go')

BINARY=./bin

LDFLAGS=

.DEFAULT_GOAL: $(BINARY)

$(BINARY): $(SOURCES)
	go build ${LDFLAGS} -o ${BINARY} cyberGo/main

.PHONY: install
install:
	go install ${LDFLAGS} cyberGo/main

run:
	go run src/cyberGo/main/main.go
test:
	go test cyberGo/store cyberGo/parser


.PHONY: clean
clean:
	rm -rf ${BINARY}
