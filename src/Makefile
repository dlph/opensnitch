BUILD_VERSION ?= dev

.PHONY: build
build:
	go build -ldflags "-X 'github.com/dlph/opensnitch/build.version=$(BUILD_VERSION)'" -o opensnitchd

.PHONY: clean
clean:
	rm opensnitchd