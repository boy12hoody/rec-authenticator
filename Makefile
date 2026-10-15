CC ?= cc
CORE = src/totp.c src/import.c src/vault.c src/ntp.c \
       third_party/monocypher/monocypher.c third_party/monocypher/monocypher-ed25519.c
HDRS = $(wildcard src/*.h)
CFLAGS = -std=gnu11 -Wall -Wextra -Werror -Ithird_party/monocypher
SAN = -g -O1 -fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer

# libFuzzer needs a clang that ships it (Homebrew LLVM on macOS, any clang on Linux).
FUZZ_CC ?= $(shell test -x /opt/homebrew/opt/llvm/bin/clang && echo /opt/homebrew/opt/llvm/bin/clang || echo clang)
FUZZ_TIME ?= 60

# ARM64 static musl build. zig bundles musl, so no AOSP tree is needed.
CROSS_CC ?= zig cc -target aarch64-linux-musl
VERSION = $(shell python3 -c 'import json;print(json.load(open("plugin.json"))["version"])')

.PHONY: test e2e fuzz aerap clean

test: build/test build/host-plugin
	./build/test
	python3 tests/e2e.py build/host-plugin

build/test: $(CORE) $(HDRS) tests/test.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(SAN) $(CORE) tests/test.c -o $@

# The real plugin built for the host, driven by tests/e2e.py as a fake AERA.
build/host-plugin: $(CORE) $(HDRS) src/main.c
	@mkdir -p build
	$(CC) $(CFLAGS) $(SAN) $(CORE) src/main.c -o $@

build/fuzz: $(CORE) $(HDRS) tests/fuzz.c
	@mkdir -p build/corpus
	$(FUZZ_CC) $(CFLAGS) -g -O1 -fsanitize=fuzzer,address,undefined -fno-sanitize-recover=all $(CORE) tests/fuzz.c -o $@

fuzz: build/fuzz
	cp tests/seeds/* build/corpus/
	./build/fuzz -max_total_time=$(FUZZ_TIME) -max_len=8192 build/corpus

aerap: plugin.json $(CORE) $(HDRS) src/main.c
	rm -rf stage build/runtime.xz
	mkdir -p stage/usr/bin stage/usr/share/licenses/aera-authenticator build
	$(CROSS_CC) $(CFLAGS) -Os -static -ffunction-sections -fdata-sections \
		-Wl,--gc-sections -s $(CORE) src/main.c -o stage/usr/bin/aera-plugin
	cp third_party/monocypher/LICENCE.md stage/usr/share/licenses/aera-authenticator/monocypher.md
	cp LICENSE stage/usr/share/licenses/aera-authenticator/LICENSE
	python3 tools/pack.py stage build
	python3 tools/update_manifest.py plugin.json build/metadata.json
	python3 tools/package_aerap.py --manifest plugin.json --payload build/runtime.xz \
		--output build/Rec-Authenticator-$(VERSION).aerap

clean:
	rm -rf build stage
