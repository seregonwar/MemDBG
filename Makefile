# memDBG - Memory debugger payload for jailbroken consoles.
# Copyright (C) 2026 SeregonWar
# SPDX-License-Identifier: GPL-3.0-or-later

HOST_CC ?= cc
HOST_AR ?= ar

BUILD_DIR ?= build
HOST_TARGET ?= $(BUILD_DIR)/MemDBG-host
PS4_TARGET ?= $(BUILD_DIR)/ps4/MemDBG-ps4.elf
PS4_LIB_TARGET ?= $(BUILD_DIR)/ps4/libmemdbg.a
PS5_TARGET ?= $(BUILD_DIR)/ps5/MemDBG-ps5.elf
PS5_LIB_TARGET ?= $(BUILD_DIR)/ps5/libmemdbg.a

PS4_PAYLOAD_SDK ?= $(CURDIR)/external/ps4-payload-sdk
PS5_PAYLOAD_SDK ?= $(CURDIR)/external/ps5-payload-sdk
PS4_HOST ?= ps4
PS4_PORT ?= 9021
PS5_HOST ?= ps5
PS5_PORT ?= 9021
LLVM_CONFIG ?= $(firstword $(wildcard /opt/homebrew/opt/llvm/bin/llvm-config /usr/local/opt/llvm/bin/llvm-config))
export LLVM_CONFIG

PS4_CC ?= $(PS4_PAYLOAD_SDK)/bin/orbis-clang
PS4_AR ?= $(PS4_PAYLOAD_SDK)/bin/orbis-ar
PS4_DEPLOY ?= $(PS4_PAYLOAD_SDK)/bin/orbis-deploy
PS5_CC ?= $(PS5_PAYLOAD_SDK)/bin/prospero-clang
PS5_AR ?= $(PS5_PAYLOAD_SDK)/bin/prospero-ar
PS5_DEPLOY ?= $(PS5_PAYLOAD_SDK)/bin/prospero-deploy

COMMON_CPPFLAGS := -Iinclude
COMMON_CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -O2
HOST_CPPFLAGS := $(COMMON_CPPFLAGS) -D_DARWIN_C_SOURCE -D_POSIX_C_SOURCE=200809L
HOST_CFLAGS := $(COMMON_CFLAGS)
HOST_LDLIBS := -lpthread

SOURCES := $(shell find src -name '*.c' | sort)
LIB_SOURCES := $(filter-out src/core/main.c,$(SOURCES))
HOST_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/host/%.o,$(SOURCES))
PS4_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/ps4/%.o,$(SOURCES))
PS4_LIB_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/ps4-lib/%.o,$(LIB_SOURCES))
PS5_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/ps5/%.o,$(SOURCES))
PS5_LIB_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/ps5-lib/%.o,$(LIB_SOURCES))

.PHONY: all clean host payload-ps4 payload-ps4-lib payload-ps5 payload-ps5-lib deploy-ps4 deploy-ps5 frontend verify test test-aob-boundary test-process-aob-e2e check-locales

all: host

host: $(HOST_TARGET)

test-aob-boundary: $(BUILD_DIR)/host/scanner/memdbg_scan.o tests/test_aob_boundary.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_aob_boundary.c $< -o $(BUILD_DIR)/test_aob_boundary
	@echo "--- Running AOB boundary test ---"
	$(BUILD_DIR)/test_aob_boundary

test-process-aob-e2e: host tests/test_process_aob_e2e.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_process_aob_e2e.c -o $(BUILD_DIR)/test_process_aob_e2e
	@echo "--- Running process AOB E2E test ---"
	@tmpdir=$$(mktemp -d /tmp/memdbg-e2e.XXXXXX); \
	port=19120; \
	$(HOST_TARGET) --bind=127.0.0.1 --debug-port=$$port --udp-port=19123 --data-root=$$tmpdir --no-udp-log --no-replace-existing >$$tmpdir/payload.log 2>&1 & \
	pid=$$!; \
	trap 'kill -TERM $$pid 2>/dev/null || true; sleep 0.8; kill -KILL $$pid 2>/dev/null || true; wait $$pid 2>/dev/null || true; rm -rf $$tmpdir' EXIT; \
	sleep 0.6; \
	$(BUILD_DIR)/test_process_aob_e2e 127.0.0.1 $$port

test: test-aob-boundary test-process-aob-e2e

payload-ps4: $(PS4_TARGET)
payload-ps5: $(PS5_TARGET)

payload-ps4-lib: $(PS4_LIB_TARGET)
payload-ps5-lib: $(PS5_LIB_TARGET)

deploy-ps4: $(PS4_TARGET)
	$(PS4_DEPLOY) -h $(PS4_HOST) -p $(PS4_PORT) $<

deploy-ps5: $(PS5_TARGET)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $<

frontend:
	cmake -S frontend -B $(BUILD_DIR)/frontend -DCMAKE_BUILD_TYPE=Release
	cmake --build $(BUILD_DIR)/frontend -j4

check-locales:
	python3 tools/check_locales.py

verify:
	$(MAKE) clean
	$(MAKE) host
	$(MAKE) payload-ps4
	$(MAKE) payload-ps5

$(HOST_TARGET): $(HOST_OBJECTS)
	@mkdir -p $(dir $@)
	$(HOST_CC) $^ $(HOST_LDLIBS) -o $@

$(BUILD_DIR)/host/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) -c $< -o $@

$(PS4_TARGET): $(PS4_OBJECTS)
	@mkdir -p $(dir $@)
	$(PS4_CC) $^ -lpthread -o $@

$(PS4_LIB_TARGET): $(PS4_LIB_OBJECTS)
	@mkdir -p $(dir $@)
	$(PS4_AR) rcs $@ $^

$(PS5_TARGET): $(PS5_OBJECTS)
	@mkdir -p $(dir $@)
	$(PS5_CC) $^ -lpthread -o $@

$(PS5_LIB_TARGET): $(PS5_LIB_OBJECTS)
	@mkdir -p $(dir $@)
	$(PS5_AR) rcs $@ $^

$(BUILD_DIR)/ps4/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(PS4_CC) $(COMMON_CPPFLAGS) -DPLATFORM_PS4=1 $(COMMON_CFLAGS) -c $< -o $@

$(BUILD_DIR)/ps4-lib/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(PS4_CC) $(COMMON_CPPFLAGS) -DPLATFORM_PS4=1 -DMEMDBG_NO_MAIN=1 $(COMMON_CFLAGS) -c $< -o $@

$(BUILD_DIR)/ps5/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(PS5_CC) $(COMMON_CPPFLAGS) -DPLATFORM_PS5=1 $(COMMON_CFLAGS) -c $< -o $@

$(BUILD_DIR)/ps5-lib/%.o: src/%.c
	@mkdir -p $(dir $@)
	$(PS5_CC) $(COMMON_CPPFLAGS) -DPLATFORM_PS5=1 -DMEMDBG_NO_MAIN=1 $(COMMON_CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
