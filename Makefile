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
VERSION_FILE ?= $(CURDIR)/VERSION
MEMDBG_VERSION ?= $(shell sed -n '1{s/^[[:space:]]*//;s/[[:space:]]*$$//;s/^[vV]//;p;q;}' "$(VERSION_FILE)")
MEMDBG_VERSION_CORE := $(firstword $(subst -, ,$(MEMDBG_VERSION)))
MEMDBG_VERSION_PARTS := $(subst ., ,$(MEMDBG_VERSION_CORE))
MEMDBG_VERSION_MAJOR := $(or $(word 1,$(MEMDBG_VERSION_PARTS)),0)
MEMDBG_VERSION_MINOR := $(or $(word 2,$(MEMDBG_VERSION_PARTS)),0)
MEMDBG_VERSION_PATCH := $(or $(word 3,$(MEMDBG_VERSION_PARTS)),0)
GENERATED_INCLUDE_DIR := $(BUILD_DIR)/generated/include
GENERATED_VERSION_HEADER := $(GENERATED_INCLUDE_DIR)/memdbg/core/memdbg_version.h

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

COMMON_CPPFLAGS := -I$(GENERATED_INCLUDE_DIR) -Iinclude
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

.PHONY: all clean host payload-ps4 payload-ps4-lib payload-ps5 payload-ps5-lib deploy-ps4 deploy-ps5 frontend verify test test-aob-boundary test-process-aob-e2e test-debugger test-lz4 test-scan-partition test-tracer-daemon test-new-features check-locales check-headers tracer-tool FORCE

all: host

host: $(HOST_TARGET)

test-aob-boundary: $(BUILD_DIR)/host/scanner/engine/memdbg_scan.o $(BUILD_DIR)/host/scanner/scan_partition.o tests/test_aob_boundary.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_aob_boundary.c $(BUILD_DIR)/host/scanner/engine/memdbg_scan.o $(BUILD_DIR)/host/scanner/scan_partition.o -o $(BUILD_DIR)/test_aob_boundary
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

test-debugger: $(BUILD_DIR)/host/debug/session/memdbg_debugger.o tests/test_debugger.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_debugger.c $< -lpthread -o $(BUILD_DIR)/test_debugger
	@echo "--- Running Debugger test ---"
	$(BUILD_DIR)/test_debugger

test-debugger-e2e: host tests/test_debugger_e2e.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_debugger_e2e.c -o $(BUILD_DIR)/test_debugger_e2e
	@echo "--- Running Debugger E2E test ---"
	@tmpdir=$$(mktemp -d /tmp/memdbg-e2e-dbg.XXXXXX); \
	port=19121; \
	$(HOST_TARGET) --bind=127.0.0.1 --debug-port=$$port --udp-port=19124 --data-root=$$tmpdir --no-udp-log --no-replace-existing >$$tmpdir/payload.log 2>&1 & \
	pid=$$!; \
	trap 'kill -TERM $$pid 2>/dev/null || true; sleep 0.8; kill -KILL $$pid 2>/dev/null || true; wait $$pid 2>/dev/null || true; rm -rf $$tmpdir' EXIT; \
	sleep 0.6; \
	$(BUILD_DIR)/test_debugger_e2e 127.0.0.1 $$port

test-debugger-protocol: tests/test_debugger_protocol.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_debugger_protocol.c -o $(BUILD_DIR)/test_debugger_protocol
	@echo "--- Running Debugger Protocol test ---"
	$(BUILD_DIR)/test_debugger_protocol

test-lz4: src/pal/lz4.c include/memdbg/pal/lz4.h tests/test_lz4.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_lz4.c src/pal/lz4.c -o $(BUILD_DIR)/test_lz4
	@echo "--- Running LZ4 test ---"
	$(BUILD_DIR)/test_lz4

test-scan-partition: $(BUILD_DIR)/host/scanner/scan_partition.o tests/test_scan_partition.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) -Isrc $(HOST_CFLAGS) tests/test_scan_partition.c $< -o $(BUILD_DIR)/test_scan_partition
	@echo "--- Running Scan Partition test ---"
	$(BUILD_DIR)/test_scan_partition

test-tracer-daemon: src/tracer/memdbg_tracer_daemon.c tests/test_tracer_daemon.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_tracer_daemon.c src/tracer/memdbg_tracer_daemon.c -lpthread -o $(BUILD_DIR)/test_tracer_daemon
	@echo "--- Running Tracer daemon lifecycle test ---"
	$(BUILD_DIR)/test_tracer_daemon

test-new-features: tests/test_new_features.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) -Isrc/scanner $(HOST_CFLAGS) tests/test_new_features.c -o $(BUILD_DIR)/test_new_features
	@echo "--- Running New Features test ---"
	$(BUILD_DIR)/test_new_features

test: test-aob-boundary test-process-aob-e2e test-debugger test-debugger-e2e test-debugger-protocol test-lz4 test-scan-partition test-tracer-daemon test-new-features

payload-ps4: $(PS4_TARGET)
payload-ps5: $(PS5_TARGET)

payload-ps4-lib: $(PS4_LIB_TARGET)
payload-ps5-lib: $(PS5_LIB_TARGET)

deploy-ps4: $(PS4_TARGET)
	$(PS4_DEPLOY) -h $(PS4_HOST) -p $(PS4_PORT) $<

deploy-ps5: $(PS5_TARGET)
	$(PS5_DEPLOY) -h $(PS5_HOST) -p $(PS5_PORT) $<

TRACER_TOOL := $(BUILD_DIR)/tracer
TRACER_SOURCES := src/tracer/memdbg_tracer.c src/tracer/syscall_names.c src/pal/pal_debug.c

.PHONY: tracer-tool
tracer-tool: $(TRACER_TOOL)

$(TRACER_TOOL): tools/tracer/main.c $(TRACER_SOURCES) $(GENERATED_VERSION_HEADER)
	@mkdir -p $(dir $@)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) \
	  tools/tracer/main.c $(TRACER_SOURCES) $(HOST_LDLIBS) -o $@

frontend:
	cmake -S frontend -B $(BUILD_DIR)/frontend -DCMAKE_BUILD_TYPE=Release -DMEMDBG_RELEASE_VERSION="$(MEMDBG_VERSION)"
	cmake --build $(BUILD_DIR)/frontend -j4

check-locales:
	python3 tools/check_locales.py

check-headers:
	python3 tools/check_headers.py

verify:
	$(MAKE) clean
	$(MAKE) host
	$(MAKE) payload-ps4
	$(MAKE) payload-ps5

$(HOST_TARGET): $(HOST_OBJECTS)
	@mkdir -p $(dir $@)
	$(HOST_CC) $^ $(HOST_LDLIBS) -o $@

$(GENERATED_VERSION_HEADER): $(VERSION_FILE) FORCE
	@mkdir -p $(dir $@)
	@tmp="$@.tmp"; \
	{ \
	  printf '/*\n'; \
	  printf ' * memDBG - Generated project version header.\n'; \
	  printf ' * Copyright (C) 2026 SeregonWar\n'; \
	  printf ' * SPDX-License-Identifier: GPL-3.0-or-later\n'; \
	  printf ' */\n\n'; \
	  printf '#ifndef MEMDBG_CORE_MEMDBG_VERSION_H\n'; \
	  printf '#define MEMDBG_CORE_MEMDBG_VERSION_H\n\n'; \
	  printf '#define MEMDBG_VERSION_MAJOR %sU\n' "$(MEMDBG_VERSION_MAJOR)"; \
	  printf '#define MEMDBG_VERSION_MINOR %sU\n' "$(MEMDBG_VERSION_MINOR)"; \
	  printf '#define MEMDBG_VERSION_PATCH %sU\n' "$(MEMDBG_VERSION_PATCH)"; \
	  printf '#define MEMDBG_VERSION_STRING "%s"\n\n' "$(MEMDBG_VERSION)"; \
	  printf '#endif /* MEMDBG_CORE_MEMDBG_VERSION_H */\n'; \
	} > "$$tmp"; \
	if [ -f "$@" ] && cmp -s "$$tmp" "$@"; then rm "$$tmp"; else mv "$$tmp" "$@"; fi

$(BUILD_DIR)/host/%.o: src/%.c $(GENERATED_VERSION_HEADER)
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

$(BUILD_DIR)/ps4/%.o: src/%.c $(GENERATED_VERSION_HEADER)
	@mkdir -p $(dir $@)
	$(PS4_CC) $(COMMON_CPPFLAGS) -DPLATFORM_PS4=1 $(COMMON_CFLAGS) -c $< -o $@

$(BUILD_DIR)/ps4-lib/%.o: src/%.c $(GENERATED_VERSION_HEADER)
	@mkdir -p $(dir $@)
	$(PS4_CC) $(COMMON_CPPFLAGS) -DPLATFORM_PS4=1 -DMEMDBG_NO_MAIN=1 $(COMMON_CFLAGS) -c $< -o $@

$(BUILD_DIR)/ps5/%.o: src/%.c $(GENERATED_VERSION_HEADER)
	@mkdir -p $(dir $@)
	$(PS5_CC) $(COMMON_CPPFLAGS) -DPLATFORM_PS5=1 $(COMMON_CFLAGS) -c $< -o $@

$(BUILD_DIR)/ps5-lib/%.o: src/%.c $(GENERATED_VERSION_HEADER)
	@mkdir -p $(dir $@)
	$(PS5_CC) $(COMMON_CPPFLAGS) -DPLATFORM_PS5=1 -DMEMDBG_NO_MAIN=1 $(COMMON_CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
