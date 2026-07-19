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

# Zydis x86-64 disassembler (cross-compiled for PS5 payload)
ZYDIS_DIR := $(CURDIR)/external/zydis
ZYCORE_DIR := $(ZYDIS_DIR)/dependencies/zycore
ZYDIS_SOURCES := $(wildcard $(ZYDIS_DIR)/src/*.c)
ZYCORE_SOURCES := $(wildcard $(ZYCORE_DIR)/src/*.c)
PS5_ZYDIS_OBJECTS := $(patsubst $(ZYDIS_DIR)/src/%.c,$(BUILD_DIR)/ps5-zydis/%.o,$(ZYDIS_SOURCES))
PS5_ZYCORE_OBJECTS := $(patsubst $(ZYCORE_DIR)/src/%.c,$(BUILD_DIR)/ps5-zycore/%.o,$(ZYCORE_SOURCES))
ZYDIS_PS5_CFLAGS := -I$(ZYDIS_DIR)/include -I$(ZYDIS_DIR)/src \
	-I$(ZYCORE_DIR)/include -I$(ZYCORE_DIR)/src \
	-DZYDIS_STATIC_BUILD -DZYCORE_STATIC_BUILD \
	-DZYDIS_DISABLE_FORMATTER -DZYDIS_DISABLE_ENCODER \
	-std=c11 -O2

# Keystone x86-64 assembler (pre-compiled for PS5).
# The pre-built libkeystone.a is large (~4 MiB) and not committed;
# the build degrades gracefully to MEMDBG_HAS_KEYSTONE=0 when absent.
KEYSTONE_DIR := $(CURDIR)/external/keystone
KEYSTONE_LIB := $(KEYSTONE_DIR)/lib/libkeystone.a
KEYSTONE_AVAILABLE := $(shell test -f '$(KEYSTONE_LIB)' && echo 1 || echo 0)
ifeq ($(KEYSTONE_AVAILABLE),1)
PS5_KEYSTONE_CPPFLAGS := -I$(KEYSTONE_DIR)/include -DMEMDBG_HAS_KEYSTONE=1
PS5_KEYSTONE_LDLIBS := $(KEYSTONE_LIB)
else
PS5_KEYSTONE_CPPFLAGS := -DMEMDBG_HAS_KEYSTONE=0
PS5_KEYSTONE_LDLIBS :=
endif

COMMON_CPPFLAGS := -I$(GENERATED_INCLUDE_DIR) -Iinclude -Isrc/core/daemon
COMMON_CFLAGS := -std=c11 -Wall -Wextra -Wpedantic -fstack-protector-strong -O2
HOST_CPPFLAGS := $(COMMON_CPPFLAGS) -D_DARWIN_C_SOURCE -D_POSIX_C_SOURCE=200809L -D_FORTIFY_SOURCE=2 -D_GLIBCXX_ASSERTIONS
HOST_CFLAGS := $(COMMON_CFLAGS) -Werror -Wconversion -Wshadow -Wformat=2
# Console (PS4/PS5) builds share the host's strictness where the SDK allows.
# CONSOLE_WERROR defaults to 1 (treat warnings as errors). Set to 0 to
# allow warnings from console SDK headers outside MemDBG's control.
CONSOLE_WERROR ?= 1
CONSOLE_CFLAGS := $(COMMON_CFLAGS) -Wconversion -Wshadow -Wformat=2
ifeq ($(CONSOLE_WERROR),1)
CONSOLE_WERROR_FLAG := -Werror
else
CONSOLE_WERROR_FLAG :=
endif

UNAME_S := $(shell uname -s)
ifeq ($(UNAME_S),Linux)
HOST_LDFLAGS := -Wl,-z,relro -Wl,-z,now
else ifeq ($(UNAME_S),Darwin)
HOST_LDFLAGS := -Wl,-bind_at_load
else
HOST_LDFLAGS :=
endif

HOST_LDLIBS := -lpthread

SOURCES := $(shell find src -name '*.c' | sort)
LIB_SOURCES := $(filter-out src/core/main.c,$(SOURCES))
HOST_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/host/%.o,$(SOURCES))
PS4_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/ps4/%.o,$(SOURCES))
PS4_LIB_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/ps4-lib/%.o,$(LIB_SOURCES))
PS5_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/ps5/%.o,$(SOURCES))
PS5_LIB_OBJECTS := $(patsubst src/%.c,$(BUILD_DIR)/ps5-lib/%.o,$(LIB_SOURCES))
ALL_DEPFILES := $(HOST_OBJECTS:.o=.d) $(PS4_OBJECTS:.o=.d) \
	$(PS4_LIB_OBJECTS:.o=.d) $(PS5_OBJECTS:.o=.d) \
	$(PS5_LIB_OBJECTS:.o=.d)

# Header dependency files are essential here: PAL structs cross translation
# unit boundaries. Without them an incremental payload build can link objects
# compiled against different layouts and trip the stack protector at runtime.
-include $(ALL_DEPFILES)

.PHONY: all clean host payload-ps4 payload-ps4-lib payload-ps5 payload-ps5-lib deploy-ps4 deploy-ps5 frontend verify test test-aob-boundary test-process-aob-e2e test-debugger test-memory test-process-map-metadata test-process-map-cache test-lz4 test-scan-partition test-scan-protocol test-tracer-daemon test-new-features test-sjson test-legacy-scanner-e2e test-legacy-process-e2e test-reconnect-state-machine check-locales check-headers tracer-tool FORCE

all: host

host: $(HOST_TARGET)

test-aob-boundary: $(BUILD_DIR)/host/scanner/memdbg_scan.o $(BUILD_DIR)/host/scanner/scan_partition.o tests/test_aob_boundary.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_aob_boundary.c $(BUILD_DIR)/host/scanner/memdbg_scan.o $(BUILD_DIR)/host/scanner/scan_partition.o $(HOST_LDFLAGS) -o $(BUILD_DIR)/test_aob_boundary
	@echo "--- Running AOB boundary test ---"
	$(BUILD_DIR)/test_aob_boundary

test-process-aob-e2e: host tests/test_process_aob_e2e.c tests/e2e_utils.c tests/e2e_utils.h
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_process_aob_e2e.c tests/e2e_utils.c $(HOST_LDFLAGS) -o $(BUILD_DIR)/test_process_aob_e2e
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
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_debugger.c $< $(HOST_LDFLAGS) -lpthread -o $(BUILD_DIR)/test_debugger
	@echo "--- Running Debugger test ---"
	$(BUILD_DIR)/test_debugger

test-memory: $(BUILD_DIR)/host/debug/memory/memdbg_memory.o tests/test_memory.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_memory.c $< $(HOST_LDFLAGS) -o $(BUILD_DIR)/test_memory
	@echo "--- Running Memory primitive test ---"
	$(BUILD_DIR)/test_memory

test-process-map-metadata: $(BUILD_DIR)/host/pal/pal_process.o tests/test_process_map_metadata.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_process_map_metadata.c $< $(HOST_LDFLAGS) -o $(BUILD_DIR)/test_process_map_metadata
	@echo "--- Running process map metadata test ---"
	$(BUILD_DIR)/test_process_map_metadata

test-process-map-cache: $(BUILD_DIR)/host/debug/process/memdbg_process.o tests/test_process_map_cache.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_process_map_cache.c $< $(HOST_LDFLAGS) $(HOST_LDLIBS) -o $(BUILD_DIR)/test_process_map_cache
	@echo "--- Running process map cache test ---"
	$(BUILD_DIR)/test_process_map_cache

test-debugger-e2e: host tests/test_debugger_e2e.c tests/e2e_utils.c tests/e2e_utils.h
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_debugger_e2e.c tests/e2e_utils.c $(HOST_LDFLAGS) -o $(BUILD_DIR)/test_debugger_e2e
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
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_debugger_protocol.c \
		src/core/daemon/handlers/debug.c src/core/daemon/handlers/process.c \
		$(HOST_LDFLAGS) -o $(BUILD_DIR)/test_debugger_protocol
	@echo "--- Running Debugger Protocol test ---"
	$(BUILD_DIR)/test_debugger_protocol

test-lz4: src/util/lz4.c include/memdbg/pal/lz4.h tests/test_lz4.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_lz4.c src/util/lz4.c $(HOST_LDFLAGS) -o $(BUILD_DIR)/test_lz4
	@echo "--- Running LZ4 test ---"
	$(BUILD_DIR)/test_lz4

test-benchmarks: src/scanner/scan_simd.c src/scanner/scan_partition.c src/util/lz4.c tests/test_benchmarks.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) -Isrc -Isrc/scanner $(HOST_CFLAGS) tests/test_benchmarks.c src/scanner/scan_simd.c src/scanner/scan_partition.c src/util/lz4.c $(HOST_LDFLAGS) -o $(BUILD_DIR)/test_benchmarks
	@echo "--- Running Benchmarks ---"
	$(BUILD_DIR)/test_benchmarks

test-zero-copy: src/util/lz4.c tests/test_zero_copy.c tests/bench_utils.h
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) -Isrc $(HOST_CFLAGS) tests/test_zero_copy.c src/util/lz4.c $(HOST_LDFLAGS) -o $(BUILD_DIR)/test_zero_copy
	@echo "--- Running Zero-Copy Benchmarks ---"
	$(BUILD_DIR)/test_zero_copy

test-thread-pool: tests/test_thread_pool.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_thread_pool.c $(HOST_LDFLAGS) $(HOST_LDLIBS) -o $(BUILD_DIR)/test_thread_pool
	@echo "--- Running Dynamic Thread Pool test ---"
	$(BUILD_DIR)/test_thread_pool

test-max-connections-e2e: host tests/test_max_connections_e2e.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_max_connections_e2e.c $(HOST_LDFLAGS) $(HOST_LDLIBS) -o $(BUILD_DIR)/test_max_connections_e2e
	@echo "--- Running E2E max_connections cap test ---"
	@tmpdir=$$(mktemp -d /tmp/memdbg-e2e-maxconn.XXXXXX); \
	port=19128; \
	$(HOST_TARGET) --bind=127.0.0.1 --debug-port=$$port --udp-port=19135 --data-root=$$tmpdir --no-udp-log --no-replace-existing --max-connections=4 >$$tmpdir/payload.log 2>&1 & \
	pid=$$!; \
	trap 'kill -TERM $$pid 2>/dev/null || true; sleep 0.8; kill -KILL $$pid 2>/dev/null || true; wait $$pid 2>/dev/null || true; rm -rf $$tmpdir' EXIT; \
	sleep 0.6; \
	rc=0; $(BUILD_DIR)/test_max_connections_e2e 127.0.0.1 $$port 4 || rc=$$?; \
	notify_count=$$(grep -c 'notify: MemDBG .* connected' $$tmpdir/payload.log || true); \
	echo "  session notifications = $$notify_count (expected 1)"; \
	if [ "$$notify_count" -ne 1 ]; then rc=1; fi; \
	exit $$rc

test-idle-timeout-unit: tests/test_idle_timeout_unit.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_idle_timeout_unit.c $(HOST_LDFLAGS) $(HOST_LDLIBS) -o $(BUILD_DIR)/test_idle_timeout_unit
	@echo "--- Running Idle Timeout unit test ---"
	$(BUILD_DIR)/test_idle_timeout_unit

test-kqueue-timeout: $(BUILD_DIR)/host/pal/pal_wait.o tests/test_kqueue_timeout.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_kqueue_timeout.c $(BUILD_DIR)/host/pal/pal_wait.o $(HOST_LDFLAGS) $(HOST_LDLIBS) -o $(BUILD_DIR)/test_kqueue_timeout
	@echo "--- Running kqueue timeout precision test ---"
	$(BUILD_DIR)/test_kqueue_timeout

test-connection-throughput: host tests/test_connection_throughput.c tests/bench_utils.h
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) -Isrc $(HOST_CFLAGS) tests/test_connection_throughput.c $(HOST_LDFLAGS) $(HOST_LDLIBS) -o $(BUILD_DIR)/test_connection_throughput
	@echo "--- Running Connection Throughput Benchmarks ---"
	$(BUILD_DIR)/test_connection_throughput

test-idle-timeout-e2e: host tests/test_idle_timeout_e2e.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_idle_timeout_e2e.c $(HOST_LDFLAGS) $(HOST_LDLIBS) -o $(BUILD_DIR)/test_idle_timeout_e2e
	@echo "--- Running E2E idle timeout test ---"
	@tmpdir=$$(mktemp -d /tmp/memdbg-e2e-idle.XXXXXX); \
	port=19136; \
	$(HOST_TARGET) --bind=127.0.0.1 --debug-port=$$port --udp-port=19137 --data-root=$$tmpdir --no-udp-log --no-replace-existing --idle-timeout=3000 >$$tmpdir/payload.log 2>&1 & \
	pid=$$!; \
	trap 'kill -TERM $$pid 2>/dev/null || true; sleep 0.8; kill -KILL $$pid 2>/dev/null || true; wait $$pid 2>/dev/null || true; rm -rf $$tmpdir' EXIT; \
	sleep 0.6; \
	$(BUILD_DIR)/test_idle_timeout_e2e 127.0.0.1 $$port 3000

test-reconnect-e2e: host tests/test_reconnect_e2e.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_reconnect_e2e.c $(HOST_LDFLAGS) $(HOST_LDLIBS) -o $(BUILD_DIR)/test_reconnect_e2e
	@echo "--- Running E2E reconnect resilience test ---"
	@tmpdir=$$(mktemp -d /tmp/memdbg-e2e-reconnect.XXXXXX); \
	port=19140; \
	$(BUILD_DIR)/test_reconnect_e2e 127.0.0.1 $$port \
		$(HOST_TARGET) --bind=127.0.0.1 --debug-port=$$port --data-root=$$tmpdir --no-udp-log --no-replace-existing; \
	rc=$$?; \
	rm -rf $$tmpdir; \
	exit $$rc

test-reconnect-state-machine: host tests/test_reconnect_state_machine.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_reconnect_state_machine.c $(HOST_LDFLAGS) $(HOST_LDLIBS) -o $(BUILD_DIR)/test_reconnect_state_machine
	@echo "--- Running Reconnect State Machine test ---"
	@tmpdir=$$(mktemp -d /tmp/memdbg-e2e-sm.XXXXXX); \
	port=19142; \
	$(BUILD_DIR)/test_reconnect_state_machine 127.0.0.1 $$port \
		$(HOST_TARGET) --bind=127.0.0.1 --debug-port=$$port --data-root=$$tmpdir --no-udp-log --no-replace-existing; \
	rc=$$?; \
	rm -rf $$tmpdir; \
	exit $$rc

test-scan-partition: $(BUILD_DIR)/host/scanner/scan_partition.o tests/test_scan_partition.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) -Isrc $(HOST_CFLAGS) tests/test_scan_partition.c $< $(HOST_LDFLAGS) -o $(BUILD_DIR)/test_scan_partition
	@echo "--- Running Scan Partition test ---"
	$(BUILD_DIR)/test_scan_partition

test-scan-protocol: tests/test_scan_protocol.c src/scanner/scan_request.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_scan_protocol.c \
		src/scanner/scan_request.c $(HOST_LDFLAGS) -o $(BUILD_DIR)/test_scan_protocol
	@echo "--- Running Scan Protocol test ---"
	$(BUILD_DIR)/test_scan_protocol

test-tracer-daemon: src/tracer/memdbg_tracer_daemon.c tests/test_tracer_daemon.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_tracer_daemon.c src/tracer/memdbg_tracer_daemon.c $(HOST_LDFLAGS) -lpthread -o $(BUILD_DIR)/test_tracer_daemon
	@echo "--- Running Tracer daemon lifecycle test ---"
	$(BUILD_DIR)/test_tracer_daemon

test-sjson: tests/test_sjson.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_sjson.c $(HOST_LDFLAGS) -o $(BUILD_DIR)/test_sjson
	@echo "--- Running sJson unit tests ---"
	$(BUILD_DIR)/test_sjson

test-new-features: tests/test_new_features.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) -Isrc/scanner $(HOST_CFLAGS) tests/test_new_features.c $(HOST_LDFLAGS) -o $(BUILD_DIR)/test_new_features
	@echo "--- Running New Features test ---"
	$(BUILD_DIR)/test_new_features

test-legacy-scanner-e2e: host tests/test_legacy_scanner_e2e.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_legacy_scanner_e2e.c $(HOST_LDFLAGS) -o $(BUILD_DIR)/test_legacy_scanner_e2e
	@echo "--- Running Legacy Scanner E2E test ---"
	@tmpdir=$$(mktemp -d /tmp/memdbg-e2e-scan.XXXXXX); \
	legacy_port=19130; \
	$(HOST_TARGET) --bind=127.0.0.1 --debug-port=19129 --legacy-compat --legacy-port=$$legacy_port --udp-port=19131 --data-root=$$tmpdir --no-udp-log --no-replace-existing >$$tmpdir/payload.log 2>&1 & \
	pid=$$!; \
	trap 'kill -TERM $$pid 2>/dev/null || true; sleep 0.8; kill -KILL $$pid 2>/dev/null || true; wait $$pid 2>/dev/null || true; rm -rf $$tmpdir' EXIT; \
	sleep 0.6; \
	$(BUILD_DIR)/test_legacy_scanner_e2e 127.0.0.1 $$legacy_port

test-legacy-process-e2e: host tests/test_legacy_process_e2e.c
	@mkdir -p $(BUILD_DIR)
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) tests/test_legacy_process_e2e.c $(HOST_LDFLAGS) -o $(BUILD_DIR)/test_legacy_process_e2e
	@echo "--- Running Legacy Process/Memory E2E test ---"
	@tmpdir=$$(mktemp -d /tmp/memdbg-e2e-proc.XXXXXX); \
	legacy_port=19132; \
	$(HOST_TARGET) --bind=127.0.0.1 --debug-port=19133 --legacy-compat --legacy-port=$$legacy_port --udp-port=19134 --data-root=$$tmpdir --no-udp-log --no-replace-existing >$$tmpdir/payload.log 2>&1 & \
	pid=$$!; \
	trap 'kill -TERM $$pid 2>/dev/null || true; sleep 0.8; kill -KILL $$pid 2>/dev/null || true; wait $$pid 2>/dev/null || true; rm -rf $$tmpdir' EXIT; \
	sleep 0.6; \
	$(BUILD_DIR)/test_legacy_process_e2e 127.0.0.1 $$legacy_port

test: test-aob-boundary test-process-aob-e2e test-debugger test-memory test-process-map-metadata test-process-map-cache test-debugger-e2e test-debugger-protocol test-lz4 test-scan-partition test-scan-protocol test-tracer-daemon test-new-features test-sjson test-legacy-scanner-e2e test-legacy-process-e2e test-thread-pool test-max-connections-e2e test-idle-timeout-e2e test-idle-timeout-unit test-kqueue-timeout test-reconnect-e2e test-reconnect-state-machine

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
	  tools/tracer/main.c $(TRACER_SOURCES) $(HOST_LDFLAGS) $(HOST_LDLIBS) -o $@

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

# ---- Sanitizer targets (use system clang, not HOST_CC) ----
SAN_CPPFLAGS := -I$(GENERATED_INCLUDE_DIR) -Iinclude -Isrc/core/daemon -D_DARWIN_C_SOURCE -D_POSIX_C_SOURCE=200809L

host-asan:
	$(MAKE) clean
	$(MAKE) host HOST_CC=clang \
		HOST_CPPFLAGS="$(SAN_CPPFLAGS)" \
		HOST_CFLAGS="-std=c11 -Wall -Wextra -Wpedantic -O1 -g -fsanitize=address -fno-omit-frame-pointer" \
		HOST_LDFLAGS="-fsanitize=address"
	@echo "Built with AddressSanitizer. Run with: ASAN_OPTIONS=detect_leaks=1 ./build/MemDBG-host"

host-ubsan:
	$(MAKE) clean
	$(MAKE) host HOST_CC=clang \
		HOST_CPPFLAGS="$(SAN_CPPFLAGS)" \
		HOST_CFLAGS="-std=c11 -Wall -Wextra -Wpedantic -O1 -g -fsanitize=undefined -fno-sanitize-recover=all"
	@echo "Built with UBSan. Run with: UBSAN_OPTIONS=halt_on_error=1 ./build/MemDBG-host"

host-tsan:
	$(MAKE) clean
	$(MAKE) host HOST_CC=clang \
		HOST_CPPFLAGS="$(SAN_CPPFLAGS)" \
		HOST_CFLAGS="-std=c11 -Wall -Wextra -Wpedantic -O1 -g -fsanitize=thread" \
		HOST_LDFLAGS="-fsanitize=thread"
	@echo "Built with ThreadSanitizer. Run with: TSAN_OPTIONS=history_size=7 ./build/MemDBG-host"

$(HOST_TARGET): $(HOST_OBJECTS)
	@mkdir -p $(dir $@)
	$(HOST_CC) $^ $(HOST_LDFLAGS) $(HOST_LDLIBS) -o $@

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
	$(HOST_CC) $(HOST_CPPFLAGS) $(HOST_CFLAGS) -MMD -MP -MF $(@:.o=.d) -c $< -o $@

$(PS4_TARGET): $(PS4_OBJECTS)
	@mkdir -p $(dir $@)
	$(PS4_CC) $^ -lpthread -o $@

$(PS4_LIB_TARGET): $(PS4_LIB_OBJECTS)
	@mkdir -p $(dir $@)
	$(PS4_AR) rcs $@ $^

$(PS5_TARGET): $(PS5_OBJECTS) $(PS5_ZYDIS_OBJECTS) $(PS5_ZYCORE_OBJECTS)
	@mkdir -p $(dir $@)
	$(PS5_CC) $^ $(PS5_KEYSTONE_LDLIBS) -lpthread -lunwind -lc++ -lc++abi -o $@

$(PS5_LIB_TARGET): $(PS5_LIB_OBJECTS)
	@mkdir -p $(dir $@)
	$(PS5_AR) rcs $@ $^

$(BUILD_DIR)/ps4/%.o: src/%.c $(GENERATED_VERSION_HEADER)
	@mkdir -p $(dir $@)
	$(PS4_CC) $(COMMON_CPPFLAGS) -DPLATFORM_PS4=1 $(CONSOLE_WERROR_FLAG) $(CONSOLE_CFLAGS) -MMD -MP -MF $(@:.o=.d) -c $< -o $@

$(BUILD_DIR)/ps4-lib/%.o: src/%.c $(GENERATED_VERSION_HEADER)
	@mkdir -p $(dir $@)
	$(PS4_CC) $(COMMON_CPPFLAGS) -DPLATFORM_PS4=1 -DMEMDBG_NO_MAIN=1 $(CONSOLE_WERROR_FLAG) $(CONSOLE_CFLAGS) -MMD -MP -MF $(@:.o=.d) -c $< -o $@

$(BUILD_DIR)/ps5/%.o: src/%.c $(GENERATED_VERSION_HEADER)
	@mkdir -p $(dir $@)
	$(PS5_CC) $(COMMON_CPPFLAGS) -I$(ZYDIS_DIR)/include -I$(ZYCORE_DIR)/include $(PS5_KEYSTONE_CPPFLAGS) -DPLATFORM_PS5=1 -DMEMDBG_HAS_ZYDIS=1 -mavx2 $(CONSOLE_WERROR_FLAG) $(CONSOLE_CFLAGS) -MMD -MP -MF $(@:.o=.d) -c $< -o $@

$(BUILD_DIR)/ps5-lib/%.o: src/%.c $(GENERATED_VERSION_HEADER)
	@mkdir -p $(dir $@)
	$(PS5_CC) $(COMMON_CPPFLAGS) -I$(ZYDIS_DIR)/include -I$(ZYCORE_DIR)/include $(PS5_KEYSTONE_CPPFLAGS) -DPLATFORM_PS5=1 -DMEMDBG_NO_MAIN=1 -DMEMDBG_HAS_ZYDIS=1 -mavx2 $(CONSOLE_WERROR_FLAG) $(CONSOLE_CFLAGS) -MMD -MP -MF $(@:.o=.d) -c $< -o $@

# Zydis disassembler objects (cross-compiled for PS5)
$(BUILD_DIR)/ps5-zydis/%.o: $(ZYDIS_DIR)/src/%.c
	@mkdir -p $(dir $@)
	$(PS5_CC) $(ZYDIS_PS5_CFLAGS) -c $< -o $@

$(BUILD_DIR)/ps5-zycore/%.o: $(ZYCORE_DIR)/src/%.c
	@mkdir -p $(dir $@)
	$(PS5_CC) $(ZYDIS_PS5_CFLAGS) -c $< -o $@

clean:
	rm -rf $(BUILD_DIR)
