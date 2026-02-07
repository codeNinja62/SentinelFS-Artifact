# SentinelFS Makefile
# Phase III/IV Ransomware Detection System
# Paper: "An Iterative Design Study in the Performance, Security, and Efficiency of User-Space Ransomware Detection"

CC = gcc
CFLAGS = -Wall -Wextra -O2 -D_FILE_OFFSET_BITS=64
LDFLAGS = -lm -lmagic
FUSE_FLAGS = $(shell pkg-config fuse3 --cflags --libs 2>/dev/null || pkg-config fuse --cflags --libs)

TARGET = sentinelfs
SRC_DIR = src
BUILD_DIR = build

SOURCES = $(wildcard $(SRC_DIR)/*.c)
OBJECTS = $(SOURCES:$(SRC_DIR)/%.c=$(BUILD_DIR)/%.o)

.PHONY: all clean test help

all: $(TARGET)

$(TARGET): $(OBJECTS)
	@echo "Linking $(TARGET)..."
	$(CC) $(CFLAGS) -o $@ $^ $(FUSE_FLAGS) $(LDFLAGS)
	@echo ""
	@echo "════════════════════════════════════════════"
	@echo " ✓ Build complete: ./$(TARGET)"
	@echo "════════════════════════════════════════════"
	@echo "Phase III/IV: Ransomware Detection System"
	@echo ""
	@echo "Performance (from paper):"
	@echo "  Throughput: ~98 MB/s (11.4x overhead)"
	@echo "  IOPS: 12,400 ops/sec"
	@echo "  Memory: 6.94 MB RSS"
	@echo "  CPU: 12.6% peak load"
	@echo ""
	@echo "Security:"
	@echo "  False Positives: 0% (1,000 binaries tested)"
	@echo "  Evasion Resistance: Header injection blocked"
	@echo "════════════════════════════════════════════"

$(BUILD_DIR)/%.o: $(SRC_DIR)/%.c | $(BUILD_DIR)
	@echo "Compiling $<..."
	$(CC) $(CFLAGS) $(FUSE_FLAGS) -c $< -o $@

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	@echo "Cleaning build artifacts..."
	rm -rf $(BUILD_DIR) $(TARGET)
	@echo "Clean complete."

test: $(TARGET)
	@echo "════════════════════════════════════════════"
	@echo " Running basic ransomware detection test"
	@echo "════════════════════════════════════════════"
	@echo ""
	@echo "This test validates that SentinelFS can:"
	@echo "  1. Allow low-entropy writes (normal files)"
	@echo "  2. Block high-entropy writes (encrypted data)"
	@echo ""
	@echo "Note: Requires FUSE to be available on the system"
	@echo ""
	@mkdir -p /tmp/sentinelfs_test_storage /tmp/sentinelfs_test_mount
	@echo "Starting SentinelFS in background..."
	@./$(TARGET) /tmp/sentinelfs_test_storage /tmp/sentinelfs_test_mount -f &
	@sleep 2
	@echo ""
	@echo "[Test 1] Writing normal text (should ALLOW):"
	@echo "Hello from SentinelFS" > /tmp/sentinelfs_test_mount/test.txt && echo "  ✓ Allowed (low entropy)" || echo "  ✗ Failed"
	@echo ""
	@echo "[Test 2] Writing encrypted data (should BLOCK):"
	@dd if=/dev/urandom of=/tmp/sentinelfs_test_mount/encrypted.bin bs=1024 count=1 2>/dev/null && echo "  ✗ Not blocked (bug!)" || echo "  ✓ Blocked (high entropy)"
	@echo ""
	@fusermount -u /tmp/sentinelfs_test_mount || umount /tmp/sentinelfs_test_mount
	@echo "Test complete!"

benchmark: $(TARGET)
	@echo "Running throughput benchmarks from paper..."
	@echo "(Reproduces Table I results)"
	@cd benchmarks && ./throughput_test.sh

help:
	@echo "SentinelFS Build System"
	@echo "Phase III/IV: Ransomware Detection"
	@echo ""
	@echo "Targets:"
	@echo "  all       - Build the SentinelFS binary (default)"
	@echo "  clean     - Remove build artifacts"
	@echo "  test      - Run basic ransomware detection tests"
	@echo "  benchmark - Run performance benchmarks (Table I from paper)"
	@echo "  help      - Show this help message"
	@echo ""
	@echo "Usage:"
	@echo "  make"
	@echo "  ./sentinelfs <storage_path> <mount_point>"
	@echo ""
	@echo "Example:"
	@echo "  mkdir -p /tmp/storage /tmp/mount"
	@echo "  ./sentinelfs /tmp/storage /tmp/mount"
