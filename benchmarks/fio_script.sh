#!/bin/bash
# SentinelFS Benchmark Script
# Reproduces the performance results from Table 1 in the paper

set -e

# Configuration
MOUNT_POINT="/tmp/sentinelfs_bench_mount"
STORAGE_PATH="/tmp/sentinelfs_bench_storage"
TEST_SIZE="1G"
RUNTIME=30

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo "========================================="
echo "  SentinelFS Performance Benchmark"
echo "  Reproducing Paper Results (Table 1)"
echo "========================================="
echo ""

# Check if FIO is installed
if ! command -v fio &> /dev/null; then
    echo -e "${RED}Error: FIO is not installed${NC}"
    echo "Install with: sudo apt-get install fio (Ubuntu/Debian)"
    echo "           or: sudo dnf install fio (Fedora/RHEL)"
    exit 1
fi

# Check if filesystem is mounted
if ! mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    echo -e "${YELLOW}Warning: $MOUNT_POINT is not mounted${NC}"
    echo "Please mount SentinelFS first:"
    echo "  mkdir -p $STORAGE_PATH $MOUNT_POINT"
    echo "  ./sentinelfs $STORAGE_PATH $MOUNT_POINT"
    echo ""
    read -p "Press Enter to continue with benchmark on regular filesystem..."
    MOUNT_POINT="."
fi

echo "Test Configuration:"
echo "  Target directory: $MOUNT_POINT"
echo "  Test size: $TEST_SIZE"
echo "  Runtime: ${RUNTIME}s per test"
echo ""

# Create test directory
TEST_DIR="$MOUNT_POINT/fio_test"
mkdir -p "$TEST_DIR"

echo "Running benchmarks (this will take several minutes)..."
echo ""

# Sequential Read Test
echo "-----------------------------------"
echo "Test 1/4: Sequential Read"
echo "-----------------------------------"
fio --name=seq-read \
    --directory="$TEST_DIR" \
    --rw=read \
    --bs=128k \
    --ioengine=libaio \
    --iodepth=16 \
    --numjobs=1 \
    --size=$TEST_SIZE \
    --runtime=$RUNTIME \
    --time_based \
    --group_reporting \
    --output-format=normal

echo ""

# Sequential Write Test
echo "-----------------------------------"
echo "Test 2/4: Sequential Write"
echo "-----------------------------------"
fio --name=seq-write \
    --directory="$TEST_DIR" \
    --rw=write \
    --bs=128k \
    --ioengine=libaio \
    --iodepth=16 \
    --numjobs=1 \
    --size=$TEST_SIZE \
    --runtime=$RUNTIME \
    --time_based \
    --group_reporting \
    --output-format=normal

echo ""

# Random Read Test (Key Performance Metric)
echo "-----------------------------------"
echo "Test 3/4: Random Read (Key Metric)"
echo "-----------------------------------"
fio --name=rand-read \
    --directory="$TEST_DIR" \
    --rw=randread \
    --bs=4k \
    --ioengine=libaio \
    --iodepth=16 \
    --numjobs=4 \
    --size=256M \
    --runtime=$RUNTIME \
    --time_based \
    --group_reporting \
    --output-format=normal

echo ""

# Random Write Test (Key Performance Metric)
echo "-----------------------------------"
echo "Test 4/4: Random Write (Key Metric)"
echo "-----------------------------------"
fio --name=rand-write \
    --directory="$TEST_DIR" \
    --rw=randwrite \
    --bs=4k \
    --ioengine=libaio \
    --iodepth=16 \
    --numjobs=4 \
    --size=256M \
    --runtime=$RUNTIME \
    --time_based \
    --group_reporting \
    --output-format=normal

echo ""
echo "========================================="
echo "  Benchmark Complete"
echo "========================================="
echo ""
echo "Paper Results (from Table 1):"
echo "  Sequential Read:  142 MB/s (98% of ext4)"
echo "  Sequential Write: 126 MB/s (98.5% of ext4)"
echo "  Random Read:      18.7 MB/s (+50.8% vs ext4)"
echo "  Random Write:     13.1 MB/s (+42.4% vs ext4)"
echo ""
echo "Note: Actual results depend on hardware, kernel version,"
echo "and system load. Random I/O should show the most improvement."
echo ""

# Cleanup
rm -rf "$TEST_DIR"
echo "Test files cleaned up."
