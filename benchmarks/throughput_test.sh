#!/bin/bash
# SentinelFS Throughput Benchmark
# Reproduces Table I from the paper:
# "An Iterative Design Study in the Performance, Security, and Efficiency of User-Space Ransomware Detection"

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m' # No Color

# Test configuration
TEST_SIZE_MB=100
TEST_FILE_SIZE=$((TEST_SIZE_MB * 1024 * 1024))
TRIALS=5

echo "════════════════════════════════════════════════════════"
echo "  SentinelFS Throughput Benchmark"
echo "  Reproducing Table I from Research Paper"
echo "════════════════════════════════════════════════════════"
echo ""
echo "Test: 100MB File Copy (n=$TRIALS trials)"
echo ""

# Check if SentinelFS is mounted
MOUNT_POINT="/tmp/sentinelfs_bench_mount"
STORAGE_PATH="/tmp/sentinelfs_bench_storage"

if ! mountpoint -q "$MOUNT_POINT" 2>/dev/null; then
    echo -e "${YELLOW}Warning: $MOUNT_POINT is not mounted${NC}"
    echo ""
    echo "To run the full benchmark, first mount SentinelFS:"
    echo "  mkdir -p $STORAGE_PATH $MOUNT_POINT"
    echo "  ./sentinelfs $STORAGE_PATH $MOUNT_POINT &"
    echo ""
    read -p "Press Enter to run baseline test only, or Ctrl+C to abort..."
    SENTINELFS_ACTIVE=0
else
    SENTINELFS_ACTIVE=1
    echo -e "${GREEN}SentinelFS is mounted at $MOUNT_POINT${NC}"
    echo ""
fi

# Create test data
echo "Generating 100MB test file..."
TEST_DATA="/tmp/sentinelfs_testdata.bin"
dd if=/dev/zero of="$TEST_DATA" bs=1M count=$TEST_SIZE_MB 2>/dev/null
echo ""

#======================================================================
# Test 1: Baseline (Native Ext4)
#======================================================================
echo "-----------------------------------"
echo "Test 1: Native Ext4 (Baseline)"
echo "-----------------------------------"

BASELINE_DIR="/tmp/sentinelfs_baseline"
mkdir -p "$BASELINE_DIR"

total_time=0
for i in $(seq 1 $TRIALS); do
    rm -f "$BASELINE_DIR/test.bin"
    sync
    echo -n "  Trial $i/$TRIALS: "

    start=$(date +%s.%N)
    cp "$TEST_DATA" "$BASELINE_DIR/test.bin"
    sync
    end=$(date +%s.%N)

    elapsed=$(echo "$end - $start" | bc)
    throughput=$(echo "scale=2; $TEST_SIZE_MB / $elapsed" | bc)

    echo "${elapsed}s (${throughput} MB/s)"
    total_time=$(echo "$total_time + $elapsed" | bc)
done

baseline_avg=$(echo "scale=3; $total_time / $TRIALS" | bc)
baseline_throughput=$(echo "scale=2; $TEST_SIZE_MB / $baseline_avg" | bc)

echo ""
echo -e "${GREEN}Baseline Average: ${baseline_avg}s (~${baseline_throughput} MB/s)${NC}"
echo ""

#======================================================================
# Test 2: SentinelFS (Phase II/III)
#======================================================================
if [ $SENTINELFS_ACTIVE -eq 1 ]; then
    echo "-----------------------------------"
    echo "Test 2: SentinelFS (Phase III/IV)"
    echo "-----------------------------------"

    total_time=0
    for i in $(seq 1 $TRIALS); do
        rm -f "$MOUNT_POINT/test.bin"
        sync
        echo -n "  Trial $i/$TRIALS: "

        start=$(date +%s.%N)
        cp "$TEST_DATA" "$MOUNT_POINT/test.bin"
        sync
        end=$(date +%s.%N)

        elapsed=$(echo "$end - $start" | bc)
        throughput=$(echo "scale=2; $TEST_SIZE_MB / $elapsed" | bc)

        echo "${elapsed}s (${throughput} MB/s)"
        total_time=$(echo "$total_time + $elapsed" | bc)
    done

    sentinelfs_avg=$(echo "scale=3; $total_time / $TRIALS" | bc)
    sentinelfs_throughput=$(echo "scale=2; $TEST_SIZE_MB / $sentinelfs_avg" | bc)
    overhead=$(echo "scale=1; $sentinelfs_avg / $baseline_avg" | bc)

    echo ""
    echo -e "${GREEN}SentinelFS Average: ${sentinelfs_avg}s (~${sentinelfs_throughput} MB/s)${NC}"
    echo -e "${BLUE}Overhead: ${overhead}x${NC}"
    echo ""
fi

#======================================================================
# Summary Table (Table I from Paper)
#======================================================================
echo "════════════════════════════════════════════════════════"
echo "  Results Summary (Compare to Table I in Paper)"
echo "════════════════════════════════════════════════════════"
echo ""
printf "%-20s | %-10s | %-10s | %-12s\n" "Implementation" "Time (s)" "Overhead" "Throughput"
echo "-------------------------------------------------------------"
printf "%-20s | %-10s | %-10s | %-12s\n" "Native Ext4" "$baseline_avg" "1.0x" "~${baseline_throughput} MB/s"

if [ $SENTINELFS_ACTIVE -eq 1 ]; then
    printf "%-20s | %-10s | %-10s | %-12s\n" "SentinelFS (C)" "$sentinelfs_avg" "${overhead}x" "~${sentinelfs_throughput} MB/s"
fi

echo ""
echo "Paper Results (for comparison):"
echo "  Native Ext4:    0.089s  | 1.0x   | ~1.1 GB/s"
echo "  Phase I (Python): 2.937s  | 70.8x  | ~15.86 MB/s"
echo "  Phase II (C):    1.013s  | 11.4x  | ~98 MB/s"
echo ""
echo "Note: Actual performance depends on hardware, file system,"
echo "and system load. The key metric is the overhead ratio."
echo ""

#======================================================================
# IOPS Test (Table II from Paper)
#======================================================================
if [ $SENTINELFS_ACTIVE -eq 1 ] && command -v fio &> /dev/null; then
    echo "════════════════════════════════════════════════════════"
    echo "  FIO Stress Test (Table II from Paper)"
    echo "════════════════════════════════════════════════════════"
    echo ""
    echo "Running random write workload (4KB blocks, Queue Depth 16)..."
    echo ""

    fio --name=sentinelfs-iops \
        --directory="$MOUNT_POINT" \
        --rw=randwrite \
        --bs=4k \
        --ioengine=libaio \
        --iodepth=16 \
        --numjobs=1 \
        --size=50M \
        --runtime=30 \
        --time_based \
        --group_reporting \
        --output-format=normal | grep -E "(IOPS|lat.*avg)"

    echo ""
    echo "Paper Results (for comparison):"
    echo "  Sustained IOPS: 12,400 ops/sec"
    echo "  Average Latency: 1.28 ms"
    echo "  99th Percentile: 2.70 ms"
    echo ""
fi

# Cleanup
rm -f "$TEST_DATA"
rm -rf "$BASELINE_DIR"

echo "════════════════════════════════════════════════════════"
echo "  Benchmark Complete"
echo "════════════════════════════════════════════════════════"
