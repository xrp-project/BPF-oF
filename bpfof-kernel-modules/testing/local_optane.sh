#!/bin/bash
set -x
set -euo pipefail

TRANSPORT="local"
DISK_TYPE="optane"
RESULTS_DIR="/mydata/bpfof_results"

mkdir -p $RESULTS_DIR

###############################################################################
# YCSB ########################################################################
###############################################################################

TEST="bpfof_${TRANSPORT}_${DISK_TYPE}_ycsb.json"
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

# Indexes pinned, data cache 5GB
python3 "${DIR}"/bench_rocksdb.py \
    --results-file="$RESULTS_DIR/$TEST" \
    --cpu 3 \
    --db-path=/nvme/rocksdb \
    --bench-path=/mydata/My-YCSB/build/run_rocksdb \
    --config-dir=/mydata/My-YCSB/rocksdb/config \
    --temp-db-path=/nvme/rocksdb_temp \
    --disk-type=${TRANSPORT} \
    --threads-per-core=10 \
    --use-bpfof=False \
    --cache-size=5000000000,10000000000 \
    --sample-rate=1 \
    --reuse-results \
    --measure-version-mismatches=False \
    > /mydata/bench_rocksdb.log \
    2>&1

# Indexes pinned, no data cache
python3 "${DIR}"/bench_rocksdb.py \
    --results-file="$RESULTS_DIR/$TEST" \
    --cpu 3 \
    --db-path=/nvme/rocksdb \
    --bench-path=/mydata/My-YCSB/build/run_rocksdb \
    --config-dir=/mydata/My-YCSB/rocksdb/config \
    --temp-db-path=/nvme/rocksdb_temp \
    --disk-type=${TRANSPORT} \
    --threads-per-core=10 \
    --use-bpfof=False \
    --cache-size=0 \
    --sample-rate=1 \
    --reuse-results \
    --measure-version-mismatches=False \
    > /mydata/bench_rocksdb.log \
    2>&1

# Indexes not pinned, cache 5GB
python3 "${DIR}"/bench_rocksdb.py \
    --results-file="$RESULTS_DIR/$TEST" \
    --cpu 3 \
    --db-path=/nvme/rocksdb \
    --bench-path=/mydata/My-YCSB/build/run_rocksdb \
    --config-dir=/mydata/My-YCSB/rocksdb/config \
    --temp-db-path=/nvme/rocksdb_temp \
    --disk-type=${TRANSPORT} \
    --threads-per-core=10 \
    --use-bpfof=False \
    --cache-size=5000000000,10000000000 \
    --sample-rate=1 \
    --reuse-results \
    --pin-indexes=False \
    --measure-version-mismatches=False \
    > /mydata/bench_rocksdb.log \
    2>&1


###############################################################################
# Throughput - Latency ########################################################
###############################################################################


TEST="bpfof_${TRANSPORT}_${DISK_TYPE}_lat_thru.json"

# Indexes pinned, data cache 5GB
python3 "${DIR}"/bench_rocksdb.py \
    --results-file="$RESULTS_DIR/$TEST" \
    --cpu 3 \
    --db-path=/nvme/rocksdb \
    --bench-path=/mydata/My-YCSB/build/run_rocksdb \
    --config-dir=/mydata/My-YCSB/rocksdb/config \
    --temp-db-path=/nvme/rocksdb_temp \
    --disk-type=${TRANSPORT} \
    --threads-per-core=1,2,4,8,16,24,32 \
    --use-bpfof=False \
    --cache-size=5000000000,10000000000 \
    --sample-rate=1 \
    --reuse-results \
    --bench-type=uniform \
    --measure-version-mismatches=False \
    > /mydata/bench_rocksdb.log \
    2>&1

# Indexes pinned, no data cache
python3 "${DIR}"/bench_rocksdb.py \
    --results-file="$RESULTS_DIR/$TEST" \
    --cpu 3 \
    --db-path=/nvme/rocksdb \
    --bench-path=/mydata/My-YCSB/build/run_rocksdb \
    --config-dir=/mydata/My-YCSB/rocksdb/config \
    --temp-db-path=/nvme/rocksdb_temp \
    --disk-type=${TRANSPORT} \
    --threads-per-core=1,2,4,8,16,24,32 \
    --use-bpfof=False \
    --cache-size=0 \
    --sample-rate=1 \
    --reuse-results \
    --bench-type=uniform \
    --measure-version-mismatches=False \
    > /mydata/bench_rocksdb.log \
    2>&1

# Indexes not pinned
python3 "${DIR}"/bench_rocksdb.py \
    --results-file="$RESULTS_DIR/$TEST" \
    --cpu 3 \
    --db-path=/nvme/rocksdb \
    --bench-path=/mydata/My-YCSB/build/run_rocksdb \
    --config-dir=/mydata/My-YCSB/rocksdb/config \
    --temp-db-path=/nvme/rocksdb_temp \
    --disk-type=${TRANSPORT} \
    --threads-per-core=1,2,4,8,16,24,32 \
    --use-bpfof=False \
    --cache-size=5000000000,10000000000 \
    --sample-rate=1 \
    --reuse-results \
    --bench-type=uniform \
    --pin-indexes=False \
    --measure-version-mismatches=False \
    > /mydata/bench_rocksdb.log \
    2>&1

###############################################################################
# Sampling Experiment #########################################################
###############################################################################

TEST="bpfof_${TRANSPORT}_${DISK_TYPE}_sampling_experiment.json"


# Indexes pinned, data cache 5GB
python3 "${DIR}"/bench_rocksdb.py \
    --results-file="$RESULTS_DIR/$TEST" \
    --cpu 3 \
    --db-path=/nvme/rocksdb \
    --bench-path=/mydata/My-YCSB/build/run_rocksdb \
    --config-dir=/mydata/My-YCSB/rocksdb/config \
    --temp-db-path=/nvme/rocksdb_temp \
    --disk-type=${TRANSPORT} \
    --threads-per-core=10 \
    --use-bpfof=False \
    --cache-size=5000000000,10000000000 \
    --sample-rate=1 \
    --runtime-seconds=120 \
    --reuse-results \
    --measure-version-mismatches=False \
    > /mydata/bench_rocksdb.log \
    2>&1
