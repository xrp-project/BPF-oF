#!/bin/bash
set -euo pipefail

TRANSPORT="local"
DISK_TYPE="ssd"
RESULTS_DIR="/mydata/bpfof_results"

eval `ssh-agent`
ssh-add ~/.ssh/columbia_cloudlab_id

mkdir -p $RESULTS_DIR
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"


TEST="bpfof_${TRANSPORT}_${DISK_TYPE}_lat_thru.json"

# Indexes pinned, data cache 5GB
python3 "${DIR}"/bench_rocksdb.py \
    --results-file="$RESULTS_DIR/$TEST" \
    --cpu 3 \
    --db-path=/nvme/rocksdb \
    --bench-path=/mydata/My-YCSB/build/run_rocksdb \
    --config-dir=/mydata/My-YCSB/rocksdb/config \
    --temp-db-path=/nvme/rocksdb_temp \
    --disk-type=local \
    --threads-per-core=1,2,4,8,16,24,32 \
    --use-bpfof=True \
    --runtime-seconds=120 \
    --cache-size=5000000000 \
    --sample-rate=1 \
    --reuse-results \
    --bench-type=uniform \
    --measure-version-mismatches=True \
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
    --disk-type=local \
    --threads-per-core=1,2,4,8,16,24,32 \
    --use-bpfof=True \
    --cache-size=0 \
    --sample-rate=1 \
    --reuse-results \
    --bench-type=uniform \
    --measure-version-mismatches=True \
    > /mydata/bench_rocksdb.log \
    2>&1


TEST="bpfof_${TRANSPORT}_${DISK_TYPE}_ycsb.json"

# Indexes pinned, data cache 5GB
python3 "${DIR}"/bench_rocksdb.py \
    --results-file="$RESULTS_DIR/$TEST" \
    --cpu 3 \
    --db-path=/nvme/rocksdb \
    --bench-path=/mydata/My-YCSB/build/run_rocksdb \
    --config-dir=/mydata/My-YCSB/rocksdb/config \
    --temp-db-path=/nvme/rocksdb_temp \
    --disk-type=local \
    --threads-per-core=24 \
    --use-bpfof=True \
    --cache-size=1000000000,5000000000 \
    --sample-rate=1 \
    --reuse-results \
    --measure-version-mismatches=True \
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
    --disk-type=local \
    --threads-per-core=24 \
    --use-bpfof=True \
    --cache-size=0 \
    --sample-rate=1 \
    --reuse-results \
    --measure-version-mismatches=True \
    > /mydata/bench_rocksdb.log \
    2>&1


