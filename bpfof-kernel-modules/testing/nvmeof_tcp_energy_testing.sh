#!/bin/bash
set -euo pipefail

TRANSPORT="tcp"
DISK_TYPE="ssd"
RESULTS_DIR="/mydata/bpfof_results"

eval `ssh-agent`
ssh-add ~/.ssh/columbia_cloudlab_id

mkdir -p $RESULTS_DIR
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"

TEST="bpfof_${TRANSPORT}_${DISK_TYPE}_ycsb.json"

# Indexes pinned, data cache 5GB
python3 "${DIR}"/bench_rocksdb.py \
    --results-file="$RESULTS_DIR/$TEST" \
    --cpu 3 \
    --db-path=/nvme/rocksdb \
    --bench-path=/mydata/My-YCSB/build/run_rocksdb \
    --config-dir=/mydata/My-YCSB/rocksdb/config \
    --temp-db-path=/nvme/rocksdb_temp \
    --disk-type=nvmeof_${TRANSPORT} \
    --threads-per-core=24 \
    --warmup-runtime-seconds=1 \
    --runtime-seconds=60 \
    --use-bpfof=True \
    --cache-size=5000000000 \
    --sample-rate=1,10 \
    --reuse-results \
    --measure-version-mismatches=True \
    --bench-type=uniform

# # Indexes pinned, no data cache
# python3 "${DIR}"/bench_rocksdb.py \
#     --results-file="$RESULTS_DIR/$TEST" \
#     --cpu 3 \
#     --db-path=/nvme/rocksdb \
#     --bench-path=/mydata/My-YCSB/build/run_rocksdb \
#     --config-dir=/mydata/My-YCSB/rocksdb/config \
#     --temp-db-path=/nvme/rocksdb_temp \
#     --disk-type=nvmeof_${TRANSPORT} \
#     --threads-per-core=24 \
#     --runtime-seconds=120 \
#     --use-bpfof=True \
#     --cache-size=0 \
#     --sample-rate=0 \
#     --reuse-results \
#     --measure-version-mismatches=True \
#     --bench_type=uniform \
#     > /mydata/bench_rocksdb.log \
#     2>&1

