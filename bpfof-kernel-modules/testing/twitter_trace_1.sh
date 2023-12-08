#!/bin/bash
set -euo pipefail

TRANSPORT="tcp"
DISK_TYPE="ssd"
RESULTS_DIR="/mydata/bpfof_results"

eval `ssh-agent`
ssh-add ~/.ssh/columbia_cloudlab_id

mkdir -p $RESULTS_DIR
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
TRACE="41"

TEST="bpfof_${TRANSPORT}_${DISK_TYPE}_twitter_trace_$TRACE.json"

# python3 "${DIR}"/bench_rocksdb.py \
#     --results-file="$RESULTS_DIR/$TEST" \
#     --cpu=3 \
#     --reuse-results \
#     --db-path=/nvme/rocksdb_trace_cluster"$TRACE" \
#     --bench-path=/mydata/My-YCSB/build/run_rocksdb \
#     --config-dir=/mydata/My-YCSB/rocksdb/config \
#     --disk-type=nvmeof_tcp \
#     --threads-per-core=24 \
#     --sample-rate=1,10 \
#     --runtime-seconds=600 \
#     --use-bpfof=True \
#     --bench-type=trace"$TRACE" \
#     --cache-size=5000000000 \
#     > /mydata/bench_rocksdb.log \
#     2>&1

# python3 "${DIR}"/bench_rocksdb.py \
#     --results-file="$RESULTS_DIR/$TEST" \
#     --cpu=3 \
#     --reuse-results \
#     --db-path=/nvme/rocksdb_trace_cluster"$TRACE" \
#     --bench-path=/mydata/My-YCSB/build/run_rocksdb \
#     --config-dir=/mydata/My-YCSB/rocksdb/config \
#     --disk-type=nvmeof_tcp \
#     --threads-per-core=24 \
#     --sample-rate=0,1 \
#     --runtime-seconds=600 \
#     --use-bpfof=True \
#     --bench-type=trace"$TRACE" \
#     --cache-size=0 \
#     > /mydata/bench_rocksdb.log \
#     2>&1


python3 "${DIR}"/bench_rocksdb.py \
    --results-file="$RESULTS_DIR/$TEST" \
    --cpu=3 \
    --reuse-results \
    --db-path=/nvme/rocksdb_trace_cluster"$TRACE" \
    --bench-path=/mydata/My-YCSB/build/run_rocksdb \
    --config-dir=/mydata/My-YCSB/rocksdb/config \
    --disk-type=nvmeof_tcp \
    --threads-per-core=24 \
    --sample-rate=1 \
    --runtime-seconds=120 \
    --use-bpfof=True \
    --bench-type=trace"$TRACE" \
    --cache-size=5000000000 \
    > /mydata/bench_rocksdb.log \
    2>&1

python3 "${DIR}"/bench_rocksdb.py \
    --results-file="$RESULTS_DIR/$TEST" \
    --cpu=3 \
    --reuse-results \
    --db-path=/nvme/rocksdb_trace_cluster"$TRACE" \
    --bench-path=/mydata/My-YCSB/build/run_rocksdb \
    --config-dir=/mydata/My-YCSB/rocksdb/config \
    --disk-type=nvmeof_tcp \
    --threads-per-core=24 \
    --sample-rate=1 \
    --runtime-seconds=120 \
    --use-bpfof=True \
    --bench-type=trace"$TRACE" \
    --cache-size=0 \
    > /mydata/bench_rocksdb.log \
    2>&1
