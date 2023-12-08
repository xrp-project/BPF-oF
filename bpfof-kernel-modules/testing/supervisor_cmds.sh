export CLOUDLAB_PASSWORD=""
python3 bench_rocksdb_supervisor.py --cloudlab-experiment nvmeof-bench --transport tcp --debug
python3 bench_rocksdb_supervisor.py --cloudlab-experiment nvmeof-bench --transport tcp --db rocksdb_bloom --debug
python3 bench_rocksdb_supervisor.py --cloudlab-experiment nvmeof-bench --transport rdma --debug
python3 bench_rocksdb_supervisor.py --cloudlab-experiment nvmeof-bench --transport rdma --rdma-offload --debug
python3 bench_rocksdb_supervisor.py --cloudlab-experiment nvmeof-bench --transport local --debug

python3 bench_rocksdb_supervisor.py --cloudlab-experiment nvmeof-bench --transport tcp --db /nvme/rocksdb_trace_cluster41 --bench-script twitter_trace_1.sh --debug
python3 bench_rocksdb_supervisor.py --cloudlab-experiment nvmeof-bench --transport tcp --db /nvme/rocksdb_trace_cluster45 --bench-script twitter_trace_2.sh --debug
