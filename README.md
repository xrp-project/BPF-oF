# BPF-oF: Storage Function Pushdown Over the Network

This repository contains source code and instructions to reproduce key results
in the BPF-oF paper ([arxiv](https://arxiv.org/abs/2312.06808)). A draft of the paper is added to
this repository.

## Dependencies

- Linux 5.12.0 with BPF-oF changes:
  https://github.com/xrp-project/linux/tree/bpf-of
- RocksDB with BPF-oF changes:
  https://github.com/xrp-project/rocksdb/tree/bpf-of
- My-YCSB (benchmarking suite) with RocksDB support:
  https://github.com/xrp-project/My-YCSB/tree/bpf-of

## Requirements

You need a different type of machine depending on the benchmark you want to run:

| Configuration | Host Machine | Target Machine |
| - | - | - |
| TCP SSD | c6525-100g | c6525-100g |
| RDMA SSD | r6525 | r6525 |
| TCP Optane | c6525-100g | flex0{1-4} |

## Step 1: Get machines from CloudLab

**NOTE:** If machines were given to you, skip this skep.

1. To get machines from CloudLab, you need to create an experiment. A CloudLab
   experiment uses a profile as a template. Since BPF-oF uses specific profiles,
   you need to load them first. Go to CloudLab, click on Experiments -> Create Experiment Profile and create profile `nvmeof-bench` and profile `optane-plus-client`, located in folder `cloudlab-profiles`.

1. Create an experiment depending on the benchmarks you want to run:

    - For TCP SSD, use the `nvmeof-bench` profile.
    - For RDMA SSD, use the `nvmeof-bench` profile and change the machine type to `r6525`.
    - For TCP Optane, use the `optane-plus-client` profile.

1. Wait until CloudLab provisions the machines for the experiment.


## Step 2: Setup the machine

**TODO:** Add Ansible instructions.

## Step 3: Run benchmarks

**TODO:** Adapt the scripts to use this repo instead of the `phd` repo.

Running the benchmarks is a fully automated process.

```sh
TRANSPORT="tcp" # tcp | rdma | local
CLOUDLAB_EXPERIMENT="nvmeof-bench" # nvmeof-bench | optane-plus-client

python3 bench_rocksdb_supervisor.py \
    --cloudlab-experiment $CLOUDLAB_EXPERIMENT \
    --transport $TRANSPORT \
    --debug
```

## Step 4: Get results

For NVMe-oF:
```sh
REMOTE_USERNAME="..."
HOST_MACHINE="..."

scp -r $REMOTE_USERNAME@$HOST_MACHINE:/mydata/bpfof_results ~/
```

For local:
```sh
REMOTE_USERNAME="..."
TARGET_MACHINE="..."

scp -r $REMOTE_USERNAME@$TARGET_MACHINE:/mydata/bpfof_results ~/
```

## Step 5: Plot the results

**TODO:** Adapt python notebook.
