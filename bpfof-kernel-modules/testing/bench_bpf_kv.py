#!/usr/bin/env python3

import os
import sys
import json
import time
import logging
import argparse

from typing import Dict, List
from subprocess import check_output


log = logging.getLogger(__name__)


class BenchResults:
    def __init__(self, results_dict: Dict) -> None:
        self.throughput_avg = results_dict["throughput_avg"]
        self.latency_avg = results_dict["latency_avg"]
        self.latency_p99 = results_dict["latency_p99"]
        self.latency_p999 = results_dict["latency_p999"]


class BenchRun:
    def __init__(self, config: Dict, results: BenchResults):
        self.config = config
        self.results = results

    def __eq__(self, other: object) -> bool:
        return self.config == other.config


def parse_results_file(results_file: str) -> List[BenchRun]:
    with open(results_file, "r") as f:
        results = json.load(f)
    return [BenchRun(r["config"], BenchResults(r["results"])) for r in results]


def exists_config_in_results(results: List[BenchRun], config: Dict) -> bool:
    for r in results:
        if r.config == config:
            return True
    return False


def parse_args():
    parser = argparse.ArgumentParser("Benchmark BPF-KV",
                                     formatter_class=argparse.ArgumentDefaultsHelpFormatter)
    subparsers = parser.add_subparsers(dest="subparser_name",
                                       help="sub-command help")

    parser_b = subparsers.add_parser("bench", help="bench help")
    parser_b.add_argument("--bpf-kv", type=str,
                          default="/mydata/BPF-KV/simplekv",
                          help="Path to BPF-KV binary")
    parser_b.add_argument("--workload", type=str, choices=["get", "range"],
                          help="Which workload to run")
    parser_b.add_argument("--results-file", type=str, default="results.json",
                          help="Path to results file (JSON format)")
    parser_b.add_argument("--runtime", type=int, default=60,
                          help="Runtime in seconds for each benchmark")
    parser_b.add_argument("--reuse-results", action="store_true",
                          default=False,
                          help="Reuse existing results and only calculate"
                               " missing results")
    parser_b.set_defaults(func=bench)

    parser_p = subparsers.add_parser("plot", help="plot help")
    parser_p.set_defaults(func=plot)

    # Add your arguments here
    return parser.parse_args()


def parse_bpf_kv_results(stdout: str) -> BenchResults:
    # Results are in the form of:
    # Average throughput: 29705.313842 op/s latency: 1611.140667 usec
    # 95%   latency: 2342.400000 us
    # 99%   latency: 2830.417300 us
    # 99.9% latency: 3521.595521 us
    # Percentage of requests with latency >= 1ms: 94.5595%
    for line in stdout.splitlines():
        line = line.strip()
        if line.startswith("Average throughput"):
            throughput_avg = float(line.split()[2])
            latency_avg = float(line.split()[5])
        elif line.startswith("95%"):
            latency_p95 = float(line.split()[2])
        elif line.startswith("99%"):
            latency_p99 = float(line.split()[2])
        elif line.startswith("99.9%"):
            latency_p999 = float(line.split()[2])
    return {
        "throughput_avg": throughput_avg,
        "latency_avg": latency_avg,
        "latency_p95": latency_p95,
        "latency_p99": latency_p99,
        "latency_p999": latency_p999,
    }


def add_config_option(name: str, values: List, configs: List[Dict]) -> List[Dict]:
    new_configs = []
    for config in configs:
        for value in values:
            new_config = config.copy()
            new_config[name] = value
            new_configs.append(new_config)
    return new_configs


def checkpoint_results(results_file: str, results: List[BenchRun]):
    with open(results_file, "w") as f:
        f.write(json.dumps(results, indent=4, default=lambda o: o.__dict__))


def bench(args):
    # Do not overwrite existing results
    results_file = args.results_file
    reuse_results = args.reuse_results
    runtime = args.runtime
    workload = args.workload

    i = 1
    results = []
    while os.path.exists(results_file):
        if reuse_results:
            log.info("Will reuse existing results file %s" % results_file)
            results = parse_results_file(results_file)
            break
        if "." in results_file:
            filename, ext = results_file.rsplit(".", 1)
            results_file = filename + "_%s." % i + ext
        else:
            results_file = results_file + "_%s" % i
    log.info("Will write results to %s" % results_file)

    configs = []
    for cpus in [1]:
        new_configs = [
            {
                "name": "BPF-KV",
                "cpus": cpus,
                "target_cpus": cpus,
            }
        ]
        new_configs = add_config_option("workload", [workload], new_configs)
        if workload == "get":
            new_configs = add_config_option("cache", [0, 3], new_configs)
        elif workload == "range":
            new_configs = add_config_option("range_size", [2, 8, 16, 32, 64],
                                            new_configs)
        else:
            raise ValueError("Unknown workload %s" % workload)

        new_configs = add_config_option("use_xrp", [True, False], new_configs)
        new_configs = add_config_option("threads", [cpus * i for i in [1, 2, 4, 8, 16, 32, 64, 96]], new_configs)
        new_configs = add_config_option("runtime", [runtime], new_configs)
        configs.extend(new_configs)

    bpf_kv = args.bpf_kv
    db_file = "/nvme/6-layer-db"
    for config in configs:
        if reuse_results and exists_config_in_results(results, config):
            log.info("Skipping config %s" % config)
            continue
        log.info("Running benchmark for %s with config %s" %
                 (config["name"], config))

        # Example command:
        # ./simplekv /nvme/6-layer-db 6 get --requests=10 --threads 1
        if config["workload"] == "get":
            cmd = [bpf_kv, db_file, "6", "get",
                   "--runtime", str(config["runtime"]),
                   "--threads", str(config["threads"]),
                   "--cache", str(config["cache"]),
                   "--requests", "1000000000",
                   "--pin-threads"]
        elif config["workload"] == "range":
            cmd = [bpf_kv, db_file, "6", "range",
                   "--runtime", str(config["runtime"]),
                   "--threads", str(config["threads"]),
                   "--range-size", str(config["range_size"]),
                   "--requests", "1000000000",
                   "--pin-threads"]
        else:
            raise Exception("Unknown workload %s" % config["workload"])

        # Limit CPUs
        cmd = ["taskset", "-c", "0-%s" % str(config["cpus"]-1)] + cmd

        if config["use_xrp"]:
            cmd.extend(["--use-xrp", "--bpf-fd", "-1234"])

        log.info("Running command: %s" % cmd)
        stdout = check_output(cmd, encoding="utf-8")

        # Save results
        log.info("Parsing results...")
        bench_run_results = parse_bpf_kv_results(stdout)
        bench_run = BenchRun(config, bench_run_results)
        results.append(bench_run)
        checkpoint_results(results_file, results)
        time.sleep(10)


def plot(args):
    print("Plotting code transferred to Jupyter Notebook in paper repo. Check"
          " check: https://github.com/yanniszark/nvmeof-xrp-paper")


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    args.func(args)


if __name__ == "__main__":
    sys.exit(main())
