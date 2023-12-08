#!/usr/bin/env python3

import os
import re
import sys
import json
import time
import json
import copy
import fabric
import shutil
import pickle
import psutil
import logging
import resource
import argparse
import configparser

from time import sleep
from ruamel.yaml import YAML
from typing import Dict, List
from abc import ABC, abstractmethod
from subprocess import check_output, CalledProcessError
from yanniszark_common.cmdutils import run

log = logging.getLogger(__name__)

##########################
# Benchmarking framework #
##########################


class ToJSONEncoder(json.JSONEncoder):
    def default(self, obj):
        if hasattr(obj, "to_json"):
            return obj.to_json()
        return json.JSONEncoder.default(self, obj)


class BenchResults:
    def __init__(self, results: Dict) -> None:
        self.results = results

    def to_json(self):
        return self.__dict__

    @classmethod
    def from_json(cls, json_dict: Dict):
        return cls(json_dict)


class BenchRun:
    def __init__(self, config: Dict, results: BenchResults):
        self.config = config
        self.results = results

    def __eq__(self, other: object) -> bool:
        return self.config == other.config

    def to_json(self):
        return self.__dict__


def parse_results_file(results_file: str, benchresults_cls) -> BenchRun:
    with open(results_file, "r") as f:
        results = json.load(f)
    return [BenchRun(r["config"], benchresults_cls.from_json(r["results"])) for r in results]


def exists_config_in_results(results: List[BenchRun], config: Dict) -> bool:
    for r in results:
        if r.config == config:
            return True
    return False


def single_result_select(results: List[BenchRun], config_match: Dict) -> BenchRun:
    # Select results based on partial config match
    matches = [r for r in results
               if config_match.items() <= r.config.items()]
    if len(matches) != 1:
        raise Exception("Expected exactly one match, got %s for config_match"
                        " %s" % (len(matches), config_match))
    return matches[0]


def add_config_option(name: str, values: List, configs: List[Dict]) -> List[Dict]:
    new_configs = []
    for config in configs:
        for value in values:
            new_config = config.copy()
            new_config[name] = value
            new_configs.append(new_config)
    return new_configs


def unique_configs_for_keys(configs: List[Dict], keys: List[str]) -> List[Dict]:
    # Return the unique configs for the given keys
    unique_configs = []
    for config in configs:
        unique_config = {}
        for key in keys:
            unique_config[key] = config[key]
        if unique_config not in unique_configs:
            unique_configs.append(unique_config)
    return unique_configs


def checkpoint_results(results_file: str, results: BenchRun):
    temp_results_file = results_file + ".tmp"
    with open(temp_results_file, "w") as f:
        f.write(json.dumps(results, cls=ToJSONEncoder, indent=4))
    os.rename(temp_results_file, results_file)


class BenchmarkFramework(ABC):
    """Simple benchmarking framework.

    Subclass it to implement a benchmark. You need to implement the abstract
    methods."""

    def __init__(self, name: str, benchresults_cls=BenchResults,
                 cli_args=None):
        self.name = name
        self.benchresults_cls = benchresults_cls
        self.args = cli_args

    def benchmark_prepare(self, config):
        pass

    @abstractmethod
    def benchmark_cmd(self, config):
        raise NotImplementedError

    def cmd_extra_envs(self, config):
        return {}

    def before_benchmark(self, config):
        pass

    def after_benchmark(self, config):
        pass

    @abstractmethod
    def parse_results(self, stdout: str) -> BenchRun:
        raise NotImplementedError

    @abstractmethod
    def add_arguments(self, parser: argparse.ArgumentParser):
        raise NotImplementedError

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        return configs

    def parse_args(self):
        parser = argparse.ArgumentParser("Benchmark %s" % self.name,
                                         formatter_class=argparse.ArgumentDefaultsHelpFormatter)
        parser.add_argument("--cpu", type=str, default="1",
                            help="Number of CPUs to use. Can be a value, a"
                                 " range, or a list of comma-separated values"
                                 " and ranges")
        parser.add_argument("--results-file", type=str, default="results.json",
                            help="Path to results file (JSON format)")
        # parser.add_argument("--runtime", type=int, default=60,
        #                     help="Runtime in seconds for each benchmark")
        parser.add_argument("--reuse-results", action="store_true",
                            default=False,
                            help="Reuse existing results and only calculate"
                            " missing results")
        parser.add_argument("--debug-segfault", action="store_true",
                            default=False, help="Debug segfaults")
        self.add_arguments(parser)
        return parser.parse_args()

    def benchmark(self):
        if not self.args:
            args = self.parse_args()
            self.args = args
        results_file = self.args.results_file
        reuse_results = self.args.reuse_results
        cpu_str = self.args.cpu

        # Parse CPU string
        cpu_amounts = parse_numbers_string(cpu_str)
        log.info("Will benchmark with each of the following amounts of CPU %s"
                 % cpu_amounts)

        i = 1
        results = []
        while os.path.exists(results_file):
            if reuse_results:
                log.info("Will reuse existing results file %s" % results_file)
                results = parse_results_file(
                    results_file, self.benchresults_cls)
                break
            if "." in results_file:
                filename, ext = results_file.rsplit(".", 1)
                results_file = filename + "_%s." % i + ext
            else:
                results_file = results_file + "_%s" % i
        log.info("Will write results to %s" % results_file)

        all_configs = []
        for cpus in cpu_amounts:
            new_configs = [
                {
                    "name": self.name,
                    "cpus": cpus,
                    "target_cpus": cpus,
                }
            ]
            new_configs = self.generate_configs(new_configs)
            all_configs.extend(new_configs)

        configs_to_run = []
        for config in all_configs:
            if reuse_results and exists_config_in_results(results, config):
                log.info("Skipping config %s" % config)
            else:
                configs_to_run.append(config)

        for idx, config in enumerate(configs_to_run):
            log.info("Progress: %.1f%% (%s/%s)" %
                     ((idx+1) / len(configs_to_run)*100, idx+1,
                      len(configs_to_run)))
            log.info("Running benchmark for %s with config %s" %
                     (config["name"], config))

            # Prepare environment for benchmarking
            self.benchmark_prepare(config)

            # Run benchmark
            cmd = self.benchmark_cmd(config)

            # Limit CPUs
            cmd = ["taskset", "-c", "0-%s" % str(config["cpus"]-1)] + cmd

            log.info("Running command: %s" % cmd)
            env = os.environ
            if self.args.debug_segfault:
                env["SEGFAULT_SIGNALS"] = "abrt segv"
                env["LD_PRELOAD"] = "/usr/lib/x86_64-linux-gnu/libSegFault.so"
            extra_envs = self.cmd_extra_envs(config)
            if extra_envs:
                log.info("Adding extra envs: %s" % extra_envs)
            env.update(extra_envs)
            self.before_benchmark(config)
            try:
                stdout = check_output(cmd, encoding="utf-8", env=env)
            except CalledProcessError as e:
                log.error("Benchmark failed with error code %s" % e.returncode)
                log.error("Output was: %s" % e.output)
                raise e

            self.after_benchmark(config)
            # Save results
            log.info("Parsing results...")
            bench_run_results = self.parse_results(stdout)
            bench_run = BenchRun(config, bench_run_results)
            results.append(bench_run)
            checkpoint_results(results_file, results)
            time.sleep(5)
        all_results = []
        for config in all_configs:
            all_results.append(single_result_select(results, config))
        return all_results

###############################################################################

###############################
# RocksDB Benchmark Framework #
###############################

# Context manager for editing a yaml file
class YAMLEditor:
    def __init__(self, path: str):
        self.path = path
        self.yaml = None

    def __enter__(self):
        with open(self.path, "r") as f:
            self.yaml = YAML().load(f)
        return self

    def __exit__(self, *exc):
        with open(self.path, "w") as f:
            YAML().dump(self.yaml, f)


class INIEditor:
    def __init__(self, path: str) -> None:
        self.path = path
        self.ini = None

    def __enter__(self):
        self.ini = configparser.ConfigParser()
        self.ini.optionxform = str
        self.ini.read(self.path)
        return self

    def __exit__(self, *exc):
        with open(self.path, "w") as f:
            self.ini.write(f)

class RocksDBBenchResults(BenchResults):
    def __init__(self, results: Dict) -> None:
        self.throughput_avg = results["throughput_avg"]
        self.latency_avg = results["latency_avg"]
        self.latency_p99 = results["latency_p99"]
        throughput_keys = ["read_throughput_avg", "insert_throughput_avg",
                           "update_throughput_avg", "scan_throughput_avg",
                           "read_modify_write_throughput_avg", "keys_failed"]
        latency_keys = ["read_latency_avg", "insert_latency_avg",
                        "update_latency_avg", "scan_latency_avg",
                        "read_modify_write_latency_avg", "read_latency_p99",
                        "insert_latency_p99", "update_latency_p99",
                        "scan_latency_p99", "read_modify_write_latency_p99"]
        for key in throughput_keys + latency_keys:
            if key in results:
                setattr(self, key, results[key])
            else:
                setattr(self, key, 0)
        self.stats = results.get("stats")
        for key in ["bytes_sent", "bytes_recv", "mismatches_fdtable",
                    "mismatches_inodes", "host_cpu_util", "target_cpu_util"]:
            if key in results:
                setattr(self, key, results[key])
        super().__init__(results)

    def to_json(self):
        dict_to_print = {}
        for key, value in self.__dict__.items():
            if key != "results":
                dict_to_print[key] = value
        return dict_to_print


class RocksDBBenchmarkFramework(BenchmarkFramework):

    def __init__(self, name: str, *args, **kwargs):
        super().__init__(name, *args, **kwargs)

    def benchmark_cmd(self, config):
        bench_path = self.args.bench_path
        config_dir = self.args.config_dir
        config_path = os.path.join(config_dir, "bench_config.yaml")
        # Copy file
        shutil.copyfile(os.path.join(config_dir, config["bench_type"] + ".yaml"),
                        config_path)
        with YAMLEditor(config_path) as ycsb_config:
            db_path = self.args.db_path
            if hasattr(self.args, "temp_db_path"):
                db_path = self.args.temp_db_path
            threads = config["threads_per_core"] * config["cpus"]
            ycsb_config.yaml["rocksdb"]["data_dir"] = db_path
            ycsb_config.yaml["rocksdb"]["cache_size"] = config["cache_size"]
            ycsb_config.yaml["rocksdb"]["print_stats"] = config["print_stats"]
            ycsb_config.yaml["workload"]["nr_thread"] = threads
            ycsb_config.yaml["workload"]["nr_warmup_op"] = config["nr_warmup_op"]
            ycsb_config.yaml["workload"]["nr_op"] = config["nr_op"]
            ycsb_config.yaml["workload"]["runtime_seconds"] = config["runtime_seconds"]
            ycsb_config.yaml["workload"]["warmup_runtime_seconds"] = config["warmup_runtime_seconds"]
            if "zipfian_constant" in config:
                ycsb_config.yaml["workload"]["zipfian_constant"] = config["zipfian_constant"]
            if "target_throughput" in config:
                if config["target_throughput"] > 0:
                    # next_op_interval_ns: how much time to wait before issuing the next
                    # request. This applies per worker thread.
                    # total_worker_threads = threads_per_core * cpus
                    # throughput = total_worker_threads * 10**9 / next_op_interval_ns
                    # Solving for next_op_interval_ns gives us:
                    # next_op_interval_ns = total_worker_threads * 10**9 / throughput
                    ycsb_config.yaml["workload"]["next_op_interval_ns"] = int(threads * 10**9 / config["target_throughput"])

            rocksdb_ini_config_path = ycsb_config.yaml["rocksdb"]["options_file"]
            with INIEditor(rocksdb_ini_config_path) as rocksdb_ini_config:
                pin_indexes_str = "false" if config["pin_indexes"] else "true"
                rocksdb_ini_config.ini['TableOptions/BlockBasedTable "default"']["cache_index_and_filter_blocks"] = pin_indexes_str

                bloom_policy_str = "rocksdb.BuiltinBloomFilter" if config["bloom_filter"] else "nullptr"
                rocksdb_ini_config.ini['TableOptions/BlockBasedTable "default"']["filter_policy"] = bloom_policy_str

        cmd = [bench_path, config_path]
        if config["disk_type"] == "local":
            cmd = ["sudo"] + cmd
        return cmd

    def parse_results(self, stdout: str) -> RocksDBBenchResults:
        # Uniform: calculating overall performance metrics... (might take a while)
        # Uniform overall: UPDATE throughput 0.00 ops/sec, INSERT throughput 0.00 ops/sec, READ throughput 9038.24 ops/sec, SCAN throughput 0.00 ops/sec, READ_MODIFY_WRITE throughput 0.00 ops/sec, total throughput 9038.24 ops/sec
        # Uniform overall: UPDATE average latency 0.00 ns, UPDATE p99 latency 0.00 ns, INSERT average latency 0.00 ns, INSERT p99 latency 0.00 ns, READ average latency 109658.84 ns, READ p99 latency 145190.65 ns, SCAN average latency 0.00 ns, SCAN p99 latency 0.00 ns, READ_MODIFY_WRITE average latency 0.00 ns, READ_MODIFY_WRITE p99 latency 0.00 ns
        # Template:
        # === RocksDB Stats Start ===
        # rocksdb.block.cache.miss COUNT : 980
        # rocksdb.block.cache.hit COUNT : 20
        # rocksdb.block.cache.add COUNT : 980
        #
        # === RocksDB Stats End ===
        results = {}
        stats = {}
        results["keys_failed"] = 0
        for line in stdout.splitlines():
            line = line.strip()
            if "Warm-Up" in line:
                continue
            elif "Key fails:" in line:
                pattern = r"Key fails: (\d+)"

                match = re.search(pattern, line)
                if match:
                    results["keys_failed"] = int(match.group(1))
            elif "overall: UPDATE throughput" in line:
                # Parse throughput
                pattern = r'(\w+ throughput) (\d+\.\d+) ops/sec'
                matches = re.findall(pattern, line)
                # Matches look like this:
                # [('UPDATE throughput', '0.00'),
                #  ('INSERT throughput', '12337.23'),
                #  ('READ throughput', '12369.98'),
                #  ('SCAN throughput', '0.00'),
                #  ('READ_MODIFY_WRITE throughput', '0.00'),
                #  ('total throughput', '24707.21')]
                assert (len(matches) == 6), "Unexpected line pattern: %s" % line
                assert ("total throughput" in matches[-1][0])
                for match in matches:
                    if "READ throughput" in match[0]:
                        results["read_throughput_avg"] = float(match[1])
                    elif "INSERT throughput" in match[0]:
                        results["insert_throughput_avg"] = float(match[1])
                    elif "UPDATE throughput" in match[0]:
                        results["update_throughput_avg"] = float(match[1])
                    elif "SCAN throughput" in match[0]:
                        results["scan_throughput_avg"] = float(match[1])
                    elif "READ_MODIFY_WRITE throughput" in match[0]:
                        results["read_modify_write_throughput_avg"] = float(
                            match[1])
                    elif "total throughput" in match[0]:
                        results["throughput_avg"] = float(match[1])
                    else:
                        raise Exception("Unknown throughput type: " + match[0])
                results["throughput_avg"] = float(matches[-1][1])
            elif "overall: UPDATE average latency" in line:
                # Parse latency
                pattern = r'(\w+ \w+ latency) (\d+\.\d+) ns'
                matches = re.findall(pattern, line)
                # Matches look like this:
                # [('UPDATE average latency', '0.00'),
                #  ('UPDATE p99 latency', '0.00'),
                #  ('INSERT average latency', '80992.84'),
                #  ('INSERT p99 latency', '887726.24'),
                #  ('READ average latency', '1850251.43'),
                #  ('READ p99 latency', '6888407.68'),
                #  ('SCAN average latency', '0.00'),
                #  ('SCAN p99 latency', '0.00'),
                #  ('READ_MODIFY_WRITE average latency', '0.00'),
                #  ('READ_MODIFY_WRITE p99 latency', '0.00')]
                for match in matches:
                    if "READ average latency" in match[0]:
                        results["read_latency_avg"] = float(match[1])
                        results["latency_avg"] = float(match[1])
                    elif "INSERT average latency" in match[0]:
                        results["insert_latency_avg"] = float(match[1])
                    elif "UPDATE average latency" in match[0]:
                        results["update_latency_avg"] = float(match[1])
                    elif "SCAN average latency" in match[0]:
                        results["scan_latency_avg"] = float(match[1])
                    elif "READ_MODIFY_WRITE average latency" in match[0]:
                        results["read_modify_write_latency_avg"] = float(
                            match[1])
                    elif "READ p99 latency" in match[0]:
                        results["read_latency_p99"] = float(match[1])
                        results["latency_p99"] = float(match[1])
                    elif "INSERT p99 latency" in match[0]:
                        results["insert_latency_p99"] = float(match[1])
                    elif "UPDATE p99 latency" in match[0]:
                        results["update_latency_p99"] = float(match[1])
                    elif "SCAN p99 latency" in match[0]:
                        results["scan_latency_p99"] = float(match[1])
                    elif "READ_MODIFY_WRITE p99 latency" in match[0]:
                        results["read_modify_write_latency_p99"] = float(
                            match[1])
                    else:
                        raise Exception("Unknown latency metric: " + match[0])
            elif "rocksdb." in line and " : " in line:
                # Parse RocksDB stats
                if "COUNT" in line and line.count(":") == 1:
                    parts = line.split()
                    assert (len(parts) == 4)
                    stats[parts[0]] = int(parts[3])
                else:
                    parts = line.split(None, 1)
                    assert (len(parts) == 2)
                    stats[parts[0]] = parts[1]
        results["stats"] = stats
        if not all(key in results for key in ["throughput_avg", "latency_avg", "latency_p99"]):
            raise Exception("Could not parse results from stdout: \n" + stdout)
        return RocksDBBenchResults(results)


###############################################################################

##########################
# RocksDB Zipf Benchmark #
##########################


class RocksDBZipfBenchmark(RocksDBBenchmarkFramework):
    """Benchmark RocksDB for different zipfian constants."""

    def __init__(self):
        self.benchresults_cls = RocksDBBenchResults
        super().__init__("rocksdb_zipf")

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument("--db-path", type=str, default="/nvme/rocksdb",
                            help="Path to RocksDB database")
        parser.add_argument("--bench-path", type=str,
                            default="/mydata/My-YCSB/build/run_rocksdb",
                            help="Path to the My-YCSB RocksDB benchmark")
        parser.add_argument("--config-dir", type=str,
                            default="/mydata/My-YCSB/rocksdb/config",
                            help="Path to the My-YCSB config directory")

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        # We don't care too much about this, because we set runtime_seconds
        configs = add_config_option("nr_warmup_op", [10**8], configs)
        configs = add_config_option("nr_op", [10**8], configs)
        # configs = add_config_option("warmup_runtime_seconds", [60], configs)
        # configs = add_config_option("runtime_seconds", [5 * 60], configs)
        configs = add_config_option("warmup_runtime_seconds", [5], configs)
        configs = add_config_option("runtime_seconds", [5], configs)

        MB = 10**6
        # Database size is roughlt 100GB
        # Try cache ratios of 1:1000, 1:100, 1:30, 1:10
        configs = add_config_option("cache_size",
                                    [100 * MB, 1000 * MB, 3333 * MB,  10000 * MB],
                                    configs)
        configs = add_config_option("threads_per_core", [4, 8, 16], configs)
        configs = add_config_option("zipfian_constant",
                                    [0.6, 0.8, 1, 1.2, 1.4], configs)
        configs = add_config_option("bench_type", ["ycsb_c"], configs)
        configs = add_config_option("print_stats", [True], configs)
        return configs


###############################################################################

###########################
# RocksDB Disk Benchmark  #
###########################

class RocksDBDiskBenchmark(RocksDBBenchmarkFramework):
    """Benchmark RocksDB across local, NVMEoF/TCP and NVMEoF/RDMA."""

    def __init__(self, *args, **kwargs):
        super().__init__("rocksdb_disk", *args,
                         benchresults_cls=RocksDBBenchResults, **kwargs)

    def add_arguments(self, parser: argparse.ArgumentParser):
        parser.add_argument("--db-path", type=str, default="/nvme/rocksdb",
                            help="Path to RocksDB database")
        parser.add_argument("--threads-per-core", type=str, default="16",
                            help="Number of threads per core. Comma-separated"
                                 " numbers and ranges. E.g. 1,2,4-8")
        parser.add_argument("--detect-best-threads-per-core", default=False,
                            action="store_true",
                            help="Detect best threads per core configuration"
                                 " for max throughput")
        MB = 10**6
        parser.add_argument("--cache-size", type=str,
                            default="0,%d" % (1000 * MB),
                            help="Cache size in bytes. 0 means no cache."
                                 " Comma-separated.")
        parser.add_argument("--temp-db-path", type=str,
                            default="/nvme/rocksdb_temp",
                            help="Path to temp RocksDB database that will be"
                            " used for benchmarking. We are testing write"
                            " workloads which change the database. For"
                            " reproducibility, we want to start from the same"
                            " database in every benchmark.")
        parser.add_argument("--bench-path", type=str,
                            default="/mydata/My-YCSB/build/run_rocksdb",
                            help="Path to the My-YCSB RocksDB benchmark")
        parser.add_argument("--config-dir", type=str,
                            default="/mydata/My-YCSB/rocksdb/config",
                            help="Path to the My-YCSB config directory")
        parser.add_argument("--disk-type", required=True,
                            choices=["local", "nvmeof_tcp", "nvmeof_rdma"],
                            help="Disk type that the database is on.")
        parser.add_argument("--use-bpfof", default=False, type=boolean_string,
                            help="Enable BPFoF.")
        parser.add_argument("--pin-indexes", default=True, type=boolean_string,
                            help="Pin indexes in memory.")
        parser.add_argument("--bloom-filter", default=False, type=boolean_string,
                            help="Use bloom filters.")
        parser.add_argument("--sample-rate", default="1", type=str,
                            help="Sample rate for BPFoF.")
        parser.add_argument("--adaptive-sample-time", default="0", type=str,
                            help="Adaptive sample time for BPFoF. 0 needs to be first in the list.")
        parser.add_argument("--print-stats", default=False,
                            type=boolean_string, help="Print RocksDB stats.")
        parser.add_argument("--bpfof-nic", default=get_cloudlab_data_nic(),
                            help="NIC used for BPFoF. Used for network stats.")
        parser.add_argument("--target-ip", default=get_default_target_ip(),
                            help="IP of the target. Used for cpu utilization.")
        parser.add_argument("--measure-version-mismatches", default=True,
                            type=boolean_string,
                            help="Measure version mismatches.")
        parser.add_argument("--target-throughput", default=0, type=int,
                            help="Target throughput in ops/sec.")
        parser.add_argument("--bench-type", type=str,
                            default="uniform,uniform_read_write,ycsb_a,ycsb_b,ycsb_c,ycsb_d,ycsb_f",
                            help="Benchmark type. Comma-separated list of"
                                 " which workloads to run.")
        parser.add_argument("--runtime-seconds", default=4*60, type=int,
                            help="Runtime in seconds for each benchmark.")
        parser.add_argument("--warmup-runtime-seconds", default=30, type=int,
                            help="Warmup runtime in seconds for each"
                                 " benchmark.")

    def benchmark_prepare(self, config):
        log.info("Copying database to temp location for benchmarking...")
        # Copy database to temp location
        src_path = self.args.db_path
        dst_path = self.args.temp_db_path
        # Trailing slash means we want to copy the contents of the directory
        if src_path[-1] != "/":
            src_path += "/"
        cmd = ["rsync", "-avpl", "--delete", src_path, dst_path]
        check_output(cmd)
        stabilize()
        super().benchmark_prepare(config)

    def generate_configs(self, configs: List[Dict]) -> List[Dict]:
        configs = add_config_option("nr_op", [10**8], configs)
        configs = add_config_option("nr_warmup_op", [10**8], configs)
        # configs = add_config_option("runtime_seconds", [4*60], configs)
        configs = add_config_option("runtime_seconds",
                                    [self.args.runtime_seconds], configs)
        # configs = add_config_option("warmup_runtime_seconds", [60], configs)
        configs = add_config_option("warmup_runtime_seconds",
                                    [self.args.warmup_runtime_seconds],
                                    configs)
        MB = 10**6
        configs = add_config_option(
            "cache_size", parse_numbers_string(self.args.cache_size), configs)
        configs = add_config_option("bench_type",
                                    parse_strings_string(self.args.bench_type),
                                    # ["uniform", "uniform_read_write", "ycsb_a",
                                    #  "ycsb_b", "ycsb_c", "ycsb_d", "ycsb_f"],
                                    configs)
        configs = add_config_option("use_bpfof", [self.args.use_bpfof],
                                    configs)
        configs = add_config_option("disk_type", [self.args.disk_type],
                                    configs)
        configs = add_config_option("target_throughput",
                                    [self.args.target_throughput],
                                    configs)
        configs = add_config_option("print_stats", [self.args.print_stats],
                                    configs)

        # tj additions
        configs = add_config_option("sample_rate",
                                    parse_numbers_string(self.args.sample_rate),
                                    configs)
        # "sample_rate", ["1", "10"], configs)

        configs = add_config_option("adaptive_sample_time",
                                    parse_numbers_string(self.args.adaptive_sample_time),
                                    configs)
        configs = add_config_option("pin_indexes", [self.args.pin_indexes],
                                    configs)
        configs = add_config_option("bloom_filter", [self.args.bloom_filter],
                                    configs)
        # "adaptive_sample_time", ["0", "2", "5", "10", "20"], configs
        if self.args.detect_best_threads_per_core:
            self.detect_best_threads_per_core(configs)
        else:
            configs = add_config_option("threads_per_core",
                                        parse_numbers_string(self.args.threads_per_core),
                                        configs)

        return configs

    BEST_TPC_KEYS = ["bench_type", "cache_size", "sample_rate",
                     "pin_indexes", "bloom_filter", "disk_type"]

    def detect_best_threads_per_core(self, configs,
                                     results_cache="/mydata/best_threads_per_core_cache.pickle") -> Dict[frozenset, int]:
        """Detect best threads per core configuration for max throughput."""
        # For each different config, detect the optimal threads per core value.
        unique_configs = unique_configs_for_keys(configs, self.BEST_TPC_KEYS)
        config_to_best_threads_per_core = {}
        if os.path.exists(results_cache):
            with open(results_cache, "rb") as f:
                config_to_best_threads_per_core = pickle.load(f)
                # Fix bug
                for key in list(config_to_best_threads_per_core.keys()):
                    key_dict = hashable_to_dict(key)
                    if "threads_per_core" not in key_dict:
                        continue
                    del key_dict["threads_per_core"]
                    new_key = dict_to_hashable(key_dict)
                    config_to_best_threads_per_core[new_key] = config_to_best_threads_per_core[key]
                    del config_to_best_threads_per_core[key]
        for unique_config in unique_configs:
            if dict_to_hashable(unique_config) in config_to_best_threads_per_core:
                best = config_to_best_threads_per_core[dict_to_hashable(unique_config)]
            else:
                best = self.detect_best_threads_per_core_for_config(unique_config)
            log.info("Best threads per core for config %s: %s"
                     % (unique_config, best))
            # Update matching configs
            for config in configs:
                if unique_config.items() <= config.items():
                    config["threads_per_core"] = best
            config_to_best_threads_per_core[dict_to_hashable(unique_config)] = best
            with open(results_cache, "wb") as f:
                pickle.dump(config_to_best_threads_per_core, f)

    def detect_best_threads_per_core_for_config(self, config):
        config = copy.deepcopy(config)
        log.info("Detecting best threads-per-core for config %s" % config)
        # Run benchmark for different threads per core values
        results_file = "/mydata/temp_results.json"
        args = copy.deepcopy(self.args)
        setattr(args, "detect_best_threads_per_core", False)
        setattr(args, "threads_per_core", "8,12,16,24,32,48")
        setattr(args, "runtime_seconds", "10")
        setattr(args, "warmup_runtime_seconds", "5")
        setattr(args, "results_file", results_file)
        setattr(args, "reuse_results", True)
        for key in self.BEST_TPC_KEYS:
            if key in ["pin_indexes", "bloom_filter"]:
                setattr(args, key, config[key])
            else:
                setattr(args, key, str(config[key]))
        results = RocksDBDiskBenchmark(cli_args=args).benchmark()
        best_threads = -1
        best_throughput = -1
        for threads in [8, 12, 16, 24, 32]:
            config["threads_per_core"] = threads
            throughput = single_result_select(results, config).results.throughput_avg
            if throughput * 0.95 > best_throughput:
                best_throughput = throughput
                best_threads = threads
        # Get result
        return best_threads

    # def benchmark_cmd(self, config)

    def cmd_extra_envs(self, config):
        extra_envs = {}
        extra_envs["XRP_SAMPLE_RATE"] = str(config["sample_rate"])

        if config["adaptive_sample_time"] != 0:
            extra_envs["XRP_ADAPTIVE_RATE"] = str(config["adaptive_sample_time"])

        if config["disk_type"] in ["nvmeof_tcp", "nvmeof_rdma"]:
            # if config["use_bpfof"]:
            #     extra_envs["ROCKSDB_BPFOF_ENABLED"] = "1"
            #     extra_envs["XRP_SAMPLE_RATE"] = "10"
            # else:
            #     extra_envs["ROCKSDB_BPFOF_ENABLED"] = "1"
            #     extra_envs["XRP_SAMPLE_RATE"] = "1"
            extra_envs["ROCKSDB_BPFOF_ENABLED"] = "1"

        else:
            extra_envs["ROCKSDB_BPF_FILE"] = "/mydata/rocksdb/ebpf/parser.o"
        # if config["cache_size"] > 0:
        #     extra_envs["XRP_ADAPTIVE_RATE"] = "1"
        return extra_envs

    def before_benchmark(self, config):
        super().before_benchmark(config)
        if config["disk_type"] == "local":
            return
        if config["use_bpfof"]:
            # Get network stats
            if config["disk_type"] == "nvmeof_tcp":
                self.start_bytes_sent, self.start_bytes_recv = get_network_stats(self.args.bpfof_nic)
            elif config["disk_type"] == "nvmeof_rdma":
                self.start_bytes_sent, self.start_bytes_recv = get_rdma_network_stats(self.args.bpfof_nic)
            if self.args.measure_version_mismatches and config["sample_rate"] != 1:
                mismatches_fdtable, mismatches_inodes = get_version_mismatches()
                self.start_mismatches_fdtable = mismatches_fdtable
                self.start_mismatches_inodes = mismatches_inodes

        cpu_list = list(range(config["cpus"]))
        self.host_start_idle_time, self.host_start_iowait_time = get_cpu_stats_multi(cpu_list)
        self.target_start_idle_time, self.target_start_iowait_time = get_cpu_stats_multi(cpu_list, ip=self.args.target_ip)
        self.start_time = time.time()

    def after_benchmark(self, config):
        super().after_benchmark(config)
        if config["disk_type"] == "local":
            return
        end_time = time.time()

        if config["use_bpfof"]:
            # Get network stats
            if config["disk_type"] == "nvmeof_tcp":
                end_bytes_sent, end_bytes_recv = get_network_stats(
                    self.args.bpfof_nic)
            elif config["disk_type"] == "nvmeof_rdma":
                end_bytes_sent, end_bytes_recv = get_rdma_network_stats(
                    self.args.bpfof_nic)
            self.bytes_sent = end_bytes_sent - self.start_bytes_sent
            self.bytes_recv = end_bytes_recv - self.start_bytes_recv
            if self.args.measure_version_mismatches and config["sample_rate"] != 1:
                mismatches_fdtable, mismatches_inodes = get_version_mismatches()
                self.mismatches_fdtable = mismatches_fdtable - self.start_mismatches_fdtable
                self.mismatches_inodes = mismatches_inodes - self.start_mismatches_inodes

        if config["disk_type"] in ["nvmeof_tcp", "nvmeof_rdma"]:
            cpu_list = list(range(config["cpus"]))
            host_end_idle_time, host_end_iowait_time = get_cpu_stats_multi(cpu_list)
            target_end_idle_time, target_end_iowait_time = get_cpu_stats_multi(cpu_list, ip=self.args.target_ip)

            time_passed = (end_time - self.start_time) * config["cpus"]
            host_idle_time = host_end_idle_time - self.host_start_idle_time
            host_iowait_time = host_end_iowait_time - self.host_start_iowait_time
            target_idle_time = target_end_idle_time - self.target_start_idle_time
            target_iowait_time = target_end_iowait_time - self.target_start_iowait_time
            self.host_cpu_util = (time_passed - host_idle_time - host_iowait_time) / time_passed
            self.target_cpu_util = (time_passed - target_idle_time - target_iowait_time) / time_passed

    def parse_results(self, stdout: str) -> BenchRun:
        bench_results = super().parse_results(stdout)

        try:
            bench_results.bytes_sent = self.bytes_sent
            bench_results.bytes_recv = self.bytes_recv
        except:
            pass

        try:
            bench_results.host_cpu_util = self.host_cpu_util
            bench_results.target_cpu_util = self.target_cpu_util
            if self.args.measure_version_mismatches:
                bench_results.mismatches_fdtable = self.mismatches_fdtable
                bench_results.mismatches_inodes = self.mismatches_inodes
        except:
            pass

        return bench_results


def parse_strings_string(s: str) -> List[str]:
    parts = s.split(",")
    res = []
    for part in parts:
        part = part.strip()
        if part:
            res.append(part)
    return res


def parse_numbers_string(num_string: str) -> List[int]:
    """Parse a string of comma-separated numbers and ranges into an int list."""
    parts = num_string.split(",")
    num_list = []
    for part in parts:
        if "-" in part:
            start, end = part.split("-")
            num_list.extend(list(range(int(start), int(end) + 1)))
        else:
            num_list.append(int(part))
    return sorted(list(set(num_list)))


def parse_cpu_string(cpu_string: str):
    return parse_numbers_string(cpu_string)


###############################################################################


def dict_to_hashable(d: Dict) -> frozenset:
    return frozenset(d.items())


def hashable_to_dict(h: frozenset) -> Dict:
    return dict(h)


def boolean_string(s):
    if s not in {'False', 'True'}:
        raise ValueError('Not a valid boolean string')
    return s == 'True'


def get_default_target_ip():
    # getent hosts nvmeof-target | awk '{print $1}'
    ip = None
    try:
        ip = check_output(["getent", "hosts", "nvmeof-target"]).split()[0].decode()
    except Exception:
        pass
    try:
        ip = check_output(["getent", "hosts", "optane-node"]).split()[0].decode()
    except Exception:
        pass
    return ip


def sudo_read_file_as_int(path: str):
    cmd = ["sudo", "cat", path]
    out = check_output(cmd, encoding="utf-8")
    return int(out)


def get_version_mismatches():
    mismatches_fdtable = sudo_read_file_as_int(
        "/sys/kernel/debug/bpfof_host_stats/version_mismatches_fdtable")
    mismatches_inodes = sudo_read_file_as_int(
        "/sys/kernel/debug/bpfof_host_stats/version_mismatches_inodes")
    return mismatches_fdtable, mismatches_inodes


def stabilize():
    sleep(1)
    os.sync()
    os.sync()
    os.sync()
    sleep(1)


def get_cloudlab_data_nic() -> str:
    # ip addr show to 10.10.1.0/24
    cmd = ["ip", "addr", "show", "to", "10.10.1.0/24"]
    out = check_output(cmd, encoding="utf-8")
    return out.split()[1][:-1]


def get_network_stats(nic: str) -> (int, int):
    """Return bytes sent and received on a NIC."""
    net_counters = psutil.net_io_counters(pernic=True)[nic]
    return net_counters.bytes_sent, net_counters.bytes_recv


def get_rdma_network_stats(nic: str) -> (int, int):
    """Return bytes sent and received on a RDMA NIC."""
    bytes_sent, bytes_recv = get_network_stats(nic)
    # Parse RDMA stats from ethtool
    stats = parse_ethtool_stats(nic)
    bytes_sent += stats["tx_vport_rdma_unicast_bytes"]
    bytes_recv += stats["rx_vport_rdma_unicast_bytes"]
    return bytes_sent, bytes_recv


def parse_ethtool_stats(nic: str):
    """Parse ethtool stats."""
    out = check_output(["sudo", "ethtool", "--statistics", nic], text=True)
    res = {}
    for line in out.splitlines():
        line = line.strip()
        if not line or "NIC statistics:" in line:
            continue
        parts = line.split(":")
        parts = [part.strip() for part in parts]
        assert (len(parts) == 2), "Unexpected line: %s" % line
        res[parts[0]] = int(parts[1])
    return res


def remote_check_output(cmd: List[str], ip: str, pty=False) -> str:
    with fabric.Connection(ip) as conn:
        return conn.run(" ".join(cmd), hide=True, pty=pty).stdout


def get_cpu_stats_multi(cpus: List[int], ip=None):
    total_idle, total_iowait = 0, 0
    for cpu in cpus:
        idle, iowait = get_cpu_stats(cpu, ip)
        total_idle += idle
        total_iowait += iowait
    return total_idle, total_iowait


def get_cpu_stats(cpu: int, ip=None) -> (int, int):
    """Return CPU idle and iowait times."""
    if not ip:
        cpu_counters = psutil.cpu_times(percpu=True)[cpu]
        return cpu_counters.idle, cpu_counters.iowait
    else:
        log.info("Measuring CPU stats on remote host %s", ip)
        cmd = ["python3", "-c",
               "'import psutil; cpu_counters = psutil.cpu_times(percpu=True)[%d]; print(cpu_counters.idle, cpu_counters.iowait)'" % cpu]
        out = remote_check_output(cmd, ip)
        parts = out.split()
        return float(parts[0]), float(parts[1])


def allow_more_open_files():
    # Get the current ulimit value
    soft, hard = resource.getrlimit(resource.RLIMIT_NOFILE)
    log.info(f"Current ulimit value: soft={soft}, hard={hard}")
    # Set a new ulimit value
    new_soft_limit = 10000
    resource.setrlimit(resource.RLIMIT_NOFILE, (new_soft_limit, hard))


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    allow_more_open_files()
    # rocksdb_bench = RocksDBZipfBenchmark()
    rocksdb_bench = RocksDBDiskBenchmark()
    rocksdb_bench.benchmark()


if __name__ == "__main__":
    sys.exit(main())
