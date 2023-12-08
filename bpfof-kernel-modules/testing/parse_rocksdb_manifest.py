#!/usr/bin/env python3

import re
import sys
import logging
import argparse

from typing import List, Dict
from subprocess import check_output
from collections import defaultdict

log = logging.getLogger(__name__)


def parse_args():
    parser = argparse.ArgumentParser("Parse RocksDB manifest file")
    parser.add_argument("--manifest", required=True,
                        help="Path to manifest file")
    parser.add_argument("--num-keys", type=int, required=True,
                        help="Number of keys in the database")
    parser.add_argument("--ldb", default="/mydata/rocksdb/ldb",
                        help="Path to the ldb cli")
    return parser.parse_args()


def parse_manifest(out: str) -> Dict[int, List[Dict[str, str]]]:
    level_pattern = r"--- level (\d+) ---"
    range_pattern = r"\['(\d+)'\sseq:\d+,\stype:\d+\s\.\.\s'(\d+)'\sseq:\d+,\stype:\d+\]"
    level_ranges = defaultdict(list)
    curr_level = None
    lines = out.splitlines()
    for line in lines:
        line = line.strip()
        level_match = re.match(level_pattern, line)
        if level_match:
            curr_level = int(level_match.group(1))
            continue
        range_match = re.search(range_pattern, line)
        if range_match:
            level_ranges[curr_level].append({
                "start": int(range_match.group(1)),
                "end": int(range_match.group(2))})
            continue
    return level_ranges


def main():
    global log
    logging.basicConfig(level=logging.INFO)
    args = parse_args()
    out = check_output([args.ldb, "manifest_dump",
                        "--path=%s" % args.manifest], text=True)
    # print(out)
    level_ranges = parse_manifest(out)
    for level, ranges in level_ranges.items():
        log.info("Level %d: Number of ranges: %d", level, len(ranges))
        key_coverage = 0
        if not ranges:
            continue
        for range in ranges:
            key_coverage += range["end"] - range["start"] + 1
        log.info("Level %d: Key coverage: %d (%d%%)", level, key_coverage,
                 key_coverage * 100 / args.num_keys)
    return 0


if __name__ == "__main__":
    sys.exit(main())
