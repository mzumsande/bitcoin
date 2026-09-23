#!/usr/bin/env python3
# Copyright (c) 2026 The Bitcoin Core developers
# Distributed under the MIT software license, see the accompanying
# file COPYING or http://www.opensource.org/licenses/mit-license.php.
"""Drive an addr-relay experiment by calling the hidden `sendaddrtorandompeer` RPC.

Each trial sends one unique address (53.<run>.x.y:8333 by default) in a
single-address ADDR message to one peer, then waits before the next trial.
Results are appended to a CSV file after every trial, so an interrupted run
can be resumed by rerunning with the same arguments (same --run and --seed
give the same address list, and addresses already sent are skipped).

A trial is "ok" if a PONG confirmed that the peer processed the ADDR, and
"unconfirmed" if the ADDR was sent but not confirmed (e.g. the peer evicted us).
Unconfirmed addresses are not retried, as the peer may still have relayed them.

The sender node should run with -connect=0 -listen=0 and have a populated
tried table.

Example:
    ./send_addrs.py --run 1 --count 100 --interval 150 \\
        --cli "build/bin/bitcoin-cli -datadir=/path/to/sender" \\
        --calibrate 203.0.113.7:8333 --calibrate 198.51.100.9:8333
"""

import argparse
import csv
import datetime
import json
import os
import random
import shlex
import subprocess
import sys
import time

CSV_FIELDS = [
    "trial", "kind", "address", "port", "requested_target", "peer",
    "rpc_time", "call_start", "call_end", "status", "error",
]


def generate_addresses(first, run, count, seed):
    """Return `count` unique addresses <first>.<run>.a.b in random order (deterministic per run/seed)."""
    if not 0 <= run <= 255:
        sys.exit("--run must be in 0..255")
    # Avoid .0 and .255 in the last octet so the addresses look like ordinary hosts.
    space = [(a, b) for a in range(256) for b in range(1, 255)]
    if count > len(space):
        sys.exit(f"--count too large, at most {len(space)} addresses per run")
    rng = random.Random(f"{seed}-{run}")
    return [f"{first}.{run}.{a}.{b}" for a, b in rng.sample(space, count)]


def build_schedule(addresses, calibrate_targets, calibrate_count, seed, run):
    """Assign a kind/target to each address and interleave calibration trials randomly."""
    trials = [{"address": a, "kind": "random", "target": ""} for a in addresses]
    n_calib = len(calibrate_targets) * calibrate_count
    if n_calib > len(trials):
        sys.exit("not enough addresses for the requested calibration trials")
    rng = random.Random(f"{seed}-{run}-schedule")
    calib_slots = rng.sample(range(len(trials)), n_calib)
    targets = [t for t in calibrate_targets for _ in range(calibrate_count)]
    for slot, target in zip(sorted(calib_slots), rng.sample(targets, len(targets))):
        trials[slot]["kind"] = "calibration"
        trials[slot]["target"] = target
    return trials


def load_done(csv_path):
    """Addresses that were already sent (confirmed or not) in a previous (interrupted) run."""
    if not os.path.exists(csv_path):
        return set()
    with open(csv_path, newline="") as f:
        return {row["address"] for row in csv.DictReader(f) if row["status"] in ("ok", "unconfirmed")}


def call_rpc(cli, address, port, max_tries, wait, target):
    args = [*cli, "-rpcclienttimeout=0", "sendaddrtorandompeer", f"{address}:{port}", str(max_tries), str(wait)]
    if target:
        args.append(target)
    proc = subprocess.run(args, capture_output=True, text=True)
    if proc.returncode != 0:
        raise RuntimeError((proc.stderr or proc.stdout).strip().replace("\n", " "))
    return json.loads(proc.stdout)


def now_iso():
    return datetime.datetime.now(datetime.timezone.utc).isoformat(timespec="milliseconds")


def main():
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument("--run", type=int, required=True, help="Run number, used as the second octet (0..255). Use a new one for every run.")
    parser.add_argument("--count", type=int, default=100, help="Total number of trials, including calibration trials (default: %(default)s).")
    parser.add_argument("--interval", type=float, default=150, help="Seconds between the starts of consecutive trials (default: %(default)s).")
    parser.add_argument("--jitter", type=float, default=0.2, help="Randomize each interval by +/- this fraction (default: %(default)s).")
    parser.add_argument("--cli", default="bitcoin-cli", help="bitcoin-cli command incl. options such as -datadir, -rpcport (default: %(default)s).")
    parser.add_argument("--port", type=int, default=8333, help="Port of the advertised addresses (default: %(default)s).")
    parser.add_argument("--prefix", type=int, default=53, help="First octet of the advertised addresses (default: %(default)s).")
    parser.add_argument("--max-tries", type=int, default=100, help="max_tries passed to the RPC (default: %(default)s).")
    parser.add_argument("--wait", type=int, default=10, help="Maximum seconds to wait for the confirming PONG, passed to the RPC (default: %(default)s).")
    parser.add_argument("--calibrate", action="append", default=[], metavar="IP:PORT",
                        help="Monitoring node to use as explicit target for calibration trials. Can be given multiple times.")
    parser.add_argument("--calibrate-count", type=int, default=1, help="Calibration trials per --calibrate target (default: %(default)s).")
    parser.add_argument("--retries", type=int, default=3, help="Attempts per trial if the RPC fails before anything was sent (default: %(default)s).")
    parser.add_argument("--seed", default="addrrelay", help="Seed for address generation and scheduling (default: %(default)s).")
    parser.add_argument("--out", help="CSV output file (default: sent_run<RUN>.csv).")
    parser.add_argument("--dry-run", action="store_true", help="Print the schedule without calling the RPC.")
    args = parser.parse_args()

    out = args.out or f"sent_run{args.run}.csv"
    cli = shlex.split(args.cli)
    addresses = generate_addresses(args.prefix, args.run, args.count, args.seed)
    trials = build_schedule(addresses, args.calibrate, args.calibrate_count, args.seed, args.run)
    done = load_done(out)
    todo = [(i, t) for i, t in enumerate(trials) if t["address"] not in done]
    print(f"run {args.run}: {len(trials)} trials, {len(done)} already sent, {len(todo)} to go, output {out}")

    if args.dry_run:
        for i, t in todo:
            print(f"{i:4d} {t['kind']:11s} {t['address']}:{args.port} {t['target']}")
        return

    new_file = not os.path.exists(out)
    rng = random.Random()
    with open(out, "a", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=CSV_FIELDS)
        if new_file:
            writer.writeheader()
            f.flush()
        try:
            for n, (i, t) in enumerate(todo):
                start = time.monotonic()
                for attempt in range(1, args.retries + 1):
                    row = {"trial": i, "kind": t["kind"], "address": t["address"], "port": args.port,
                           "requested_target": t["target"], "call_start": now_iso()}
                    try:
                        res = call_rpc(cli, t["address"], args.port, args.max_tries, args.wait, t["target"])
                        row.update(peer=res["peer"], rpc_time=res["time"], status="ok" if res["confirmed"] else "unconfirmed")
                    except Exception as e:
                        row.update(status="error", error=str(e))
                    row["call_end"] = now_iso()
                    writer.writerow(row)
                    f.flush()
                    print(f"[{row['call_end']}] {n + 1}/{len(todo)} trial {i} {t['kind']} {t['address']} -> "
                          f"{row.get('peer') or row.get('error')} ({row['status']}, attempt {attempt})", flush=True)
                    if row["status"] != "error":
                        break
                if n + 1 < len(todo):
                    delay = args.interval * (1 + rng.uniform(-args.jitter, args.jitter))
                    time.sleep(max(0.0, delay - (time.monotonic() - start)))
        except KeyboardInterrupt:
            print("\ninterrupted; rerun with the same arguments to resume", file=sys.stderr)
            sys.exit(1)


if __name__ == "__main__":
    main()
