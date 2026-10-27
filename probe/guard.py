#!/usr/bin/env python3
"""Run one command with a wall-clock limit and a resident-memory limit.

Usage: guard.py [--rss-mb N] [--timeout S] -- COMMAND...

The guard polls the command and its descendants (macOS libproc). It kills the
process group when the summed resident size exceeds the limit or when the time
limit passes. It prints one JSON line on stderr: verdict, exit code, wall
seconds and peak resident megabytes. The exit code is the code of the command
(128 plus the signal number for a signal), or 137 when the guard killed it.
"""

import argparse
import ctypes
import json
import os
import resource
import signal
import subprocess
import sys
import time

LIBPROC = ctypes.CDLL("/usr/lib/libproc.dylib", use_errno=True)
RUSAGE_INFO_V2 = 2
MEGABYTE = 1024 * 1024
WORD_FIELDS = (
    "ri_user_time",
    "ri_system_time",
    "ri_pkg_idle_wkups",
    "ri_interrupt_wkups",
    "ri_pageins",
    "ri_wired_size",
    "ri_resident_size",
    "ri_phys_footprint",
    "ri_proc_start_abstime",
    "ri_proc_exit_abstime",
    "ri_child_user_time",
    "ri_child_system_time",
    "ri_child_pkg_idle_wkups",
    "ri_child_interrupt_wkups",
    "ri_child_pageins",
    "ri_child_elapsed_abstime",
    "ri_diskio_bytesread",
    "ri_diskio_byteswritten",
)


class RusageInfoV2(ctypes.Structure):
    _fields_ = [("ri_uuid", ctypes.c_uint8 * 16)] + [
        (name, ctypes.c_uint64) for name in WORD_FIELDS
    ]


def resident(pid):
    info = RusageInfoV2()
    status = LIBPROC.proc_pid_rusage(pid, RUSAGE_INFO_V2, ctypes.byref(info))
    return info.ri_resident_size if status == 0 else 0


def children(pid):
    buffer = (ctypes.c_int * 4096)()
    count = LIBPROC.proc_listchildpids(pid, buffer, ctypes.sizeof(buffer))
    return [buffer[index] for index in range(max(count, 0))]


def descendants(pid):
    return [pid] + [later for kid in children(pid) for later in descendants(kid)]


def total_resident(pid):
    return sum(map(resident, descendants(pid)))


def watch(proc, limit_bytes, deadline):
    peak = 0
    verdict = "exit"
    while proc.poll() is None:
        now = total_resident(proc.pid)
        peak = max(peak, now)
        over_memory = now > limit_bytes
        over_time = time.monotonic() > deadline
        if over_memory or over_time:
            verdict = "rss-limit" if over_memory else "timeout"
            os.killpg(proc.pid, signal.SIGKILL)
            proc.wait()
        time.sleep(0.02)
    return verdict, peak


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--rss-mb", type=int, default=4096)
    parser.add_argument("--timeout", type=float, default=120.0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    start = time.monotonic()
    proc = subprocess.Popen(command, start_new_session=True)
    verdict, peak = watch(proc, args.rss_mb * MEGABYTE, start + args.timeout)
    wall = time.monotonic() - start
    largest = resource.getrusage(resource.RUSAGE_CHILDREN).ru_maxrss
    code = proc.returncode if verdict == "exit" else 137
    if code < 0:
        code = 128 - code
    report = {
        "verdict": verdict,
        "exit": code,
        "wall_s": round(wall, 3),
        "peak_polled_mb": round(peak / MEGABYTE, 1),
        "peak_child_mb": round(largest / MEGABYTE, 1),
    }
    print(json.dumps(report), file=sys.stderr)
    return code


if __name__ == "__main__":
    sys.exit(main())
