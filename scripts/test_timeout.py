#!/usr/bin/env python3
"""
test_timeout.py - run a `cargo test` (or `cargo miri test`) with a timeout on each test.

Libtest has no per-test timeout: a test that loops keeps the whole run going for as long as
nobody stops it, and stopping it by hand does not say which test it was. This wrapper runs the
command with libtest's JSON events (`-Z unstable-options --format json`, the toolchain being
nightly), keeps the tests that have started and not yet ended, and when one has run longer than
the per-test timeout, or the whole run longer than the run timeout, prints the tests still
running, kills the command (its whole process group) and fails. Otherwise it prints what libtest
prints - a line per test, each failure's output, the result line - and exits with the command's
status.

The JSON flags go after the command's `--` (one is added when it has none), so the command's own
test-binary arguments (a filter, `--test-threads`) stay as they are. Cargo's own messages go to
standard error untouched.

Usage:
  test_timeout.py [--test-timeout SECONDS] [--run-timeout SECONDS] -- cargo test ... [-- ARGS]

  --test-timeout  the longest one test may run (default 120; 0: no limit)
  --run-timeout   the longest the whole command may run, compile time included (default 0: no
                  limit)
"""

import argparse
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time

JSON_FLAGS = ["-Z", "unstable-options", "--format", "json"]


def with_json_flags(command):
    if "--" in command:
        return command + JSON_FLAGS
    return command + ["--"] + JSON_FLAGS


def read_lines(stream, lines):
    for line in stream:
        lines.put(line)
    lines.put(None)


def kill_group(process):
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait()


class Suite:
    """One test binary's run (the library's tests, the doc tests), from its JSON events."""

    def __init__(self):
        self.running = {}
        self.failures = []
        self.started = time.monotonic()

    def event(self, event, out):
        kind = event.get("type")
        name = event.get("name", "")
        what = event.get("event")
        if kind == "suite" and what == "started":
            count = event.get("test_count", 0)
            out(f"\nrunning {count} test{'' if count == 1 else 's'}")
        elif kind == "test" and what == "started":
            self.running[name] = time.monotonic()
        elif kind == "test" and what == "timeout":
            out(f"test {name} has been running for over 60 seconds")
        elif kind == "test":
            self.running.pop(name, None)
            if what == "failed":
                self.failures.append((name, event.get("stdout", "")))
            label = {"ok": "ok", "failed": "FAILED", "ignored": "ignored"}.get(what, what)
            out(f"test {name} ... {label}")
        elif kind == "suite":
            self.finish(event, out)

    def finish(self, event, out):
        if self.failures:
            out("\nfailures:\n")
            for name, stdout in self.failures:
                if stdout:
                    out(f"---- {name} stdout ----\n{stdout}")
            out("\nfailures:")
            for name, _ in self.failures:
                out(f"    {name}")
        result = "ok" if event.get("event") == "ok" else "FAILED"
        took = event.get("exec_time", time.monotonic() - self.started)
        out(
            f"\ntest result: {result}. {event.get('passed', 0)} passed; "
            f"{event.get('failed', 0)} failed; {event.get('ignored', 0)} ignored; "
            f"{event.get('measured', 0)} measured; {event.get('filtered_out', 0)} filtered out; "
            f"finished in {took:.2f}s\n"
        )


def main():
    parser = argparse.ArgumentParser(description=__doc__.split("\n\n")[0])
    parser.add_argument("--test-timeout", type=float, default=120)
    parser.add_argument("--run-timeout", type=float, default=0)
    parser.add_argument("command", nargs=argparse.REMAINDER)
    args = parser.parse_args()
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    if not command:
        parser.error("no command given")

    def out(text):
        print(text, flush=True)

    process = subprocess.Popen(
        with_json_flags(command), stdout=subprocess.PIPE, text=True, start_new_session=True
    )
    lines = queue.Queue()
    threading.Thread(target=read_lines, args=(process.stdout, lines), daemon=True).start()
    started = time.monotonic()
    suite = Suite()
    try:
        while True:
            try:
                line = lines.get(timeout=1)
            except queue.Empty:
                line = ""
            if line is None:
                break
            if line.startswith("{"):
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    event = None
                if isinstance(event, dict) and "type" in event:
                    if event["type"] == "suite" and event.get("event") == "started":
                        suite = Suite()
                    suite.event(event, out)
                else:
                    out(line.rstrip("\n"))
            elif line:
                out(line.rstrip("\n"))
            now = time.monotonic()
            late = [
                name
                for name, began in suite.running.items()
                if args.test_timeout and now - began > args.test_timeout
            ]
            if late or (args.run_timeout and now - started > args.run_timeout):
                if late:
                    out(f"\nTIMEOUT: over {args.test_timeout:g}s (--test-timeout):")
                    for name in late:
                        out(f"    {name}")
                else:
                    out(f"\nTIMEOUT: the run took over {args.run_timeout:g}s (--run-timeout)")
                others = sorted(set(suite.running) - set(late))
                if others:
                    out("still running:")
                    for name in others:
                        out(f"    {name} ({now - suite.running[name]:.0f}s)")
                kill_group(process)
                return 124
    except KeyboardInterrupt:
        kill_group(process)
        return 130
    return process.wait()


if __name__ == "__main__":
    sys.exit(main())
