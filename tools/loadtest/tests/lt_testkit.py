"""Helpers for the load-test kit tests (deliberately not a conftest.py: edge/tests has one and both
suites may run in one pytest session)."""

import contextlib
import json
import os
import pathlib
import subprocess
import sys
import time

LT_DIR = pathlib.Path(__file__).resolve().parent.parent
REPO = LT_DIR.parent.parent
sys.path.insert(0, str(LT_DIR))

import loadtest  # noqa: E402


@contextlib.contextmanager
def origin_proc(tmp_path, *extra):
    """origin.py in a subprocess on a free port; yields the port."""
    port_file = tmp_path / f"origin-{time.monotonic_ns()}.port"
    p = subprocess.Popen([sys.executable, str(LT_DIR / "origin.py"), "--listen", "127.0.0.1", "--port", "0",
                          "--port-file", str(port_file), *extra],
                         stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
    try:
        for _ in range(100):
            if port_file.exists():
                break
            if p.poll() is not None:
                raise RuntimeError("origin.py exited: " + p.stderr.read().decode())
            time.sleep(0.05)
        else:
            raise RuntimeError("origin.py did not start")
        yield int(port_file.read_text())
    finally:
        p.terminate()
        try:
            p.wait(5)
        except subprocess.TimeoutExpired:
            p.kill()


def run_lt(tmp_path, *args) -> dict:
    """Run pcdn-loadtest in-process; returns the JSON report."""
    out = tmp_path / f"report-{time.monotonic_ns()}.json"
    rc = loadtest.main([*map(str, args), "--quiet", "--out", str(out)])
    assert rc == 0
    return json.loads(out.read_text())


def run_cli(*args, timeout=60) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(LT_DIR / "pcdn-loadtest"), *map(str, args)], capture_output=True,
                          text=True, timeout=timeout, env=dict(os.environ, PYTHONIOENCODING="utf-8"))
