#!/usr/bin/env python3
"""Pasargad CDN edge functions service (SPEC §16.9): pcdn-fn.

Customer JavaScript is untrusted multi-tenant code. It never runs inside nginx/njs. nginx proxies
the routes a customer bound to this service over a unix socket; every invocation runs in a FRESH
QuickJS process (`qjs`, Debian/Ubuntu package `quickjs`) that is sandboxed before exec:

  * one process per invocation, never a shared JS heap between invocations or sites;
  * Landlock (kernel >= 5.13): the only filesystem access left is READ of the qjs binary, its
    shared libraries, ld.so.cache and the runtime glue, and EXECUTE of qjs + its ELF interpreter.
    No writes anywhere, no directory listing, no /proc, no other site's code or data (ABI >= 4:
    no TCP bind/connect either; ABI >= 6: no signals / abstract unix sockets outside the worker);
  * seccomp-BPF allow-list (no socket/connect, fork/clone, kill, ptrace, ioctl, rt_sigaction, path
    stat, ... -> EPERM; foreign architecture / x32 -> kill);
  * rlimits (address space = memory_mb + headroom, no core, no files, no new processes) plus the
    engine's own --memory-limit / --stack-size;
  * CPU budget: ITIMER_PROF (SIGPROF kills, the worker cannot install a handler or block it),
    RLIMIT_CPU as a backstop, a wall-clock deadline (SIGKILL) and the real CPU time from wait4()
    (an invocation over budget is a timeout even if it produced a response);
  * no network: the only I/O are the stdin/stdout pipes. fetch() is a request frame on stdout that
    pcdn-fn validates (own site hosts only) and forwards to nginx's local fetch socket, which proxies
    it to the site's own origin (never cached, never another site);
  * the whole service additionally runs under systemd sandboxing (systemd/pcdn-fn.service:
    DynamicUser, ProtectSystem=strict, PrivateNetwork, RestrictAddressFamilies=AF_UNIX, MemoryMax,
    TasksMax, SystemCallFilter, MemoryDenyWriteExecute, ...).

A self-test (benign function, file read, exec, signal, CPU and memory bombs, seccomp/no_new_privs
state) runs at start and hourly; its result is written to FN_STATUS. The agent reports the
`edge_functions` capability only while that status is fresh and ok. Usage is appended to
FN_USAGE_LOG as JSON lines {"t","h","n","c","e","o"} (host, invocations, cpu_ms, errors, timeouts).

    pcdn-fn serve      run the service
    pcdn-fn selftest   run the self-test once, print the JSON result (exit 0 = pass)

Standard library only (python3 >= 3.9, Linux).
"""

import asyncio
import collections
import ctypes
import hashlib
import json
import logging
import math
import os
import platform
import re
import resource
import select
import signal
import socket
import struct
import subprocess
import sys
import time
from datetime import datetime, timezone

log = logging.getLogger("pcdn-fn")

DEFAULTS = {
    "FN_SOCKET": "/run/pcdn-fn/fn.sock",
    "FN_SOCKET_GROUP": "",               # group that may connect (nginx workers); "" = own group
    "FN_FETCH_SOCKET": "/run/pcdn-fnfetch/fetch.sock",   # nginx's fetch() proxy (rendered by pcdn-agent)
    "FN_DIR": "/var/lib/pcdn-fn",         # manifest.json + code/<sha256>.js (written by pcdn-agent)
    "FN_STATUS": "/run/pcdn-fn/status.json",
    "FN_USAGE_LOG": "/var/log/pcdn-fn/usage.log",
    "FN_QJS": "/usr/bin/qjs",
    "FN_RUNTIME": "/usr/share/pcdn/fn/runtime.js",
    "FN_WORKERS": "0",                    # concurrent invocations on the node (0 = 2 x CPUs, max 32)
    "FN_SITE_WORKERS": "4",               # concurrent invocations per site
    "FN_QUEUE_MS": "1000",                # wait for a free worker slot before "busy" (on_error)
    "FN_WALL_MS": "5000",                 # wall-clock cap per invocation, fetch() waits included
    "FN_STARTUP_MS": "30",                # CPU allowance on top of timeout_ms for engine start + parse
    "FN_MAX_FETCHES": "8",                # fetch() calls per invocation
    "FN_FETCH_TIMEOUT_MS": "5000",
    "FN_SELFTEST_INTERVAL": "3600",
    "FN_USAGE_FLUSH": "10",               # seconds between usage-log appends
}

MAX_CODE = 256 * 1024               # SPEC §16.9: code <= 256 KB
MAX_REQ_BODY = 1024 * 1024          # request body handed to a function
MAX_RESP_BODY = 5 * 1024 * 1024     # function (and fetch) response body
MAX_HEADER_BYTES = 32 * 1024        # response / fetch header block
MAX_HEADERS = 64
MAX_SET_COOKIE = 32
MAX_HEAD_IN = 64 * 1024             # nginx -> pcdn-fn request head
TIMEOUT_MS = (1, 200, 50)           # (min, max, default) CPU ms per invocation
MEMORY_MB = (8, 128, 32)
AS_HEADROOM_MB = 64                 # address space on top of the JS heap limit (binary, libc, stacks)
STACK_BYTES = 1024 * 1024           # JS stack (qjs --stack-size)
USAGE_ROTATE = 16 * 1024 * 1024     # usage.log -> usage.log.1 (the agent reads both by inode)
STATUS_EVERY = 30

SAFE_ID = re.compile(r"^[a-z0-9_-]{1,32}$")
SAFE_SID = re.compile(r"^\d{1,12}$")
SAFE_HOST = re.compile(r"^[a-z0-9*][a-z0-9.*-]{0,252}$")
SAFE_LOC = re.compile(r"^@pcdn_fn_[a-z]{1,16}$")
TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9A-Za-z-]{1,64}$")
HVALUE = re.compile(r"^[\t\x20-\x7e\x80-\xff]{0,8192}$")
SAFE_PATH = re.compile(r"^/[\x21-\x7e]{0,2047}$")
METHODS = {"GET", "HEAD", "POST", "PUT", "PATCH", "DELETE", "OPTIONS"}
HOP = {"connection", "keep-alive", "proxy-authenticate", "proxy-authorization", "proxy-connection", "te",
       "trailer", "trailers", "transfer-encoding", "upgrade", "content-length", "host", "http2-settings"}
# never accepted from a function response: hop-by-hop, framing, and every header nginx interprets
# itself (X-Accel-* would let a function redirect internally, e.g. into /__pcdn/ locations)
RESP_DROP = HOP | {"status", "date", "server"}
RESP_DROP_PREFIX = ("x-accel-", "x-pcdn-", "proxy-")
REQ_DROP_PREFIX = ("x-pcdn-", "proxy-")
FN_HDR = "x-pcdn-fn-"


def _now_iso() -> str:
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")


def load_config(path: str | None) -> dict:
    cfg = dict(DEFAULTS)
    if path:
        try:
            with open(path) as f:
                for line in f:
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        k, v = line.split("=", 1)
                        cfg[k.strip()] = v.strip()
        except FileNotFoundError:
            pass
    return cfg


def _int(v, default: int, lo: int, hi: int) -> int:
    try:
        return max(lo, min(hi, int(v)))
    except (TypeError, ValueError):
        return default


def clamp_limits(timeout_ms, memory_mb) -> tuple[int, int]:
    return (_int(timeout_ms, TIMEOUT_MS[2], TIMEOUT_MS[0], TIMEOUT_MS[1]),
            _int(memory_mb, MEMORY_MB[2], MEMORY_MB[0], MEMORY_MB[1]))


# ================================================================== sandbox

_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long
_libc.prctl.restype = ctypes.c_int
_libc.prctl.argtypes = [ctypes.c_int, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong, ctypes.c_ulong]

SYS_LANDLOCK_CREATE_RULESET, SYS_LANDLOCK_ADD_RULE, SYS_LANDLOCK_RESTRICT_SELF = 444, 445, 446
PR_SET_NO_NEW_PRIVS, PR_SET_SECCOMP, PR_SET_MDWE = 38, 22, 65
SECCOMP_MODE_FILTER = 2
PR_MDWE_REFUSE_EXEC_GAIN = 1

LL_EXECUTE, LL_WRITE_FILE, LL_READ_FILE, LL_READ_DIR = 1 << 0, 1 << 1, 1 << 2, 1 << 3
LL_FS_ABI = {1: (1 << 13) - 1, 2: (1 << 14) - 1, 3: (1 << 15) - 1, 4: (1 << 15) - 1, 5: (1 << 16) - 1}
LL_NET_ALL = (1 << 0) | (1 << 1)          # BIND_TCP | CONNECT_TCP (ABI >= 4)
LL_SCOPE_ALL = (1 << 0) | (1 << 1)        # ABSTRACT_UNIX_SOCKET | SIGNAL (ABI >= 6)


def landlock_abi() -> int:
    r = _libc.syscall(SYS_LANDLOCK_CREATE_RULESET, None, ctypes.c_size_t(0), ctypes.c_uint32(1))
    return int(r) if r > 0 else 0


class _PathBeneath(ctypes.Structure):
    _pack_ = 1
    _fields_ = [("allowed_access", ctypes.c_uint64), ("parent_fd", ctypes.c_int32)]


# ---- seccomp-BPF

AUDIT_ARCH = {"x86_64": 0xC000003E, "aarch64": 0xC00000B7}
SYSCALLS = {
    "x86_64": {"read": 0, "write": 1, "readv": 19, "writev": 20, "close": 3, "fstat": 5, "lseek": 8, "mmap": 9,
               "mprotect": 10, "munmap": 11, "brk": 12, "mremap": 25, "madvise": 28, "rt_sigreturn": 15,
               "pread64": 17, "sched_yield": 24, "nanosleep": 35, "clock_nanosleep": 230, "getpid": 39,
               "gettid": 186, "exit": 60, "exit_group": 231, "uname": 63, "getcwd": 79, "gettimeofday": 96,
               "time": 201, "clock_gettime": 228, "clock_getres": 229, "futex": 202, "set_tid_address": 218,
               "set_robust_list": 273, "rseq": 334, "arch_prctl": 158, "getrandom": 318, "select": 23,
               "pselect6": 270, "poll": 7, "ppoll": 271, "restart_syscall": 219, "execve": 59, "openat": 257,
               "close_range": 436, "dup": 32, "dup2": 33, "dup3": 292, "fcntl": 72, "prlimit64": 302},
    "aarch64": {"read": 63, "write": 64, "readv": 65, "writev": 66, "close": 57, "fstat": 80, "lseek": 62,
                "mmap": 222, "mprotect": 226, "munmap": 215, "brk": 214, "mremap": 216, "madvise": 233,
                "rt_sigreturn": 139, "pread64": 67, "sched_yield": 124, "nanosleep": 101, "clock_nanosleep": 115,
                "getpid": 172, "gettid": 178, "exit": 93, "exit_group": 94, "uname": 160, "getcwd": 17,
                "gettimeofday": 169, "clock_gettime": 113, "clock_getres": 114, "futex": 98,
                "set_tid_address": 96, "set_robust_list": 99, "rseq": 293, "getrandom": 278, "pselect6": 72,
                "ppoll": 73, "restart_syscall": 128, "execve": 221, "openat": 56, "close_range": 436, "dup": 23,
                "dup3": 24, "fcntl": 25, "prlimit64": 261},
}
# Argument checks: prlimit64 only as getrlimit on itself (pid 0, new_limit NULL); fcntl only for fd
# flags / dup (no F_SETOWN / F_SETSIG: SIGIO must never reach another process); openat never with
# O_PATH (an O_PATH open is not mediated by Landlock and would leak file metadata via fstat).
# Everything not listed -> EPERM. execve stays allowed (the initial exec happens after the filter is
# installed); Landlock limits EXECUTE to qjs + its interpreter and fork/clone are denied, so nothing
# else can ever run.
SECCOMP_COND = {"prlimit64", "fcntl", "openat"}
FCNTL_OK = (0, 1, 2, 3, 4, 1030)   # F_DUPFD F_GETFD F_SETFD F_GETFL F_SETFL F_DUPFD_CLOEXEC
O_PATH = 0o10000000

BPF_LD_W_ABS, BPF_JEQ_K, BPF_JSET_K, BPF_RET_K = 0x20, 0x15, 0x45, 0x06
RET_KILL, RET_ALLOW, RET_ERRNO = 0x80000000, 0x7FFF0000, 0x00050000
EPERM = 1


def seccomp_program(arch: str) -> bytes:
    """Allow-list BPF program for one architecture (raises KeyError if unsupported)."""
    nrs = SYSCALLS[arch]
    ins = []   # (code, jt, jf, k) with jt/jf as labels or ints

    def emit(code, k, jt=0, jf=0):
        ins.append([code, jt, jf, k])
    emit(BPF_LD_W_ABS, 4)                                  # seccomp_data.arch
    emit(BPF_JEQ_K, AUDIT_ARCH[arch], 1, 0)
    emit(BPF_RET_K, RET_KILL)
    emit(BPF_LD_W_ABS, 0)                                  # seccomp_data.nr
    if arch == "x86_64":
        emit(BPF_JSET_K, 0x40000000, "kill", 0)            # x32 ABI
    for name, nr in sorted(nrs.items(), key=lambda kv: kv[1]):
        emit(BPF_JEQ_K, nr, "allow" if name not in SECCOMP_COND else "c_" + name, 0)
    emit(BPF_RET_K, RET_ERRNO | EPERM)
    labels = {}
    labels["c_prlimit64"] = len(ins)
    for off in (16, 20, 32, 36):                           # args[0] (pid) and args[2] (new_limit), both halves
        emit(BPF_LD_W_ABS, off)
        emit(BPF_JEQ_K, 0, 0, "deny")
    emit(BPF_RET_K, RET_ALLOW)
    labels["c_fcntl"] = len(ins)
    emit(BPF_LD_W_ABS, 24)                                 # args[1] (cmd)
    for cmd in FCNTL_OK:
        emit(BPF_JEQ_K, cmd, "allow", 0)
    emit(BPF_RET_K, RET_ERRNO | EPERM)
    labels["c_openat"] = len(ins)
    emit(BPF_LD_W_ABS, 32)                                 # args[2] (flags)
    emit(BPF_JSET_K, O_PATH, "deny", "allow")
    labels["allow"] = len(ins)
    emit(BPF_RET_K, RET_ALLOW)
    labels["deny"] = len(ins)
    emit(BPF_RET_K, RET_ERRNO | EPERM)
    labels["kill"] = len(ins)
    emit(BPF_RET_K, RET_KILL)
    out = b""
    for i, (code, jt, jf, k) in enumerate(ins):
        jt = labels[jt] - i - 1 if isinstance(jt, str) else jt
        jf = labels[jf] - i - 1 if isinstance(jf, str) else jf
        if not (0 <= jt <= 255 and 0 <= jf <= 255):
            raise ValueError("BPF jump out of range")
        out += struct.pack("=HBBI", code, jt, jf, k)
    return out


class _SockFprog(ctypes.Structure):
    _fields_ = [("len", ctypes.c_ushort), ("filter", ctypes.c_void_p)]


def elf_interp(path: str) -> str | None:
    """PT_INTERP of a 64-bit little-endian ELF (the dynamic loader qjs needs EXECUTE on)."""
    try:
        with open(path, "rb") as f:
            h = f.read(64)
            if h[:4] != b"\x7fELF" or h[4] != 2 or h[5] != 1:
                return None
            phoff, = struct.unpack_from("<Q", h, 32)
            phentsize, phnum = struct.unpack_from("<HH", h, 54)
            for i in range(phnum):
                f.seek(phoff + i * phentsize)
                p_type, _, p_offset, _, _, p_filesz = struct.unpack("<IIQQQQ", f.read(40))
                if p_type == 3:
                    f.seek(p_offset)
                    return f.read(p_filesz).rstrip(b"\0").decode()
    except (OSError, struct.error, UnicodeDecodeError):
        return None
    return None


def shared_libs(exe: str, interp: str | None) -> list[str]:
    """Resolved shared libraries of `exe` (ld.so --list); [] when it cannot be determined."""
    if not interp:
        return []
    try:
        p = subprocess.run([interp, "--list", exe], capture_output=True, text=True, timeout=10)
    except (OSError, subprocess.SubprocessError):
        return []
    libs = []
    for line in p.stdout.splitlines():
        m = re.search(r"=>\s+(/\S+)\s+\(", line) or re.match(r"^\s*(/\S+)\s+\(", line)
        if m:
            libs.append(m.group(1))
    return libs


class SandboxError(RuntimeError):
    pass


def dac_readable(path: str, uid: int, gid: int, groups=()) -> bool:
    """Would uid/gid pass the classic permission checks to open `path` for reading (x on every
    parent directory, r on the file)? root (uid 0) is treated as any other uid: workers never are."""
    try:
        parts = os.path.realpath(path).split("/")[1:]
        cur = "/"
        for i, part in enumerate(parts):
            st = os.stat(cur)
            if not _perm(st, uid, gid, groups, 0o1):
                return False
            cur = os.path.join(cur, part)
        return _perm(os.stat(cur), uid, gid, groups, 0o4)
    except OSError:
        return False


def _perm(st, uid, gid, groups, bit) -> bool:
    if st.st_uid == uid:
        return bool(st.st_mode & (bit << 6))
    if st.st_gid == gid or st.st_gid in groups:
        return bool(st.st_mode & (bit << 3))
    return bool(st.st_mode & bit)


class Sandbox:
    """Pre-built Landlock ruleset + seccomp program; `preexec(limits)` applies them in the child
    between fork and exec (the parent is single-threaded, so preexec_fn is safe)."""

    def __init__(self, exe: str, read_files=(), arch: str | None = None, abi_max: int | None = None):
        self.exe = os.path.realpath(exe)
        self.arch = arch or platform.machine()
        if self.arch not in SYSCALLS:
            raise SandboxError(f"unsupported architecture {self.arch}")
        self.kernel_abi = landlock_abi()
        # abi_max (FN_LANDLOCK_ABI_MAX): use at most this Landlock ABI, to exercise the code paths of
        # older kernels (Ubuntu 24.04 / 6.8 = ABI 4). It can only lower the ABI; 0 = no Landlock,
        # which fails closed exactly like a kernel without it.
        self.abi = self.kernel_abi if abi_max is None else max(0, min(self.kernel_abi, int(abi_max)))
        if self.abi < 1:
            raise SandboxError("Landlock is not available (kernel >= 5.13 with landlock in the LSM list)"
                               if self.kernel_abi < 1 else "Landlock disabled (FN_LANDLOCK_ABI_MAX=0)")
        # the worker uid must be able to reach every file it needs (DAC is checked before Landlock):
        # a non-traversable parent directory would otherwise surface only as a silent engine failure
        self.worker_ids = (65534, 65534) if os.geteuid() == 0 else (os.geteuid(), os.getegid())
        for p in [self.exe] + [x for x in read_files]:
            if not dac_readable(p, *self.worker_ids):
                raise SandboxError(f"{p} is not readable by the worker uid {self.worker_ids[0]} "
                                   "(check the permissions of every parent directory)")
        interp = elf_interp(self.exe)
        libs = shared_libs(self.exe, interp)
        if interp and not libs:
            raise SandboxError("cannot resolve the shared libraries of " + self.exe)
        fs_all = LL_FS_ABI.get(min(self.abi, 5))
        attr = struct.pack("=Q", fs_all)
        if self.abi >= 4:
            attr += struct.pack("=Q", LL_NET_ALL)
        if self.abi >= 6:
            attr += struct.pack("=Q", LL_SCOPE_ALL)
        buf = ctypes.create_string_buffer(attr, len(attr))
        fd = _libc.syscall(SYS_LANDLOCK_CREATE_RULESET, buf, ctypes.c_size_t(len(attr)), ctypes.c_uint32(0))
        if fd < 0:
            raise SandboxError("landlock_create_ruleset: " + os.strerror(ctypes.get_errno()))
        self.ruleset_fd = int(fd)
        self.allowed = {}
        self._allow(self.exe, LL_EXECUTE | LL_READ_FILE)
        if interp:
            self._allow(os.path.realpath(interp), LL_EXECUTE | LL_READ_FILE)
        for p in libs + ["/etc/ld.so.cache"] + list(read_files):
            if os.path.exists(p):
                self._allow(os.path.realpath(p), LL_READ_FILE)
        self.fail_at = None
        self.bpf = seccomp_program(self.arch)
        self._bpf_buf = ctypes.create_string_buffer(self.bpf, len(self.bpf))
        self._fprog = _SockFprog(len(self.bpf) // 8, ctypes.addressof(self._bpf_buf))

    def _allow(self, path: str, access: int):
        if not os.path.isfile(path):
            raise SandboxError(f"sandbox rule on a non-file: {path}")
        pfd = os.open(path, os.O_PATH | os.O_CLOEXEC)
        try:
            pb = _PathBeneath(access, pfd)
            r = _libc.syscall(SYS_LANDLOCK_ADD_RULE, ctypes.c_int(self.ruleset_fd), ctypes.c_int(1),
                              ctypes.byref(pb), ctypes.c_uint32(0))
            if r != 0:
                raise SandboxError(f"landlock_add_rule {path}: " + os.strerror(ctypes.get_errno()))
        finally:
            os.close(pfd)
        self.allowed[path] = access

    def preexec(self, cpu_ms: int, memory_mb: int):
        """-> the preexec_fn for one worker. Runs in the forked child; any failure raises, which
        makes Popen fail (the worker never runs unsandboxed)."""
        fprog, rfd = self._fprog, self.ruleset_fd
        as_bytes = (memory_mb + AS_HEADROOM_MB) * 1024 * 1024
        cpu_s = cpu_ms / 1000.0
        rl_cpu = int(math.ceil(cpu_s)) + 1

        fail_at = self.fail_at   # test hook: simulate a failing setup stage

        def stage(name, ok):
            if fail_at == name:
                ok, err = False, 22
            else:
                err = ctypes.get_errno()
            if not ok:
                # stderr is the supervisor's diagnostics pipe; the worker never gets to exec
                os.write(2, f"pcdn-fn sandbox setup failed at {name}: errno {err} ({os.strerror(err)})\n"
                         .encode())
                os._exit(126)

        def fn():
            try:   # under cgroup memory pressure the OOM killer takes a worker, never the supervisor
                with open("/proc/self/oom_score_adj", "w") as f:
                    f.write("1000")
            except OSError:
                pass
            for res, lim in ((resource.RLIMIT_AS, as_bytes), (resource.RLIMIT_DATA, as_bytes),
                             (resource.RLIMIT_STACK, 8 * 1024 * 1024), (resource.RLIMIT_CORE, 0),
                             (resource.RLIMIT_FSIZE, 0), (resource.RLIMIT_NOFILE, 16),
                             (resource.RLIMIT_NPROC, 0), (resource.RLIMIT_MEMLOCK, 0),
                             (resource.RLIMIT_MSGQUEUE, 0), (resource.RLIMIT_SIGPENDING, 16),
                             (resource.RLIMIT_CPU, None)):
                try:
                    resource.setrlimit(res, (rl_cpu, rl_cpu + 1) if lim is None else (lim, lim))
                    ok = True
                except (OSError, ValueError) as e:
                    ctypes.set_errno(getattr(e, "errno", None) or 22)
                    ok = False
                stage(f"setrlimit({res})", ok)
            stage("no_new_privs", _libc.prctl(PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) == 0)
            # refuse W^X violations even outside systemd's MemoryDenyWriteExecute (Linux >= 6.3; older
            # kernels return EINVAL and rely on the unit's MemoryDenyWriteExecute=yes)
            _libc.prctl(PR_SET_MDWE, PR_MDWE_REFUSE_EXEC_GAIN, 0, 0, 0)
            stage("landlock_restrict_self",
                  _libc.syscall(SYS_LANDLOCK_RESTRICT_SELF, ctypes.c_int(rfd), ctypes.c_uint32(0)) == 0)
            # CPU budget: SIGPROF's default action terminates; the worker can neither catch nor block
            # it (rt_sigaction / rt_sigprocmask are not in the seccomp allow-list). Survives execve.
            signal.setitimer(signal.ITIMER_PROF, cpu_s)
            stage("seccomp", _libc.prctl(PR_SET_SECCOMP, SECCOMP_MODE_FILTER, ctypes.addressof(fprog), 0, 0) == 0)
        return fn

    def spawn(self, argv: list[str], cpu_ms: int, memory_mb: int) -> subprocess.Popen:
        kw = {}
        if os.geteuid() == 0:   # never run customer code as root (tests / a misconfigured unit)
            kw = {"user": 65534, "group": 65534, "extra_groups": []}
        # stderr: a bounded diagnostics channel (sandbox setup stage + errno, engine start errors)
        return subprocess.Popen([self.exe] + argv[1:], executable=self.exe, stdin=subprocess.PIPE,
                                stdout=subprocess.PIPE, stderr=subprocess.PIPE, close_fds=True, cwd="/",
                                env={}, start_new_session=True, restore_signals=True,
                                preexec_fn=self.preexec(cpu_ms, memory_mb), **kw)


# ================================================================== manifest

class Manifest:
    """FN_DIR/manifest.json + FN_DIR/code/<sha256>.js written by pcdn-agent (re-read on change)."""

    def __init__(self, fn_dir: str):
        self.dir = fn_dir
        self.key = None
        self.sites: dict = {}
        self.code: collections.OrderedDict = collections.OrderedDict()
        self.code_bytes = 0

    def refresh(self):
        path = os.path.join(self.dir, "manifest.json")
        try:
            st = os.stat(path)
        except OSError:
            self.key, self.sites = None, {}
            return
        key = (st.st_ino, st.st_mtime_ns, st.st_size)
        if key == self.key:
            return
        try:
            with open(path) as f:
                data = json.load(f)
            sites = data.get("sites") if isinstance(data, dict) else None
            self.sites = sites if isinstance(sites, dict) else {}
            self.key = key
        except (OSError, ValueError) as e:
            log.error("manifest unreadable: %s", e)

    def lookup(self, sid: str, fid: str):
        self.refresh()
        s = self.sites.get(sid)
        if not isinstance(s, dict):
            return None, None
        f = (s.get("functions") or {}).get(fid)
        return s, (f if isinstance(f, dict) else None)

    def source(self, sha: str) -> str | None:
        if not isinstance(sha, str) or not re.match(r"^[0-9a-f]{64}$", sha):
            return None
        if sha in self.code:
            self.code.move_to_end(sha)
            return self.code[sha]
        try:
            with open(os.path.join(self.dir, "code", sha + ".js"), "rb") as f:
                raw = f.read(MAX_CODE + 1)
        except OSError:
            return None
        if len(raw) > MAX_CODE or hashlib.sha256(raw).hexdigest() != sha:
            log.error("code %s: size or digest mismatch", sha[:12])
            return None
        src = raw.decode("utf-8", "replace")
        self.code[sha] = src
        self.code_bytes += len(raw)
        while self.code_bytes > 64 * 1024 * 1024 and len(self.code) > 1:
            _, old = self.code.popitem(last=False)
            self.code_bytes -= len(old.encode("utf-8", "replace"))
        return src


# ================================================================== validation

def host_matches(pattern: str, host: str) -> bool:
    if pattern.startswith("*."):
        return host.endswith(pattern[1:]) and host != pattern[2:]
    return host == pattern


def cookie_domain_ok(value: str, host: str, domain: str) -> bool:
    """A Set-Cookie without Domain is host-only (fine); with Domain it must cover the request host
    and stay inside the site's own domain (no cookies for other sites / parent suffixes)."""
    m = re.search(r";\s*domain\s*=\s*([^;]*)", value, re.I)
    if not m:
        return True
    d = m.group(1).strip().lstrip(".").lower()
    if not d or not re.match(r"^[a-z0-9.-]{1,253}$", d):
        return False
    in_site = d == domain or d.endswith("." + domain)
    covers = host == d or host.endswith("." + d)
    return in_site and covers


def clean_headers(pairs, drop=RESP_DROP, drop_prefix=RESP_DROP_PREFIX, max_n=MAX_HEADERS,
                  max_bytes=MAX_HEADER_BYTES, host: str = "", domain: str = "", cookies=True) -> list:
    """Validated header list (raises ValueError on a malformed entry; drops forbidden names)."""
    if not isinstance(pairs, list):
        raise ValueError("headers must be a list")
    out, size, n_cookie = [], 0, 0
    for p in pairs:
        if not (isinstance(p, list) and len(p) == 2 and isinstance(p[0], str) and isinstance(p[1], str)):
            raise ValueError("malformed header")
        name, value = p
        if not TOKEN.match(name):
            raise ValueError("invalid header name")
        try:
            raw = value.encode("latin-1")
        except UnicodeEncodeError:
            raw = value.encode("utf-8")
        if not HVALUE.match(raw.decode("latin-1")):
            raise ValueError("invalid header value")
        low = name.lower()
        if low in drop or low.startswith(drop_prefix):
            continue
        if low == "set-cookie":
            if not cookies:
                continue
            n_cookie += 1
            if n_cookie > MAX_SET_COOKIE or not cookie_domain_ok(value, host, domain):
                continue
        size += len(name) + len(raw) + 4
        if len(out) >= max_n or size > max_bytes:
            raise ValueError("too many / too large headers")
        out.append((name, raw.decode("latin-1")))
    return out


# ================================================================== usage

class Usage:
    def __init__(self, path: str):
        self.path = path
        self.acc: dict = {}

    def add(self, host: str, cpu_ms: float, outcome: str):
        a = self.acc.setdefault(host, [0, 0.0, 0, 0])
        a[0] += 1
        a[1] += cpu_ms
        if outcome == "error":
            a[2] += 1
        elif outcome == "timeout":
            a[3] += 1

    def flush(self):
        if not self.acc:
            return
        t = _now_iso()
        lines = "".join(json.dumps({"t": t, "h": h, "n": a[0], "c": int(round(a[1])), "e": a[2], "o": a[3]},
                                   separators=(",", ":")) + "\n" for h, a in sorted(self.acc.items()))
        try:
            try:
                if os.path.getsize(self.path) > USAGE_ROTATE:
                    os.replace(self.path, self.path + ".1")
            except OSError:
                pass
            fd = os.open(self.path, os.O_WRONLY | os.O_APPEND | os.O_CREAT, 0o640)
            with os.fdopen(fd, "a") as f:
                f.write(lines)
            self.acc.clear()
        except OSError as e:
            log.error("usage log %s: %s", self.path, e)


# ================================================================== the service

class _Tail(asyncio.Protocol):
    """Keeps the first DIAG_MAX bytes of a worker's stderr (diagnostics) and discards the rest, so a
    chatty worker can never block on a full pipe or grow the supervisor's memory."""

    def __init__(self):
        self.buf = bytearray()

    def data_received(self, data):
        if len(self.buf) < DIAG_MAX:
            self.buf += data[:DIAG_MAX - len(self.buf)]

    def text(self) -> str:
        t = self.buf.decode("utf-8", "replace")
        return re.sub(r"[^\x20-\x7e]+", " ", t).strip()[:300]


DIAG_MAX = 2048


class Result:
    def __init__(self, kind, status=0, headers=(), body=b"", message=""):
        self.kind = kind   # resp | pass | error | timeout
        self.status, self.headers, self.body, self.message = status, list(headers), body, message
        self.cpu_ms = 0.0


class Service:
    def __init__(self, cfg: dict):
        self.cfg = cfg
        self.qjs = cfg["FN_QJS"]
        self.runtime = os.path.realpath(cfg["FN_RUNTIME"])
        self.sandbox = None
        self.sandbox_error = None
        abi_max = cfg.get("FN_LANDLOCK_ABI_MAX")
        try:
            if not os.path.isfile(self.runtime):
                raise SandboxError("runtime missing: " + self.runtime)
            self.runtime = self._stage_runtime(self.runtime)
            self.sandbox = Sandbox(self.qjs, read_files=[self.runtime],
                                   abi_max=None if abi_max in (None, "") else _int(abi_max, 0, 0, 64))
        except (SandboxError, OSError) as e:
            self.sandbox_error = str(e)
        self.manifest = Manifest(cfg["FN_DIR"])
        self.usage = Usage(cfg["FN_USAGE_LOG"])
        workers = _int(cfg.get("FN_WORKERS"), 0, 0, 1024) or min(32, 2 * (os.cpu_count() or 1))
        self.workers = asyncio.Semaphore(workers)
        self.site_workers = _int(cfg.get("FN_SITE_WORKERS"), 4, 1, 256)
        self.site_sems: dict = {}
        self.wall_ms = _int(cfg.get("FN_WALL_MS"), 5000, 100, 60000)
        self.startup_ms = _int(cfg.get("FN_STARTUP_MS"), 30, 0, 1000)
        self.max_fetches = _int(cfg.get("FN_MAX_FETCHES"), 8, 0, 64)
        self.fetch_timeout = _int(cfg.get("FN_FETCH_TIMEOUT_MS"), 5000, 100, 60000) / 1000.0
        self.queue_s = _int(cfg.get("FN_QUEUE_MS"), 1000, 0, 30000) / 1000.0
        self.selftest_result: dict | None = None
        self.engine = self._engine_version()

    @staticmethod
    def _stage_runtime(path: str) -> str:
        """As root, workers run as nobody (65534): when the runtime sits below a directory nobody may
        not traverse (e.g. a CI checkout under a 0750 home), use a private root-owned 0644 copy in a
        0755 directory. Never needed in production (/usr/share/pcdn/fn, read by the DynamicUser)."""
        if os.geteuid() != 0 or dac_readable(path, 65534, 65534):
            return path
        import atexit  # noqa: PLC0415
        import tempfile  # noqa: PLC0415
        d = tempfile.mkdtemp(prefix="pcdn-fn-runtime-")
        os.chmod(d, 0o755)
        dst = os.path.join(d, "runtime.js")
        with open(path, "rb") as src, open(dst, "wb") as out:
            out.write(src.read())
        os.chmod(dst, 0o644)
        atexit.register(lambda: (os.unlink(dst), os.rmdir(d)) if os.path.exists(dst) else None)
        return dst

    def _engine_version(self) -> str:
        try:
            p = subprocess.run([self.qjs, "-h"], capture_output=True, text=True, timeout=5)
            m = re.search(r"QuickJS version (\S+)", p.stdout + p.stderr)
            return "quickjs " + m.group(1) if m else "quickjs"
        except (OSError, subprocess.SubprocessError):
            return ""

    @property
    def ready(self) -> bool:
        return bool(self.sandbox and self.selftest_result and self.selftest_result.get("ok"))

    # ---------------------------------------------------------- one invocation

    async def run(self, code: str, req: dict, body: bytes, timeout_ms: int, memory_mb: int,
                  fetch_ctx: dict | None = None, on_spawn=None) -> Result:
        """Run `code` for one request in a fresh sandboxed worker. Never raises."""
        if not self.sandbox:
            return Result("error", message="sandbox unavailable: " + str(self.sandbox_error))
        timeout_ms, memory_mb = clamp_limits(timeout_ms, memory_mb)
        cpu_ms = timeout_ms + self.startup_ms
        argv = [self.qjs, "--memory-limit", str(memory_mb * 1024 * 1024), "--stack-size", str(STACK_BYTES),
                "-m", self.runtime]
        raw_code = code.encode("utf-8")
        head = json.dumps({"v": 1, "code_len": len(raw_code), "body_len": len(body), "req": req},
                          separators=(",", ":")).encode() + b"\n"
        loop = asyncio.get_running_loop()
        t0 = time.monotonic()
        deadline = t0 + self.wall_ms / 1000.0
        try:
            proc = self.sandbox.spawn(argv, cpu_ms, memory_mb)
        except (OSError, subprocess.SubprocessError) as e:
            return Result("error", message="spawn failed: " + str(e))
        res = Result("error", message="no response")
        rtrans = wtrans = etrans = diag = None
        try:
            pidfd = os.pidfd_open(proc.pid)
        except OSError as e:   # Linux < 5.3: never leave a worker behind
            os.kill(proc.pid, signal.SIGKILL)
            os.waitpid(proc.pid, 0)
            proc.returncode = -9
            for f in (proc.stdin, proc.stdout, proc.stderr):
                f.close()
            return Result("error", message="pidfd_open: " + str(e))
        try:
            reader = asyncio.StreamReader(limit=8 * 1024 * 1024)
            rtrans, _ = await loop.connect_read_pipe(lambda: asyncio.StreamReaderProtocol(reader), proc.stdout)
            etrans, diag = await loop.connect_read_pipe(_Tail, proc.stderr)
            wtrans, _ = await loop.connect_write_pipe(asyncio.BaseProtocol, proc.stdin)
            wtrans.write(head + raw_code + body)
            if on_spawn:
                on_spawn(proc)
            res = await asyncio.wait_for(self._converse(reader, wtrans, deadline, fetch_ctx, proc),
                                         timeout=max(0.0, deadline - time.monotonic()))
        except asyncio.TimeoutError:
            res = Result("timeout", message="wall-clock limit")
        except Exception as e:  # noqa: BLE001 - protocol violation by the worker
            res = Result("error", message="worker protocol: " + str(e)[:200])
        finally:
            # The transports own the pipe fds: close THEM (they unregister from the event loop at once
            # and close the fd afterwards). Closing the file objects underneath a registered transport
            # would leave a stale selector key, and the next pipe reusing that fd number would never
            # be polled.
            for t, f in ((rtrans, proc.stdout), (wtrans, proc.stdin), (etrans, proc.stderr)):
                if t is not None:
                    if not t.is_closing():
                        t.abort() if t is wtrans else t.close()
                else:
                    try:
                        f.close()
                    except OSError:
                        pass
            # never proc.poll() here: it would reap the worker and lose its rusage. The pidfd stays
            # valid until we reap, so a signal through it can never hit a recycled pid.
            grace = 0.05 if res.kind in ("resp", "pass", "error") else 0.0
            killed = not await self._exited(pidfd, loop, grace)
            if killed:
                try:
                    signal.pidfd_send_signal(pidfd, signal.SIGKILL)
                except ProcessLookupError:
                    killed = False
            status, ru = await self._reap(proc)
            os.close(pidfd)
            if diag is not None and res.kind == "error":
                await asyncio.sleep(0)   # let the stderr transport deliver what is already buffered
        used = (ru.ru_utime + ru.ru_stime) * 1000.0 if ru else 0.0
        sig = os.WTERMSIG(status) if status is not None and os.WIFSIGNALED(status) else 0
        if sig in (signal.SIGPROF, signal.SIGXCPU):
            res = Result("timeout", message="cpu limit")
        elif used > cpu_ms + 5:   # finished, but over its CPU budget (timer granularity)
            res = Result("timeout", message="cpu limit")
        elif sig and not (killed and res.kind != "error"):
            # died on its own (e.g. SIGSEGV on an engine fault); a worker WE killed after it
            # answered (pending timers) or at the wall-clock deadline keeps that classification
            res = Result("error", message=f"worker died (signal {sig})")
        if res.kind == "error" and res.message.startswith(("worker exited", "worker died", "worker protocol")):
            if status is not None and os.WIFEXITED(status):
                res.message += f" (exit status {os.WEXITSTATUS(status)})"
            if diag is not None and diag.text():
                res.message += ": " + diag.text()
        res.cpu_ms = used
        return res

    @staticmethod
    async def _exited(pidfd: int, loop, timeout: float) -> bool:
        """True once the worker behind `pidfd` has exited (waits up to `timeout` seconds)."""
        p = select.poll()   # not select(): pidfds can be >= FD_SETSIZE on a busy node
        p.register(pidfd, select.POLLIN)
        if p.poll(0):
            return True
        if timeout <= 0:
            return False
        fut = loop.create_future()
        loop.add_reader(pidfd, lambda: fut.done() or fut.set_result(True))
        try:
            await asyncio.wait_for(fut, timeout)
            return True
        except asyncio.TimeoutError:
            return False
        finally:
            loop.remove_reader(pidfd)

    async def _reap(self, proc):
        """wait4() the worker (it has exited or was SIGKILLed): -> (status, rusage)."""
        for _ in range(500):
            try:
                pid, status, ru = os.wait4(proc.pid, os.WNOHANG)
            except ChildProcessError:
                return None, None
            if pid == proc.pid:
                proc.returncode = -os.WTERMSIG(status) if os.WIFSIGNALED(status) else os.WEXITSTATUS(status)
                return status, ru
            await asyncio.sleep(0.002)
        os.kill(proc.pid, signal.SIGKILL)
        pid, status, ru = os.wait4(proc.pid, 0)
        proc.returncode = -9
        return status, ru

    async def _converse(self, reader, wtrans, deadline, fetch_ctx, proc) -> Result:
        fetches = 0
        while True:
            line = await reader.readline()
            if not line:
                return Result("error", message="worker exited without a response")
            fr = json.loads(line)
            if not isinstance(fr, dict):
                raise ValueError("bad frame")
            t = fr.get("t")
            if t == "fetch":
                blen = fr.get("body_len")
                body = b""
                if blen is not None:
                    if not isinstance(blen, int) or not 0 <= blen <= MAX_REQ_BODY:
                        raise ValueError("fetch body too large")
                    body = await reader.readexactly(blen)
                elif isinstance(fr.get("body_text"), str):
                    body = fr["body_text"].encode("utf-8", "surrogatepass")
                    if len(body) > MAX_REQ_BODY:
                        raise ValueError("fetch body too large")
                fetches += 1
                if fetch_ctx is None or fetches > self.max_fetches:
                    reply = {"error": "fetch not allowed" if fetch_ctx is None else "too many fetches"}
                    out = b""
                else:
                    reply, out = await self._fetch(fr, body, fetch_ctx, deadline, proc)
                if out:
                    reply["body_len"] = len(out)
                wtrans.write(json.dumps(reply, separators=(",", ":")).encode() + b"\n" + out)
                continue
            if t == "pass":
                return Result("pass")
            if t == "error":
                return Result("error", message=str(fr.get("message") or "")[:200])
            if t == "resp":
                status = fr.get("status")
                if not isinstance(status, int) or not 200 <= status <= 599:
                    raise ValueError("invalid status")
                body = await reader.read(MAX_RESP_BODY + 1)
                while len(body) <= MAX_RESP_BODY:
                    chunk = await reader.read(MAX_RESP_BODY + 1 - len(body))
                    if not chunk:
                        break
                    body += chunk
                if len(body) > MAX_RESP_BODY:
                    raise ValueError("response body over 5 MB")
                return Result("resp", status=status, headers=fr.get("headers") or [], body=body)
            raise ValueError("unknown frame")

    # ---------------------------------------------------------- fetch() -> own origin only

    async def _fetch(self, fr: dict, body: bytes, ctx: dict, deadline: float, proc) -> tuple[dict, bytes]:
        if ctx.get("selftest_hook"):
            return ctx["selftest_hook"](fr, proc), b""
        method = str(fr.get("method") or "GET").upper()
        url = str(fr.get("url") or "")
        if method not in METHODS:
            return {"error": "method not allowed"}, b""
        m = re.match(r"^(?:https?://([A-Za-z0-9.-]{1,253})(?::(\d{1,5}))?)?(/[^\s#]*)?(?:#.*)?$", url)
        if not m or (m.group(1) is None and m.group(3) is None):
            return {"error": "invalid url"}, b""
        host = (m.group(1) or ctx["host"]).lower()
        path = m.group(3) or "/"
        if not SAFE_PATH.match(path):
            return {"error": "invalid url"}, b""
        if not any(host_matches(h, host) for h in ctx["hosts"]):
            return {"error": "fetch is restricted to the site's own hosts"}, b""
        try:
            hdrs = clean_headers(fr.get("headers") or [], drop=HOP, drop_prefix=REQ_DROP_PREFIX + ("x-forwarded-",),
                                 cookies=False)
        except ValueError as e:
            return {"error": str(e)}, b""
        lines = [f"{method} {path} HTTP/1.0", f"Host: {host}", f"X-Pcdn-Fn-Client: {ctx['ip']}",
                 f"X-Pcdn-Fn-Site: {ctx['sid']}"]
        lines += [f"{k}: {v}" for k, v in hdrs]
        if body or method in ("POST", "PUT", "PATCH"):
            lines.append(f"Content-Length: {len(body)}")
        data = ("\r\n".join(lines) + "\r\n\r\n").encode("latin-1") + body
        budget = min(self.fetch_timeout, deadline - time.monotonic())
        if budget <= 0:
            return {"error": "timeout"}, b""
        try:
            return await asyncio.wait_for(self._fetch_io(data, method), timeout=budget)
        except asyncio.TimeoutError:
            return {"error": "timeout"}, b""
        except (OSError, ValueError, asyncio.IncompleteReadError) as e:
            return {"error": "fetch failed: " + type(e).__name__}, b""

    async def _fetch_io(self, data: bytes, method: str) -> tuple[dict, bytes]:
        r, w = await asyncio.open_unix_connection(self.cfg["FN_FETCH_SOCKET"], limit=MAX_HEAD_IN)
        try:
            w.write(data)
            await w.drain()
            head = await r.readuntil(b"\r\n\r\n")
            if len(head) > MAX_HEAD_IN:
                raise ValueError("head too large")
            lines = head.decode("latin-1").split("\r\n")
            sm = re.match(r"^HTTP/1\.[01] (\d{3})", lines[0])
            if not sm:
                raise ValueError("bad status line")
            status = int(sm.group(1))
            hdrs, clen = [], None
            for ln in lines[1:]:
                if not ln:
                    continue
                k, _, v = ln.partition(":")
                k, v = k.strip(), v.strip()
                if k.lower() == "content-length":
                    clen = int(v)
                if TOKEN.match(k) and k.lower() not in HOP:
                    hdrs.append([k, v])
            if method == "HEAD" or status in (204, 304):
                out = b""
            elif clen is not None:
                if clen > MAX_RESP_BODY:
                    raise ValueError("body too large")
                out = await r.readexactly(clen)
            else:
                out = await r.read(MAX_RESP_BODY + 1)
                while len(out) <= MAX_RESP_BODY:
                    chunk = await r.read(65536)
                    if not chunk:
                        break
                    out += chunk
                if len(out) > MAX_RESP_BODY:
                    raise ValueError("body too large")
            return {"status": status, "headers": hdrs[:MAX_HEADERS]}, out
        finally:
            w.close()

    # ---------------------------------------------------------- nginx-facing HTTP

    async def handle(self, reader: asyncio.StreamReader, writer: asyncio.StreamWriter):
        try:
            await self._handle(reader, writer)
        except Exception as e:  # noqa: BLE001 - never let one connection kill the service
            log.debug("connection: %s", e)
        finally:
            try:
                writer.close()
            except Exception:  # noqa: BLE001
                pass

    async def _handle(self, reader, writer):
        try:
            head = await asyncio.wait_for(reader.readuntil(b"\r\n\r\n"), timeout=10)
        except (asyncio.TimeoutError, asyncio.IncompleteReadError, asyncio.LimitOverrunError):
            return
        lines = head.decode("latin-1").split("\r\n")
        rl = re.match(r"^([A-Z]{1,16}) (\S+) HTTP/1\.[01]$", lines[0])
        if not rl:
            return await self._send(writer, 400, [], b"bad request")
        method = rl.group(1)
        hdrs, ctl, clen = [], {}, 0
        for ln in lines[1:]:
            if not ln:
                continue
            k, _, v = ln.partition(":")
            k, v = k.strip(), v.strip()
            low = k.lower()
            if low.startswith(FN_HDR):
                ctl[low[len(FN_HDR):]] = v
                continue
            if low == "content-length":
                try:
                    clen = int(v)
                except ValueError:
                    return await self._send(writer, 400, [], b"bad request")
                continue
            if low in HOP or low.startswith(REQ_DROP_PREFIX) or not TOKEN.match(k):
                continue
            if len(hdrs) < 128:
                hdrs.append([k, v])
        pass_loc, err_loc = ctl.get("pass", ""), ctl.get("err", "")
        if not SAFE_LOC.match(pass_loc) or not SAFE_LOC.match(err_loc):
            return await self._send(writer, 400, [], b"bad request")
        if clen > MAX_REQ_BODY or clen < 0:
            return await self._accel(writer, err_loc)
        body = await asyncio.wait_for(reader.readexactly(clen), timeout=30) if clen else b""
        sid, fid, host = ctl.get("site", ""), ctl.get("id", ""), ctl.get("host", "").lower()
        site, fn = (self.manifest.lookup(sid, fid) if SAFE_SID.match(sid) and SAFE_ID.match(fid) else (None, None))
        if site is None:   # unknown site (config propagation lag): nothing to bill
            return await self._accel(writer, err_loc)
        hosts = [h for h in (site.get("hosts") or []) if isinstance(h, str) and SAFE_HOST.match(h)]
        domain = str(site.get("domain") or "").lower()
        if host not in hosts:
            host = domain
        if not fn or not self.ready:   # unknown function, or the sandbox self-test has not passed
            self.usage.add(host, 0.0, "error")
            return await self._accel(writer, err_loc)
        code = self.manifest.source(fn.get("sha256"))
        if code is None:
            self.usage.add(host, 0.0, "error")
            return await self._accel(writer, err_loc)
        url = ctl.get("url", "")
        req = {"method": method, "url": url, "headers": hdrs,
               "client": {"ip": ctl.get("ip", "")[:64], "country": ctl.get("country", "")[:2]}}
        req_host = (re.match(r"^https?://([^/:]+)", url) or [None, host])[1].lower()
        sem = self.site_sems.setdefault(sid, asyncio.Semaphore(self.site_workers))
        try:
            await asyncio.wait_for(sem.acquire(), timeout=self.queue_s)
        except asyncio.TimeoutError:
            self.usage.add(host, 0.0, "error")
            return await self._accel(writer, err_loc)
        try:
            try:
                await asyncio.wait_for(self.workers.acquire(), timeout=self.queue_s)
            except asyncio.TimeoutError:
                self.usage.add(host, 0.0, "error")
                return await self._accel(writer, err_loc)
            try:
                ctx = {"host": req_host, "hosts": hosts, "ip": req["client"]["ip"] or "127.0.0.1", "sid": sid}
                res = await self.run(code, req, body, fn.get("timeout_ms"), fn.get("memory_mb"), ctx)
            finally:
                self.workers.release()
        finally:
            sem.release()
        if res.kind == "resp":
            try:
                out_h = clean_headers(res.headers, host=req_host, domain=domain)
            except ValueError as e:
                res = Result("error", message="invalid response headers: " + str(e))
                res.cpu_ms = 0.0
            else:
                self.usage.add(host, res.cpu_ms, "ok")
                return await self._send(writer, res.status, out_h, b"" if method == "HEAD" else res.body)
        self.usage.add(host, res.cpu_ms, "ok" if res.kind == "pass" else res.kind)
        if res.kind == "pass":
            return await self._accel(writer, pass_loc)
        log.info("site %s fn %s: %s (%s)", sid, fid, res.kind, res.message)
        return await self._accel(writer, err_loc)

    async def _accel(self, writer, loc: str):
        """Hand the request back to nginx: a named location (pass -> origin, or the error page)."""
        await self._send(writer, 200, [("X-Accel-Redirect", loc)], b"")

    async def _send(self, writer, status: int, headers, body: bytes):
        reason = "OK" if status == 200 else "Status"
        head = [f"HTTP/1.0 {status} {reason}"] + [f"{k}: {v}" for k, v in headers]
        head += [f"Content-Length: {len(body)}", "Connection: close"]
        writer.write(("\r\n".join(head) + "\r\n\r\n").encode("latin-1") + body)
        await writer.drain()

    # ---------------------------------------------------------- self-test

    async def selftest(self) -> dict:
        checks: dict = {}
        info = {"engine": self.engine, "landlock_abi": landlock_abi(), "arch": platform.machine()}
        if not self.sandbox:
            return dict(info, ok=False, error=self.sandbox_error, checks={}, t=_now_iso())
        req = {"method": "GET", "url": "http://selftest.invalid/x", "headers": [], "client": {}}
        secret = os.path.join(self.cfg["FN_DIR"], "manifest.json")

        runs = []

        async def go(code, timeout_ms=50, memory_mb=16, ctx=None):
            r = await self.run(code, req, b"", timeout_ms, memory_mb, ctx)
            runs.append(r)
            return r

        def as_json(r):
            try:
                return json.loads(r.body) if r.kind == "resp" else {}
            except ValueError:
                return {}

        r = await go("function handleRequest(r){return new Response('ok:'+r.method,{status:201})}")
        checks["engine"] = r.kind == "resp" and r.status == 201 and r.body == b"ok:GET"
        paths = ["/etc/passwd", "/etc/hostname", secret, "/proc/self/status", "/proc/1/environ", "/tmp/x"]
        r = await go("async function handleRequest(){const std=await import('std');"
                     "const p=%s;const o=p.filter(x=>{const f=std.open(x,'r');return f!==null});"
                     "const w=std.open('/tmp/pcdn-fn-w','w');"
                     "return new Response(JSON.stringify({o,w:w!==null}))}" % json.dumps(paths))
        checks["fs_denied"] = as_json(r) == {"o": [], "w": False}
        r = await go("async function handleRequest(){const os=await import('os');let x;"
                     "try{x=os.exec(['/bin/true'],{block:true})}catch(e){x='denied'}"
                     "const k=os.kill(1,0);return new Response(JSON.stringify({x:String(x),k}))}")
        d = as_json(r)
        checks["exec_denied"] = d.get("x") == "denied"
        checks["signal_denied"] = isinstance(d.get("k"), int) and d["k"] < 0
        t0 = time.monotonic()
        r = await go("function handleRequest(){for(;;){}}", timeout_ms=20)
        checks["cpu_limit"] = r.kind == "timeout" and time.monotonic() - t0 < 2.0
        r = await go("function handleRequest(){let a=[];for(;;)a.push(new Array(1e5).fill(1.5))}", memory_mb=16)
        # only meaningful when the engine itself works (a broken engine "fails" every allocation)
        checks["memory_limit"] = checks["engine"] and r.kind in ("error", "timeout")
        state = {}

        def hook(fr, proc):
            try:
                with open(f"/proc/{proc.pid}/status") as f:
                    st = dict(ln.split(":", 1) for ln in f.read().splitlines() if ":" in ln)
                state["seccomp"] = st.get("Seccomp", "").strip()
                state["nnp"] = st.get("NoNewPrivs", "").strip()
            except OSError:
                pass
            return {"status": 204, "headers": []}
        r = await go("async function handleRequest(){await fetch('/x');return new Response('y')}",
                     ctx={"selftest_hook": hook})
        checks["seccomp_active"] = r.kind == "resp" and state.get("seccomp") == "2" and state.get("nnp") == "1"
        ok = all(checks.values())
        out = dict(info, ok=ok, checks=checks, t=_now_iso())
        # why a check failed: the invocation outcome (incl. the worker's setup stage / errno / stderr)
        idx = {"engine": 0, "fs_denied": 1, "exec_denied": 2, "signal_denied": 2, "cpu_limit": 3,
               "memory_limit": 4, "seccomp_active": 5}
        details = {k: f"{runs[i].kind}: {runs[i].message}"[:300] for k, i in idx.items()
                   if not checks.get(k) and i < len(runs)}
        if details:
            out["details"] = details
        return out

    def write_status(self):
        st = dict(self.selftest_result or {"ok": False, "checks": {}, "engine": self.engine},
                  pid=os.getpid(), updated=_now_iso())
        if self.sandbox_error:
            st["error"] = self.sandbox_error
        path = self.cfg["FN_STATUS"]
        tmp = path + ".tmp"
        try:
            with open(tmp, "w") as f:
                json.dump(st, f)
            os.chmod(tmp, 0o644)
            os.replace(tmp, path)
        except OSError as e:
            log.error("status %s: %s", path, e)

    async def periodic(self):
        last_test, last_status, last_usage = 0.0, 0.0, time.monotonic()
        interval = _int(self.cfg.get("FN_SELFTEST_INTERVAL"), 3600, 60, 86400)
        flush = _int(self.cfg.get("FN_USAGE_FLUSH"), 10, 1, 300)
        while True:
            now = time.monotonic()
            try:
                if now - last_test >= interval or not self.selftest_result:
                    last_test, last_status = now, 0.0
                    try:
                        self.selftest_result = await self.selftest()
                    except Exception as e:  # noqa: BLE001 - a crashing self-test is a failed one
                        self.selftest_result = {"ok": False, "checks": {}, "error": str(e)[:200], "t": _now_iso()}
                    if not self.selftest_result.get("ok"):
                        log.error("self-test FAILED: %s", self.selftest_result)
                        last_test = now - interval + 60   # retry in a minute
                if now - last_status >= STATUS_EVERY:
                    self.write_status()
                    last_status = now
                if now - last_usage >= flush:
                    self.usage.flush()
                    last_usage = now
            except Exception as e:  # noqa: BLE001 - never stop refreshing status / usage
                log.error("periodic: %s", e)
            await asyncio.sleep(1)


def _bind(cfg: dict) -> socket.socket:
    path = cfg["FN_SOCKET"]
    try:
        os.unlink(path)
    except FileNotFoundError:
        pass
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    s.bind(path)
    grp_name = cfg.get("FN_SOCKET_GROUP") or ""
    if grp_name:
        import grp  # noqa: PLC0415
        try:
            os.chown(path, -1, grp.getgrnam(grp_name).gr_gid)
        except (KeyError, OSError) as e:
            log.error("cannot give %s to group %s: %s", path, grp_name, e)
    os.chmod(path, 0o660)
    s.listen(512)
    return s


async def serve(cfg: dict):
    svc = Service(cfg)
    if svc.sandbox_error:
        log.error("sandbox unavailable, every invocation fails (on_error): %s", svc.sandbox_error)
    sock = _bind(cfg)
    server = await asyncio.start_unix_server(svc.handle, sock=sock, limit=MAX_HEAD_IN)
    stop = asyncio.get_running_loop().create_future()
    for sig in (signal.SIGTERM, signal.SIGINT):
        asyncio.get_running_loop().add_signal_handler(sig, lambda: stop.done() or stop.set_result(True))
    task = asyncio.ensure_future(svc.periodic())
    log.info("pcdn-fn listening on %s (%s)", cfg["FN_SOCKET"], svc.engine)
    await stop
    task.cancel()
    server.close()
    svc.usage.flush()
    try:
        os.unlink(cfg["FN_SOCKET"])
    except OSError:
        pass


def main():
    logging.basicConfig(level=logging.INFO, format="%(levelname)s %(message)s")
    cfg = load_config(os.getenv("PCDN_FN_CONFIG", "/etc/pcdn/fn.conf"))
    cmd = sys.argv[1] if len(sys.argv) > 1 else "serve"
    if cmd == "selftest":
        res = asyncio.run(Service(cfg).selftest())
        print(json.dumps(res, indent=1))
        sys.exit(0 if res.get("ok") else 1)
    if cmd == "serve":
        asyncio.run(serve(cfg))
        return
    print(__doc__)
    sys.exit(2)


if __name__ == "__main__":
    main()
