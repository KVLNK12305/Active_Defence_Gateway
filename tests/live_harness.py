"""
live_harness.py -- shared machinery for privileged live acceptance tests.

Guarantees (and their limits):
  * Session isolation: the harness re-executes itself in a new session (setsid --fork), so a signal
    sent to the launching terminal's process group (Ctrl-C, an interrupted prompt, a hangup) does
    not reach it. Its output goes to <run>/harness.log; progress to <run>/progress.log.
  * Signal handling: SIGINT/SIGTERM/SIGHUP are logged with arrival time and turned into an orderly
    abort (Interrupted); signals arriving during cleanup are logged and ignored so cleanup finishes.
  * Deterministic child termination: SIGINT -> SIGTERM -> SIGKILL with bounded waits; the step that
    worked and the exit latency are recorded per process.
  * Ownership: every process / bridge the run creates is recorded in <run>/manifest.json, and every
    spawned process carries ADG_HARNESS_RUN=<run dir> in its environment. `--cleanup <run>` removes
    only resources whose ownership still verifies against the manifest.
  * Evidence: events.json and progress.log are rewritten/appended as the run progresses; the caller
    always writes summary.json from `finally`.
  * Signal attribution (root only): a private tracefs instance records every SIGHUP/SIGINT/SIGKILL/
    SIGTERM generated on the system during the run, with sender and target.
  Limit: SIGKILL of the harness itself cannot be handled; children then survive as orphans in their
  own sessions, and `--cleanup <run>` (manifest + ownership checks) is the recovery path.
"""
import json, os, re, signal, subprocess, sys, threading, time
from pathlib import Path

RUN_ENV = "ADG_HARNESS_RUN"
SESSION_ENV = "ADG_HARNESS_SESSION"
DEFAULT_STEPS = ((signal.SIGINT, 5.0), (signal.SIGTERM, 3.0), (signal.SIGKILL, 2.0))


class Interrupted(BaseException):
    """Raised in the main thread when the harness receives SIGINT/SIGTERM/SIGHUP."""


def ensure_own_session(run_dir: Path):
    """Re-exec in a new session (detached), logging to run_dir/harness.log. Returns only in the child."""
    if os.environ.get(SESSION_ENV) == "1":
        return
    run_dir.mkdir(parents=True, exist_ok=True)
    env = dict(os.environ, **{SESSION_ENV: "1", RUN_ENV: str(run_dir)})
    log = os.open(str(run_dir / "harness.log"), os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o644)
    print("detached into a new session; evidence: %s (follow progress.log / summary.json)" % run_dir,
          flush=True)
    os.dup2(log, 1)
    os.dup2(log, 2)
    os.execvpe("setsid", ["setsid", "--fork", sys.executable] + sys.argv, env)


def _atomic_json(path: Path, obj):
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(obj, indent=2, default=str))
    os.replace(tmp, path)


class LiveRun:
    def __init__(self, run_dir: Path, steps=DEFAULT_STEPS):
        self.out = run_dir
        self.out.mkdir(parents=True, exist_ok=True)
        self.steps = steps
        self.events, self.notes, self.signals = {}, [], []
        self.procs, self.files, self.order = {}, [], []
        self.cleaning = False
        self.manifest = {"run_dir": str(run_dir), "harness_pid": os.getpid(), "processes": {}, "bridges": []}
        self._progress = open(run_dir / "progress.log", "a", buffering=1)
        os.environ[RUN_ENV] = str(run_dir)     # inherited by everything started from here (incl. Mininet hosts)
        self.save_manifest()

    # ---------- evidence ----------
    def log(self, msg):
        self._progress.write("%.3f %s\n" % (time.time(), msg))

    def mark(self, key, value=None):
        self.events[key] = time.time() if value is None else value
        self.log("event %s" % key)
        _atomic_json(self.out / "events.json", self.events)

    def note(self, msg):
        self.notes.append(msg)
        self.log("NOTE " + msg)

    def save_manifest(self):
        _atomic_json(self.out / "manifest.json", self.manifest)

    # ---------- signals ----------
    def install_signal_handlers(self):
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            signal.signal(sig, self._on_signal)

    def _on_signal(self, signo, _frame):
        name = signal.Signals(signo).name
        self.signals.append({"t": time.time(), "signal": name, "during_cleanup": self.cleaning})
        self.log("received %s%s" % (name, " (ignored: cleanup in progress)" if self.cleaning else ""))
        if not self.cleaning:
            raise Interrupted(name)

    # ---------- processes ----------
    def spawn(self, name, cmd, log_path, env=None, cwd=None):
        f = open(log_path, "wb")
        env = dict(env if env is not None else os.environ, **{RUN_ENV: str(self.out)})
        p = subprocess.Popen(cmd, stdout=f, stderr=subprocess.STDOUT, env=env, cwd=cwd, start_new_session=True)
        self.files.append(f)
        self.register_process(name, p, cmd)
        return p

    def register_process(self, name, p, cmd):
        self.procs[name] = p
        self.order.append(name)
        self.manifest["processes"][name] = {"pid": p.pid, "cmd": [str(c) for c in cmd]}
        self.save_manifest()
        self.log("started %s pid=%d" % (name, p.pid))

    def register_bridge(self, name, controller_target):
        self.manifest["bridges"].append({"name": name, "controller": controller_target})
        self.save_manifest()

    def stop(self, name, steps=None):
        """Escalating, bounded termination. Returns {signal, exit_s, returncode} (signal None = already exited)."""
        p = self.procs[name]
        rec = {"signal": None, "exit_s": 0.0, "returncode": p.poll()}
        if p.poll() is None:
            t0 = time.time()
            for sig, wait in (steps or self.steps):
                try:
                    p.send_signal(sig)
                except ProcessLookupError:
                    break
                try:
                    p.wait(wait)
                    rec = {"signal": signal.Signals(sig).name, "exit_s": round(time.time() - t0, 3),
                           "returncode": p.returncode}
                    break
                except subprocess.TimeoutExpired:
                    self.log("%s did not exit %.1fs after %s; escalating" % (name, wait, signal.Signals(sig).name))
            else:
                rec = {"signal": "UNKILLABLE", "exit_s": round(time.time() - t0, 3), "returncode": p.poll()}
            self.events["stop_" + name] = rec
            self.log("stopped %s: %s" % (name, rec))
            _atomic_json(self.out / "events.json", self.events)
            return rec
        else:
            self.log("already stopped %s: returncode=%s" % (name, p.poll()))
            if "stop_" + name not in self.events:
                self.events["stop_" + name] = rec
                _atomic_json(self.out / "events.json", self.events)
            return self.events["stop_" + name]

    def cleanup_processes(self):
        """Stop everything still running, newest first."""
        self.cleaning = True
        report = {}
        for name in reversed(self.order):
            try:
                rec = self.stop(name)
                report[name] = rec
            except Exception as e:
                self.note("stop %s failed: %r" % (name, e))
                report[name] = {"error": str(e)}
        for f in self.files:
            try:
                f.close()
            except Exception:
                pass
        return report


def run_bounded(fn, timeout, what, run: LiveRun):
    """Run fn in a thread; give up (and note it) after timeout so cleanup cannot hang forever."""
    t = threading.Thread(target=fn, daemon=True)
    t.start()
    t.join(timeout)
    if t.is_alive():
        run.note("%s did not finish within %ss" % (what, timeout))
        return False
    return True


# ---------- signal attribution via a private tracefs instance (root only) ----------
TRACE_RE = re.compile(r"^\s*(?P<scomm>.+?)-(?P<spid>\d+)\s+\[\d+\].*?signal_generate: sig=(?P<sig>\d+) "
                      r"errno=\d+ code=-?\d+ comm=(?P<tcomm>\S+) pid=(?P<tpid>\d+)")


class SignalTracer:
    SIGS = (1, 2, 9, 15)

    def __init__(self, run: LiveRun, name):
        self.run = run
        self.out_file = run.out / "signals_trace.log"
        base = Path("/sys/kernel/tracing")
        if not (base / "instances").exists():
            base = Path("/sys/kernel/debug/tracing")
        self.inst = base / "instances" / name
        self.fd, self.thread, self.stop_ev = None, None, threading.Event()

    def start(self):
        try:
            self.inst.mkdir()
            ev = self.inst / "events" / "signal" / "signal_generate"
            (ev / "filter").write_text(" || ".join("sig == %d" % s for s in self.SIGS))
            (ev / "enable").write_text("1")
            self.fd = os.open(str(self.inst / "trace_pipe"), os.O_RDONLY | os.O_NONBLOCK)
        except OSError as e:
            self.run.note("signal tracing unavailable: %r" % (e,))
            return False
        self.thread = threading.Thread(target=self._pump, daemon=True)
        self.thread.start()
        return True

    def _pump(self):
        fd = self.fd
        assert fd is not None
        with open(self.out_file, "ab") as f:
            while not self.stop_ev.is_set():
                try:
                    data = os.read(fd, 65536)
                    if data:
                        f.write(data); f.flush()
                        continue
                except BlockingIOError:
                    pass
                time.sleep(0.2)

    def stop(self):
        if self.thread is None:
            return
        try:
            (self.inst / "events" / "signal" / "signal_generate" / "enable").write_text("0")
        except OSError:
            pass
        time.sleep(0.3)
        self.stop_ev.set()
        self.thread.join(3)
        if self.fd is not None:
            os.close(self.fd)
        try:
            self.inst.rmdir()
        except OSError as e:
            self.run.note("could not remove tracefs instance %s: %r" % (self.inst, e))


def parse_signal_trace(path: Path):
    out = []
    if not path.exists():
        return out
    for ln in path.read_text(errors="replace").splitlines():
        m = TRACE_RE.search(ln)
        if m:
            out.append({k: (int(v) if k in ("spid", "sig", "tpid") else v) for k, v in m.groupdict().items()})
    return out


# ---------- recovery after the harness itself was killed ----------
def _owned(pid, run_dir):
    """True only if pid is alive and its environment carries this run's marker."""
    try:
        env = Path("/proc/%d/environ" % pid).read_bytes().split(b"\0")
    except OSError:
        return False
    return ("%s=%s" % (RUN_ENV, run_dir)).encode() in env


def cleanup_from_manifest(run_dir: Path, steps=DEFAULT_STEPS, sh=None):
    """Remove only resources recorded in run_dir/manifest.json whose ownership still verifies."""
    manifest = json.loads((run_dir / "manifest.json").read_text())
    report = {"processes": {}, "bridges": {}}
    for name, rec in manifest["processes"].items():
        pid = rec["pid"]
        if not _owned(pid, manifest["run_dir"]):
            report["processes"][name] = "not running or ownership not verified (left alone)"
            continue
        for sig, wait in steps:
            try:
                os.kill(pid, sig)
            except ProcessLookupError:
                break
            t0 = time.time()
            while time.time() - t0 < wait and Path("/proc/%d" % pid).exists():
                time.sleep(0.1)
            if not _owned(pid, manifest["run_dir"]):
                break
        report["processes"][name] = "terminated" if not _owned(pid, manifest["run_dir"]) else "STILL ALIVE"
    run_cmd = sh or (lambda c: subprocess.run(c, shell=True, capture_output=True, text=True, timeout=20))
    for br in manifest["bridges"]:
        target = run_cmd("ovs-vsctl get-controller %s" % br["name"]).stdout.strip()
        if run_cmd("ovs-vsctl br-exists %s" % br["name"]).returncode != 0:
            report["bridges"][br["name"]] = "absent"
        elif target != br["controller"]:
            report["bridges"][br["name"]] = "controller %r != recorded %r (left alone)" % (target, br["controller"])
        else:
            run_cmd("ovs-vsctl del-br %s" % br["name"])
            report["bridges"][br["name"]] = "deleted"
    _atomic_json(run_dir / ("cleanup_report_%d.json" % int(time.time())), report)
    return report
