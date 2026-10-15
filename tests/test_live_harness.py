"""Non-privileged tests for tests/live_harness.py: escalation, session isolation, interruption
handling (incl. signals during cleanup) and manifest-based recovery with ownership checks."""
import json
import os
import signal
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path

sys.path.insert(0, os.path.abspath(os.path.dirname(__file__)))
import live_harness as lh

PY = sys.executable
SHORT = ((signal.SIGINT, 0.5), (signal.SIGTERM, 0.5), (signal.SIGKILL, 2.0))
IGNORE_INT = "import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); time.sleep(60)"
IGNORE_INT_TERM = ("import signal,time; signal.signal(signal.SIGINT, signal.SIG_IGN); "
                   "signal.signal(signal.SIGTERM, signal.SIG_IGN); time.sleep(60)")


def alive(pid):
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    try:   # zombie = exited, not yet reaped
        return Path("/proc/%d/stat" % pid).read_text().split(")")[1].split()[0] != "Z"
    except OSError:
        return False


def wait_until(fn, timeout=10.0):
    t0 = time.time()
    while time.time() - t0 < timeout:
        if fn():
            return True
        time.sleep(0.05)
    return False


class HarnessTestBase(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp(prefix="adg-harness-test-"))
        self.saved_env = os.environ.get(lh.RUN_ENV)
        self.addCleanup(self._restore)

    def _restore(self):
        if self.saved_env is None:
            os.environ.pop(lh.RUN_ENV, None)
        else:
            os.environ[lh.RUN_ENV] = self.saved_env
        subprocess.run(["rm", "-rf", str(self.tmp)])


class TestStopEscalation(HarnessTestBase):
    def run_child(self, code):
        run = lh.LiveRun(self.tmp / "run", steps=SHORT)
        p = run.spawn("child", [PY, "-c", code], self.tmp / "child.log")
        time.sleep(0.3)                                      # let it install its handlers
        return run, run.stop("child")

    def test_cooperative_child_stops_on_sigint(self):
        _, rec = self.run_child("import time; time.sleep(60)")
        self.assertEqual(rec["signal"], "SIGINT")
        self.assertLess(rec["exit_s"], 0.5)

    def test_escalates_to_sigterm(self):
        _, rec = self.run_child(IGNORE_INT)
        self.assertEqual(rec["signal"], "SIGTERM")
        self.assertGreaterEqual(rec["exit_s"], 0.5)

    def test_escalates_to_sigkill_within_bound(self):
        _, rec = self.run_child(IGNORE_INT_TERM)
        self.assertEqual(rec["signal"], "SIGKILL")
        self.assertLess(rec["exit_s"], 2.0)

    def test_children_get_own_session_and_run_marker(self):
        run = lh.LiveRun(self.tmp / "run", steps=SHORT)
        p = run.spawn("child", ["sleep", "30"], self.tmp / "c.log")
        self.assertEqual(os.getsid(p.pid), p.pid)
        env = Path("/proc/%d/environ" % p.pid).read_bytes()
        self.assertIn(("%s=%s" % (lh.RUN_ENV, run.out)).encode(), env)
        run.stop("child")


SCRIPT = textwrap.dedent('''
    import json, os, sys, time
    sys.path.insert(0, {libdir!r})
    import live_harness as lh
    run_dir = lh.Path({run_dir!r})
    lh.ensure_own_session(run_dir)
    run = lh.LiveRun(run_dir, steps={steps!r})
    run.install_signal_handlers()
    run.mark("session", {{"pid": os.getpid(), "sid": os.getsid(0), "pgid": os.getpgid(0)}})
    child = run.spawn("child", [sys.executable, "-c", {child!r}], run_dir / "child.log")
    try:
        run.mark("ready")
        while True:
            time.sleep(0.1)
    except lh.Interrupted as e:
        run.note("interrupted by %s" % e)
    finally:
        run.cleaning = True
        run.cleanup_processes()
        (run_dir / "summary.json").write_text(json.dumps(dict(
            notes=run.notes, signals=run.signals, child_pid=child.pid, events=run.events), default=str))
''')
STEPS_REPR = [(int(s), w) for s, w in SHORT]


class TestInterruption(HarnessTestBase):
    def launch(self, child_code="import time; time.sleep(60)"):
        run_dir = self.tmp / "run"
        script = self.tmp / "scenario.py"
        script.write_text(SCRIPT.format(libdir=os.path.dirname(os.path.abspath(lh.__file__)), run_dir=str(run_dir),
                                        steps=STEPS_REPR, child=child_code))
        env = {k: v for k, v in os.environ.items() if k not in (lh.SESSION_ENV, lh.RUN_ENV)}
        # The launcher plays the interactive terminal: its own process group, like a shell job.
        launcher = subprocess.Popen([PY, str(script)], env=env, start_new_session=True,
                                    stdout=subprocess.PIPE, stderr=subprocess.STDOUT)
        out = launcher.communicate(timeout=10)[0].decode()
        self.assertIn("detached into a new session", out)
        self.assertTrue(wait_until(lambda: "ready" in json.loads((run_dir / "events.json").read_text() or "{}")
                                   if (run_dir / "events.json").exists() else False))
        session = json.loads((run_dir / "events.json").read_text())["session"]
        return run_dir, launcher, session

    def summary(self, run_dir):
        self.assertTrue(wait_until(lambda: (run_dir / "summary.json").exists(), 15), "no summary.json")
        return json.loads((run_dir / "summary.json").read_text())

    def test_detached_session_is_isolated_from_launcher_group(self):
        run_dir, launcher, session = self.launch()
        self.assertEqual(session["sid"], session["pid"], "harness must lead its own session")
        self.assertNotEqual(session["pgid"], launcher.pid)
        try:                                       # terminal Ctrl-C to the launcher's group: no effect
            os.killpg(launcher.pid, signal.SIGINT)
        except ProcessLookupError:
            pass
        time.sleep(0.5)
        self.assertTrue(alive(session["pid"]))
        self.assertFalse((run_dir / "summary.json").exists())
        os.kill(session["pid"], signal.SIGTERM)
        self.summary(run_dir)

    def test_each_signal_leads_to_cleanup_and_summary(self):
        for sig in (signal.SIGINT, signal.SIGTERM, signal.SIGHUP):
            with self.subTest(sig=sig.name):
                run_dir, _, session = self.launch()
                os.kill(session["pid"], sig)
                s = self.summary(run_dir)
                self.assertIn("interrupted by %s" % sig.name, s["notes"])
                self.assertEqual(s["signals"][0]["signal"], sig.name)
                self.assertFalse(alive(s["child_pid"]), "child left running")
                self.assertTrue(wait_until(lambda: not alive(session["pid"]), 5))
                subprocess.run(["rm", "-rf", str(run_dir)])

    def test_signal_during_cleanup_is_logged_and_ignored(self):
        run_dir, _, session = self.launch(child_code=IGNORE_INT_TERM)   # cleanup must escalate to SIGKILL
        os.kill(session["pid"], signal.SIGTERM)
        time.sleep(0.3)                                                 # now inside cleanup escalation
        os.kill(session["pid"], signal.SIGTERM)
        s = self.summary(run_dir)
        self.assertEqual([x["during_cleanup"] for x in s["signals"]], [False, True])
        self.assertEqual(s["events"]["stop_child"]["signal"], "SIGKILL")
        self.assertFalse(alive(s["child_pid"]))


class TestManifestCleanup(HarnessTestBase):
    def test_kills_only_processes_that_carry_the_run_marker(self):
        run = lh.LiveRun(self.tmp / "run", steps=SHORT)
        owned = run.spawn("owned", [PY, "-c", IGNORE_INT], self.tmp / "o.log")
        # same pid recorded but the process does not carry the marker (e.g. pid reuse)
        stranger = subprocess.Popen(["sleep", "30"], env={k: v for k, v in os.environ.items() if k != lh.RUN_ENV},
                                    start_new_session=True)
        self.addCleanup(lambda: (stranger.kill(), stranger.wait()))
        run.manifest["processes"]["stranger"] = {"pid": stranger.pid, "cmd": ["sleep"]}
        run.save_manifest()
        time.sleep(0.3)
        # harness "SIGKILLed": nothing was cleaned up; recover from the manifest only
        calls = []
        report = lh.cleanup_from_manifest(run.out, steps=SHORT, sh=lambda c: calls.append(c) or
                                          subprocess.CompletedProcess(c, 1, "", ""))
        self.assertEqual(report["processes"]["owned"], "terminated")
        self.assertIn("left alone", report["processes"]["stranger"])
        self.assertTrue(alive(stranger.pid))
        owned.wait(2)

    def test_bridge_removed_only_if_controller_matches(self):
        run = lh.LiveRun(self.tmp / "run", steps=SHORT)
        run.register_bridge("s1", "tcp:127.0.0.1:6653")
        for target, expected in (("tcp:10.9.9.9:6653", "left alone"), ("tcp:127.0.0.1:6653", "deleted")):
            calls = []

            def fake(c, target=target, calls=calls):
                calls.append(c)
                out = target if "get-controller" in c else ""
                return subprocess.CompletedProcess(c, 0, out + "\n", "")
            with self.subTest(target=target):
                report = lh.cleanup_from_manifest(run.out, steps=SHORT, sh=fake)
                self.assertIn(expected, report["bridges"]["s1"])
                self.assertEqual(any("del-br" in c for c in calls), expected == "deleted")


class TestSignalTraceParsing(unittest.TestCase):
    def test_parses_sender_and_target(self):
        line = ("           sudo-20903   [003] d..2.  4376.201: signal_generate: sig=2 errno=0 code=128 "
                "comm=python3 pid=20905 grp=1 res=0")
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as f:
            f.write(line + "\nnoise\n")
        try:
            self.assertEqual(lh.parse_signal_trace(Path(f.name)),
                             [{"scomm": "sudo", "spid": 20903, "sig": 2, "tcomm": "python3", "tpid": 20905}])
        finally:
            os.unlink(f.name)


if __name__ == '__main__':
    unittest.main()
