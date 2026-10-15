import os
import time
from collections import namedtuple
from os_ken.lib import hub
from flow import IP_POLICY_PRIORITY
from policy import DegradedConfig, Quality, Resolved
from telemetry import LookupStatus, Reading, SignalState
from utils import get_logger

logger = get_logger("ADG-Detector")

Assessment = namedtuple("Assessment", "trust risk action")   # trust/risk are policy.Resolved


class TrustChangeDetector:
    """Background policy reconciler (class name kept for compatibility).

    Every cycle re-evaluates trust AND risk for each known host with the same `assess()` used by
    the PacketIn path, and makes the ADG IP-level rule on every datapath match that desired
    action. Risk changes therefore take effect without a new PacketIn, and stale tiers are
    replaced rather than left behind.

    Telemetry handling (per signal, per host):
      fresh telemetry + value       -> VALID; remembered with its observation time
      never scored + fresh telemetry + no entry
                                    -> PROVISIONAL bootstrap value (first contact)
      previously scored, and no new valid value (stale/degraded telemetry, map/lookup error,
      or the entry disappeared, e.g. after a daemon restart)
                                    -> HELD last valid value within the hold window,
                                       then UNAVAILABLE (explicit degraded action in policy.py)
      never scored + degraded       -> UNAVAILABLE
    Invariant: no held value is authoritative more than DegradedConfig.MAX_HOLD_S after its
    observation. The observation time is the heartbeat time of the daemon cycle that wrote it
    (controller read time only when no heartbeat is available), so a value read just before
    staleness is detected cannot extend the hold.
    """

    INTERVAL_S = 2
    SIGNALS = ("trust", "risk")

    def __init__(self, controller, clock=time.monotonic):
        self.controller = controller
        self.clock = clock
        self.known_hosts = set()
        # (dpid, ip) -> Action this controller last applied; missing = unknown, re-asserted next cycle
        self.installed = {}
        # (signal, ip) -> (value, monotonic seconds of the observation)
        self.last_valid = {}
        # (signal, ip) -> Quality last reported, for transition logging
        self.quality = {}
        self.both_degraded = False
        self.monitor_thread = hub.spawn(self._monitor)

    def register_host(self, ip):
        """Register an IP to be monitored by the background thread"""
        self.known_hosts.add(ip)

    def _resolve(self, signal, ip, reading, telemetry_state, observed, now):
        key = (signal, ip)
        degraded = (telemetry_state not in (None, SignalState.FRESH)
                    or reading.status in (LookupStatus.MAP_UNAVAILABLE, LookupStatus.LOOKUP_ERROR))
        if not degraded and reading.status == LookupStatus.OK:
            self.last_valid[key] = (reading.value, observed if observed is not None else now)
            return Resolved(reading.value, Quality.VALID)

        last = self.last_valid.get(key)
        if last is not None:   # previously scored: never fall back to the first-contact default
            if now - last[1] <= DegradedConfig.MAX_HOLD_S:
                return Resolved(last[0], Quality.HELD)
            return Resolved(None, Quality.UNAVAILABLE)
        if not degraded:       # never scored, fresh telemetry, no entry: first contact
            bootstrap = DegradedConfig.BOOTSTRAP_TRUST if signal == "trust" else DegradedConfig.BOOTSTRAP_RISK
            return Resolved(bootstrap, Quality.PROVISIONAL)
        return Resolved(None, Quality.UNAVAILABLE)

    def assess(self, ip):
        """Single policy decision for both enforcement paths."""
        c = self.controller
        telemetry = getattr(c, "telemetry", None)
        states = telemetry.state if telemetry is not None else {}
        observed = getattr(telemetry, "observed_s", None) or {}
        now = self.clock()
        readings = {"trust": c.trust_store.read(ip), "risk": c.risk_store.read(ip)}
        mock_trust = os.environ.get("ADG_MOCK_TRUST")
        if mock_trust:
            readings["trust"] = Reading(int(mock_trust), LookupStatus.OK)
        resolved = {s: self._resolve(s, ip, readings[s], states.get(s), observed.get(s), now)
                    for s in self.SIGNALS}
        self._log_quality(ip, resolved)
        action = c.policy_engine.decide_resolved(resolved["trust"], resolved["risk"])
        return Assessment(resolved["trust"], resolved["risk"], action)

    def decide(self, ip):
        """Returns (trust, risk, action); trust/risk are None when unavailable."""
        a = self.assess(ip)
        return a.trust.value, a.risk.value, a.action

    def _log_quality(self, ip, resolved):
        for signal, r in resolved.items():
            prev = self.quality.get((signal, ip))
            if r.quality == prev:
                continue
            self.quality[(signal, ip)] = r.quality
            if r.quality == Quality.UNAVAILABLE:
                logger.error("[TELEMETRY ALERT] Host=%s %s unavailable (no valid value within %ss hold); "
                             "applying degraded policy", ip, signal, DegradedConfig.MAX_HOLD_S)
            elif r.quality == Quality.HELD:
                logger.warning("Host=%s %s HELD at last valid value %s", ip, signal, r.value)
            elif prev in (Quality.HELD, Quality.UNAVAILABLE):
                logger.info("Host=%s %s recovered (%s)", ip, signal, r.quality.name)

    def enforce(self, datapath, ip, action):
        """Idempotently apply `action` for `ip` on `datapath`. Returns True if rules were sent."""
        key = (datapath.id, ip)
        if self.installed.get(key) == action:
            return False
        self.controller.flow_installer.install_ip_policy_flow(datapath, ip, action)
        self.installed[key] = action
        return True

    def reconcile_once(self):
        # Reopen replaced maps and classify telemetry freshness before reading any value, so
        # recovered telemetry is applied in the same cycle it is detected.
        telemetry = getattr(self.controller, "telemetry", None)
        if telemetry is not None:
            states = telemetry.check()
            both = bool(states) and all(st != SignalState.FRESH for st in states.values())
            if both and not self.both_degraded:      # alert on the transition, not every cycle
                logger.error("[TELEMETRY ALERT] trust and risk telemetry both degraded: %s",
                             {k: v.name for k, v in states.items()})
            elif not both and self.both_degraded:
                logger.info("Telemetry no longer fully degraded: %s", {k: v.name for k, v in states.items()})
            self.both_degraded = both
        datapaths = list(self.controller.datapaths.values())
        if not datapaths:
            return
        for ip in list(self.known_hosts):
            a = self.assess(ip)
            changed = [dp.id for dp in datapaths if self.enforce(dp, ip, a.action)]
            if changed:
                logger.info("[POLICY UPDATE] Host=%s Trust=%s(%s) Risk=%s(%s) Action=%s Datapaths=%s",
                            ip, a.trust.value, a.trust.quality.name, a.risk.value, a.risk.quality.name,
                            a.action.name, changed)

    def on_rule_removed(self, dpid, ip, priority):
        """An ADG IP-level rule left the switch (idle timeout or another controller's delete).
        Forget it only if it is the tier we believe is active, so the next cycle re-asserts it."""
        key = (dpid, ip)
        action = self.installed.get(key)
        if action is not None and IP_POLICY_PRIORITY.get(action) == priority:
            del self.installed[key]

    def forget_datapath(self, dpid):
        """A (re)connected switch may not hold our rules; re-assert everything on it next cycle."""
        for key in [k for k in self.installed if k[0] == dpid]:
            del self.installed[key]

    def _monitor(self):
        """Background loop re-evaluating policy for all known hosts"""
        while True:
            hub.sleep(self.INTERVAL_S)
            try:
                self.reconcile_once()
            except Exception:
                logger.exception("Policy reconciliation cycle failed")
