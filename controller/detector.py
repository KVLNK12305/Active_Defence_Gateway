import os
from os_ken.lib import hub
from flow import IP_POLICY_PRIORITY
from utils import get_logger

logger = get_logger("ADG-Detector")


class TrustChangeDetector:
    """Background policy reconciler (class name kept for compatibility).

    Every cycle re-evaluates trust AND risk for each known host with the same `decide()` used by
    the PacketIn path, and makes the ADG IP-level rule on every datapath match that desired
    action. Risk changes therefore take effect without a new PacketIn, and stale tiers are
    replaced rather than left behind.
    """

    INTERVAL_S = 2

    def __init__(self, controller):
        self.controller = controller
        self.known_hosts = set()
        # (dpid, ip) -> Action this controller last applied; missing = unknown, re-asserted next cycle
        self.installed = {}
        self.monitor_thread = hub.spawn(self._monitor)

    def register_host(self, ip):
        """Register an IP to be monitored by the background thread"""
        self.known_hosts.add(ip)

    def decide(self, ip):
        """Single policy decision for both enforcement paths. Returns (trust, risk, action)."""
        trust = self.controller.trust_store.get(ip)
        mock_trust = os.environ.get("ADG_MOCK_TRUST")
        if mock_trust:
            trust = int(mock_trust)
        risk = self.controller.risk_store.get(ip)
        return trust, risk, self.controller.policy_engine.evaluate(trust, risk)

    def enforce(self, datapath, ip, action):
        """Idempotently apply `action` for `ip` on `datapath`. Returns True if rules were sent."""
        key = (datapath.id, ip)
        if self.installed.get(key) == action:
            return False
        self.controller.flow_installer.install_ip_policy_flow(datapath, ip, action)
        self.installed[key] = action
        return True

    def reconcile_once(self):
        datapaths = list(self.controller.datapaths.values())
        if not datapaths:
            return
        for ip in list(self.known_hosts):
            trust, risk, action = self.decide(ip)
            changed = [dp.id for dp in datapaths if self.enforce(dp, ip, action)]
            if changed:
                logger.info("[POLICY UPDATE] Host=%s Trust=%s Risk=%s Action=%s Datapaths=%s",
                            ip, trust, risk, action.name, changed)

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
