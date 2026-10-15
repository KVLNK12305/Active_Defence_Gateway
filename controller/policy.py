"""
policy.py

Active Defense Gateway Policy Engine

This module contains all security decision logic.
The controller should NEVER make security decisions directly.
"""

import os
from collections import namedtuple
from enum import Enum, auto


class Action(Enum):
    ALLOW = auto()
    DROP = auto()
    MIRROR = auto()      # IDS packet inspection


class PolicyConfig:
    ALLOW = 90
    LOG = 70
    MIRROR = 40
    RISK_MIRROR = 80


class Quality(Enum):
    VALID = "valid"              # read from fresh telemetry
    PROVISIONAL = "provisional"  # first contact: host not scored yet, bootstrap value (not an assessment)
    HELD = "held"                # last valid value, within the hold window
    UNAVAILABLE = "unavailable"  # no usable value: degraded telemetry and no (unexpired) hold


# value is None iff quality is UNAVAILABLE
Resolved = namedtuple("Resolved", "value quality")


def _env_action(name, default):
    value = os.environ.get(name, default).upper()
    if value not in Action.__members__:
        raise ValueError("%s must be one of %s, got %r" % (name, list(Action.__members__), value))
    return Action[value]


class DegradedConfig:
    """Explicit behaviour when telemetry cannot be trusted. All values are configurable."""
    MAX_HOLD_S = float(os.environ.get("ADG_HOLD_MAX_S", "30"))
    # First contact (fresh telemetry, host has no entry yet): the existing defaults, marked PROVISIONAL.
    BOOTSTRAP_TRUST = int(os.environ.get("ADG_BOOTSTRAP_TRUST", "100"))
    BOOTSTRAP_RISK = int(os.environ.get("ADG_BOOTSTRAP_RISK", "0"))
    # Trust unavailable (hold expired or never valid while degraded): fail closed.
    TRUST_UNAVAILABLE_ACTION = _env_action("ADG_TRUST_UNAVAILABLE_ACTION", "DROP")
    # Risk unavailable while trust permits ALLOW: risk could at most have escalated to MIRROR.
    RISK_UNAVAILABLE_ACTION = _env_action("ADG_RISK_UNAVAILABLE_ACTION", "MIRROR")

class PolicyEngine:
    def evaluate(self, trust: int, risk: int = 0) -> Action:
        """Precedence: trust decides first; risk may only escalate it.

        trust action | risk < 80 | risk >= 80
        ALLOW        | ALLOW     | MIRROR
        MIRROR       | MIRROR    | MIRROR
        DROP         | DROP      | DROP   (risk never weakens DROP)
        """
        action = self._trust_action(trust)
        if risk >= PolicyConfig.RISK_MIRROR and action == Action.ALLOW:
            return Action.MIRROR
        return action

    def decide_resolved(self, trust: Resolved, risk: Resolved) -> Action:
        """Same precedence as `evaluate`, extended to unavailable signals.

        trust part: trust action, or TRUST_UNAVAILABLE_ACTION if trust is unavailable
        If the trust part is MIRROR or DROP it is final: risk (or its absence) only acts on ALLOW.
        risk part (trust part is ALLOW): MIRROR if risk >= 80, ALLOW if lower,
                                         RISK_UNAVAILABLE_ACTION if risk is unavailable.
        For VALID / PROVISIONAL / HELD values this equals evaluate(trust.value, risk.value).
        """
        if trust.quality == Quality.UNAVAILABLE:
            trust_part = DegradedConfig.TRUST_UNAVAILABLE_ACTION
        else:
            trust_part = self._trust_action(trust.value)
        if trust_part != Action.ALLOW:
            return trust_part
        if risk.quality == Quality.UNAVAILABLE:
            return DegradedConfig.RISK_UNAVAILABLE_ACTION
        return Action.MIRROR if risk.value >= PolicyConfig.RISK_MIRROR else Action.ALLOW

    def _trust_action(self, trust: int) -> Action:
        if trust >= PolicyConfig.ALLOW:
            return Action.ALLOW
            
        elif trust >= PolicyConfig.LOG:
            # For 70 <= trust < 90, log internally but ALLOW
            # In a real implementation this would emit a log event.
            return Action.ALLOW
            
        elif trust >= PolicyConfig.MIRROR:
            return Action.MIRROR
            
        else:
            return Action.DROP