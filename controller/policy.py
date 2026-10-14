"""
policy.py

Active Defense Gateway Policy Engine

This module contains all security decision logic.
The controller should NEVER make security decisions directly.
"""

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

class PolicyEngine:
    def evaluate(self, trust: int, risk: int = 0) -> Action:
        # High network risk can only escalate the trust decision (ALLOW -> MIRROR); it never
        # weakens DROP, so the PacketIn path agrees with the trust-only TrustChangeDetector.
        action = self._trust_action(trust)
        if risk >= PolicyConfig.RISK_MIRROR and action == Action.ALLOW:
            return Action.MIRROR
        return action

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