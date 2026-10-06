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
    REDIRECT = auto()    # Reserved for future honeypot support (Phase 3)


class PolicyConfig:
    ALLOW = 90
    LOG = 70
    MIRROR = 40

class PolicyEngine:
    def evaluate(self, trust: int, risk: int = 0) -> Action:
        # High network risk proactively forces MIRROR to isolate potential threats, overriding trust
        if risk >= 80:
            return Action.MIRROR

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