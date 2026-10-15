"""
telemetry.py

Detects replaced, stale or unhealthy HOST_TRUST / HOST_RISK telemetry.

Pinned maps outlive the adg-xdp daemon, and an open map fd keeps an unpinned (replaced) map
alive, so "the map is readable" says nothing about freshness. This module:
  - reopens a pinned map when the daemon has replaced it (kernel map ID changed),
  - validates the daemon heartbeat (incarnation, liveness, map IDs, per-signal pipeline health).

This module only classifies telemetry. What to do with non-FRESH telemetry (bounded hold,
degraded actions) is decided in detector.py / policy.py.
"""

import ctypes
import json
import logging
import os
import time
from collections import namedtuple
from enum import Enum

logger = logging.getLogger("ADG-Telemetry")

BPF_OBJ_GET_INFO_BY_FD = 15

HEARTBEAT_PATH = os.environ.get("ADG_HEARTBEAT_PATH", "/run/adg/heartbeat.json")
FRESHNESS_TIMEOUT_S = float(os.environ.get("ADG_TELEMETRY_FRESHNESS_S", "5"))
# "0" only for synthetic experiments without an adg-xdp daemon (e.g. injected map values):
# freshness is then NOT enforced and only map-level failures are detected.
HEARTBEAT_REQUIRED = os.environ.get("ADG_HEARTBEAT_REQUIRED", "1") != "0"
HEARTBEAT_SCHEMA = 1


class LookupStatus(Enum):
    OK = "ok"
    NO_ENTRY = "no_entry"              # host not scored (yet); not a failure
    MAP_UNAVAILABLE = "map_unavailable"
    LOOKUP_ERROR = "lookup_error"


# value is None unless status is OK
Reading = namedtuple("Reading", "value status")


class MapRefresh(Enum):
    UNCHANGED = "unchanged"
    OPENED = "opened"
    REPLACED = "replaced"              # pin now points to a different kernel map (daemon restart)
    UNAVAILABLE = "unavailable"        # pin missing/unreadable; any previously open fd is kept


class SignalState(Enum):
    FRESH = "fresh"
    MAP_UNAVAILABLE = "map_unavailable"
    NO_HEARTBEAT = "no_heartbeat"
    HEARTBEAT_INVALID = "heartbeat_invalid"
    DAEMON_STOPPED = "daemon_stopped"  # clean shutdown; map values are frozen
    MAP_MISMATCH = "map_mismatch"      # we hold a map the current daemon does not write
    STALE = "stale"                    # no completed cycle within the freshness timeout
    STARTING = "starting"              # maps pinned, first cycle not completed
    PIPELINE_ERROR = "pipeline_error"  # last cycle had read/write errors for this signal


class BpfAttrGetInfo(ctypes.Structure):
    _fields_ = [
        ("bpf_fd", ctypes.c_uint32),
        ("info_len", ctypes.c_uint32),
        ("info", ctypes.c_uint64),
    ]


class BpfMapInfoHead(ctypes.Structure):
    # Leading fields of struct bpf_map_info; the kernel copies min(info_len, sizeof) bytes.
    _fields_ = [
        ("type", ctypes.c_uint32),
        ("id", ctypes.c_uint32),
        ("key_size", ctypes.c_uint32),
        ("value_size", ctypes.c_uint32),
        ("max_entries", ctypes.c_uint32),
        ("map_flags", ctypes.c_uint32),
    ]


def map_id_of(fd, syscall):
    """Kernel ID of the map behind `fd` (raises OSError)."""
    info = BpfMapInfoHead()
    attr = BpfAttrGetInfo()
    attr.bpf_fd = fd
    attr.info_len = ctypes.sizeof(info)
    attr.info = ctypes.addressof(info)
    syscall(BPF_OBJ_GET_INFO_BY_FD, attr)
    return info.id


def refresh_pinned(store, obj_get, syscall, close):
    """Point `store.map_fd` at whatever map is pinned now. `store` has map_fd / map_id attributes.

    The previous fd is closed only after a different, valid map has been opened, so a lookup
    never runs on a closed fd.
    """
    try:
        new_fd = obj_get()
    except OSError:
        return MapRefresh.UNAVAILABLE
    try:
        new_id = map_id_of(new_fd, syscall)
    except OSError:
        close(new_fd)
        return MapRefresh.UNAVAILABLE

    if store.map_fd is not None and store.map_id is None:
        try:
            store.map_id = map_id_of(store.map_fd, syscall)
        except OSError:
            store.map_id = None

    if store.map_fd is not None and new_id == store.map_id:
        close(new_fd)
        return MapRefresh.UNCHANGED

    old_fd = store.map_fd
    store.map_fd, store.map_id = new_fd, new_id
    if old_fd is not None:
        close(old_fd)
        return MapRefresh.REPLACED
    return MapRefresh.OPENED


_REQUIRED = {
    "schema": int, "incarnation": str, "pid": int, "state": str, "generation": int,
    "monotonic_ns": int, "trust_map_id": int, "risk_map_id": int,
    "trust_ok": bool, "risk_ok": bool,
}


def read_heartbeat(path):
    """Returns (heartbeat dict, None) or (None, SignalState explaining why it is unusable)."""
    try:
        with open(path, "r") as f:
            hb = json.load(f)
    except FileNotFoundError:
        return None, SignalState.NO_HEARTBEAT
    except (OSError, ValueError) as e:
        logger.warning("Unreadable heartbeat %s: %s", path, e)
        return None, SignalState.HEARTBEAT_INVALID
    if not isinstance(hb, dict) or hb.get("schema") != HEARTBEAT_SCHEMA:
        return None, SignalState.HEARTBEAT_INVALID
    for key, typ in _REQUIRED.items():
        # bool is a subclass of int: reject it where an int is required
        if not isinstance(hb.get(key), typ) or (typ is int and isinstance(hb.get(key), bool)):
            return None, SignalState.HEARTBEAT_INVALID
    if hb["state"] not in ("starting", "running", "stopped"):
        return None, SignalState.HEARTBEAT_INVALID
    return hb, None


class TelemetryMonitor:
    """Per-signal telemetry state, refreshed once per reconciliation cycle."""

    def __init__(self, stores, heartbeat_path=HEARTBEAT_PATH,
                 freshness_s=FRESHNESS_TIMEOUT_S, clock=time.monotonic_ns,
                 require_heartbeat=HEARTBEAT_REQUIRED):
        self.stores = stores                     # {"trust": TrustStore, "risk": RiskStore}
        self.heartbeat_path = heartbeat_path
        self.require_heartbeat = require_heartbeat
        if not require_heartbeat:
            logger.warning("ADG_HEARTBEAT_REQUIRED=0: telemetry freshness is NOT enforced")
        self.freshness_ns = int(freshness_s * 1e9)
        self.clock = clock
        self.state = {name: None for name in stores}
        # Per signal: CLOCK_MONOTONIC seconds of the daemon cycle that produced the current map
        # values (heartbeat time), or None if unknown. Values are rewritten for every scored host
        # each completed cycle, so this is the observation time of any value read while FRESH.
        self.observed_s = {name: None for name in stores}
        self.last_refresh = {}
        self.incarnation = None
        self.restarts = 0

    def check(self):
        self.last_refresh = {name: store.refresh() for name, store in self.stores.items()}
        hb, problem = read_heartbeat(self.heartbeat_path)
        if hb is not None:
            if self.incarnation is not None and hb["incarnation"] != self.incarnation:
                self.restarts += 1
                logger.warning("adg-xdp daemon restart detected: incarnation %s -> %s",
                               self.incarnation, hb["incarnation"])
            self.incarnation = hb["incarnation"]

        new_state = {name: self._classify(name, hb, problem) for name in self.stores}
        for name, st in new_state.items():
            prev = self.state[name]
            if st != prev:
                if st == SignalState.FRESH:
                    logger.info("%s telemetry FRESH (was %s)", name, prev.name if prev else "unknown")
                else:
                    logger.warning("%s telemetry DEGRADED: %s", name, st.name)
        self.state = new_state
        self.observed_s = {
            name: (hb["monotonic_ns"] / 1e9
                   if hb is not None and st == SignalState.FRESH and self.require_heartbeat else None)
            for name, st in new_state.items()
        }
        return dict(new_state)

    def _classify(self, name, hb, problem):
        if self.last_refresh[name] == MapRefresh.UNAVAILABLE:
            return SignalState.MAP_UNAVAILABLE
        if not self.require_heartbeat:
            return SignalState.FRESH
        if hb is None:
            return problem
        if hb["state"] == "stopped":
            return SignalState.DAEMON_STOPPED
        if hb["%s_map_id" % name] != self.stores[name].map_id:
            return SignalState.MAP_MISMATCH
        age = self.clock() - hb["monotonic_ns"]
        if age < 0:
            return SignalState.HEARTBEAT_INVALID   # not written on this boot's monotonic clock
        if age > self.freshness_ns:
            return SignalState.STALE
        if hb["state"] == "starting" or hb["generation"] == 0:
            return SignalState.STARTING
        if not hb["%s_ok" % name]:
            return SignalState.PIPELINE_ERROR
        return SignalState.FRESH
