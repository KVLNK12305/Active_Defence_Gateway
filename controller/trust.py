import ctypes
import errno
import os
import socket
import struct
import logging

from telemetry import LookupStatus, Reading, refresh_pinned, MapRefresh

logger = logging.getLogger("ADG-Trust")

# syscall numbers and constants
__NR_bpf = 321
BPF_OBJ_GET = 7
BPF_MAP_LOOKUP_ELEM = 1

HOST_TRUST_MAP_PATH = "/sys/fs/bpf/HOST_TRUST"

class BpfAttrObjGet(ctypes.Structure):
    _fields_ = [
        ("pathname", ctypes.c_uint64),
        ("bpf_fd", ctypes.c_uint32),
        ("file_flags", ctypes.c_uint32),
    ]

class BpfAttrMapLookupElem(ctypes.Structure):
    _fields_ = [
        ("map_fd", ctypes.c_uint32),
        ("key", ctypes.c_uint64),
        ("value", ctypes.c_uint64),
        ("flags", ctypes.c_uint64),
    ]

class TrustEntry(ctypes.Structure):
    _fields_ = [
        ("score", ctypes.c_uint8),
        ("level", ctypes.c_uint8),
        ("version", ctypes.c_uint8),
        ("flags", ctypes.c_uint8),
    ]

libc = ctypes.CDLL("libc.so.6", use_errno=True)

def bpf_syscall(cmd, attr_struct):
    # bpf_attr is exactly 144 bytes on modern linux
    buffer = ctypes.create_string_buffer(144)
    ctypes.memmove(buffer, ctypes.byref(attr_struct), ctypes.sizeof(attr_struct))
    
    ret = libc.syscall(__NR_bpf, cmd, ctypes.byref(buffer), 144)
    if ret < 0:
        err = ctypes.get_errno()
        raise OSError(err, os.strerror(err))
    return ret

class TrustStore:
    DEFAULT_TRUST = 100  # get() fallback for legacy callers; the controller uses read() + hold policy
    _close = staticmethod(os.close)  # injectable for tests

    def __init__(self):
        self.map_fd = None
        self.map_id = None
        self._open_map()

    def _obj_get(self):
        path_bytes = HOST_TRUST_MAP_PATH.encode('utf-8')
        attr = BpfAttrObjGet()
        attr.pathname = ctypes.cast(ctypes.c_char_p(path_bytes), ctypes.c_void_p).value
        attr.bpf_fd = 0
        attr.file_flags = 0
        return bpf_syscall(BPF_OBJ_GET, attr)

    def refresh(self) -> MapRefresh:
        """Reopen HOST_TRUST if the daemon re-pinned a new map (restart)."""
        result = refresh_pinned(self, self._obj_get, lambda cmd, attr: bpf_syscall(cmd, attr), self._close)
        if result == MapRefresh.REPLACED:
            logger.warning("HOST_TRUST map was replaced (daemon restart); reopened map id %s", self.map_id)
        return result

    def _open_map(self):
        try:
            self.map_fd = self._obj_get()
            self.map_id = None
            logger.info("Successfully opened HOST_TRUST map.")
        except OSError as e:
            # We don't crash if the map isn't there, we just fallback.
            logger.warning("Could not open HOST_TRUST map at %s: %s", HOST_TRUST_MAP_PATH, e)
            self.map_fd = None

    def get(self, ip: str) -> int:
        reading = self.read(ip)
        return reading.value if reading.status == LookupStatus.OK else self.DEFAULT_TRUST

    def read(self, ip: str) -> Reading:
        """Trust score with an explicit status; NO_ENTRY is distinct from map/lookup failures."""
        if self.map_fd is None:
            self._open_map()
            if self.map_fd is None:
                logger.error("HOST_TRUST map unavailable; cannot determine trust for %s", ip)
                return Reading(None, LookupStatus.MAP_UNAVAILABLE)

        try:
            ip_bytes = socket.inet_aton(ip)
            # Rust Ipv4Addr::into() for u32 produces (a<<24)|(b<<16)... (big-endian integer representation)
            ip_u32 = struct.unpack("!I", ip_bytes)[0]
            
            key = ctypes.c_uint32(ip_u32)
            value = TrustEntry()
            
            attr = BpfAttrMapLookupElem()
            attr.map_fd = self.map_fd
            attr.key = ctypes.cast(ctypes.byref(key), ctypes.c_void_p).value
            attr.value = ctypes.cast(ctypes.byref(value), ctypes.c_void_p).value
            attr.flags = 0

            bpf_syscall(BPF_MAP_LOOKUP_ELEM, attr)
            
            return Reading(value.score, LookupStatus.OK)
        except OSError as e:
            if e.errno == errno.ENOENT:  # ENOENT: host is not currently in HOST_TRUST
                logger.debug(
                    "No trust entry for %s; using default trust 100",
                    ip
                )
                return Reading(None, LookupStatus.NO_ENTRY)

            logger.error(
                "HOST_TRUST lookup failed for %s: %s",
                ip,
                e
            )
            return Reading(None, LookupStatus.LOOKUP_ERROR)
        except Exception as e:
            logger.exception(
                "Unexpected HOST_TRUST lookup error for %s",
                ip
            )
            return Reading(None, LookupStatus.LOOKUP_ERROR)