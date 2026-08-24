"""Python bridge to the C central IDS runtime (libids_central.so)."""

from __future__ import annotations

import ctypes
import json
import logging
import os
import time

logger = logging.getLogger("coreids.ids_bridge")

_lib = None

def _load_lib():
    global _lib
    if _lib is not None:
        return _lib

    # Look for the shared library next to this file
    lib_path = os.path.join(os.path.dirname(__file__), "..", "libids_central.so")
    lib_path = os.path.abspath(lib_path)
    if not os.path.exists(lib_path):
        raise FileNotFoundError(f"libids_central.so not found at {lib_path}")

    _lib = ctypes.CDLL(lib_path)

    # Set up function signatures
    _lib.ids_central_create.restype = ctypes.c_void_p
    _lib.ids_central_create.argtypes = []

    _lib.ids_central_destroy.argtypes = [ctypes.c_void_p]

    _lib.ids_central_ingest.restype = ctypes.c_int
    _lib.ids_central_ingest.argtypes = [
        ctypes.c_void_p,           # handle
        ctypes.c_char_p,           # user_id
        ctypes.c_char_p,           # src_ip
        ctypes.c_int,              # src_port
        ctypes.c_char_p,           # dst_ip
        ctypes.c_int,              # dst_port
        ctypes.c_int,              # protocol
        ctypes.c_long,             # bytes
        ctypes.c_char_p,           # event_type
        ctypes.c_double,           # unix_ts
        ctypes.POINTER(ctypes.c_char_p),  # alert_json_out
    ]

    _lib.ids_central_free_string.argtypes = [ctypes.c_char_p]

    # Batch API
    _lib.ids_central_ingest_batch.restype = ctypes.c_int
    _lib.ids_central_ingest_batch.argtypes = [
        ctypes.c_void_p,           # handle
        ctypes.c_char_p,           # user_id
        ctypes.POINTER(ctypes.c_char_p),  # src_ips
        ctypes.POINTER(ctypes.c_int),      # src_ports
        ctypes.POINTER(ctypes.c_char_p),  # dst_ips
        ctypes.POINTER(ctypes.c_int),      # dst_ports
        ctypes.POINTER(ctypes.c_int),      # protocols
        ctypes.POINTER(ctypes.c_long),     # bytes
        ctypes.POINTER(ctypes.c_char_p),  # event_types
        ctypes.POINTER(ctypes.c_double),   # unix_ts
        ctypes.c_int,              # batch_size
        ctypes.POINTER(ctypes.POINTER(ctypes.c_char_p)),  # alerts_json_out
        ctypes.POINTER(ctypes.c_int),      # num_alerts_out
    ]

    _lib.ids_central_free_alerts.argtypes = [
        ctypes.POINTER(ctypes.c_char_p),
        ctypes.c_int,
    ]

    return _lib


class CentralRuntime:
    def __init__(self):
        self._handle = None

    def start(self):
        if self._handle:
            return  # already started
        lib = _load_lib()
        self._handle = lib.ids_central_create()

    def stop(self):
        if self._handle:
            lib = _load_lib()
            lib.ids_central_destroy(self._handle)
            self._handle = None

    def ingest(self, user_id: str, src_ip: str, src_port: int,
               dst_ip: str, dst_port: int, protocol: int, bytes_count: int,
               event_type: str, timestamp: float):
        if not self._handle:
            return None

        lib = _load_lib()
        alert_out = ctypes.c_char_p()

        result = lib.ids_central_ingest(
            self._handle,
            user_id.encode(),
            src_ip.encode(),
            src_port,
            dst_ip.encode(),
            dst_port,
            protocol,
            bytes_count,
            event_type.encode(),
            ctypes.c_double(timestamp),
            ctypes.byref(alert_out),
        )

        if result and alert_out.value:
            try:
                alert = json.loads(alert_out.value.decode())
                return alert
            finally:
                lib.ids_central_free_string(alert_out)

        return None

    def ingest_batch(self, user_id: str, events):
        """Ingest multiple events for the same user in one C call."""
        if not self._handle or not events:
            return []

        lib = _load_lib()
        n = len(events)

        # Build parallel arrays for C
        src_ips = (ctypes.c_char_p * n)()
        src_ports = (ctypes.c_int * n)()
        dst_ips = (ctypes.c_char_p * n)()
        dst_ports = (ctypes.c_int * n)()
        protocols = (ctypes.c_int * n)()
        bytes_arr = (ctypes.c_long * n)()
        event_types = (ctypes.c_char_p * n)()
        timestamps = (ctypes.c_double * n)()

        for i, ev in enumerate(events):
            src_ips[i] = ev.get("src_ip", "").encode()
            src_ports[i] = ev.get("src_port", 0)
            dst_ips[i] = ev.get("dst_ip", "").encode()
            dst_ports[i] = ev.get("dst_port", 0)
            protocols[i] = ev.get("protocol", 0)
            bytes_arr[i] = ev.get("bytes", 0)
            event_types[i] = ev.get("event_type", "network").encode()
            timestamps[i] = ev.get("timestamp", time.time())

        alerts_out = ctypes.POINTER(ctypes.c_char_p)()
        num_alerts = ctypes.c_int(0)

        try:
            lib.ids_central_ingest_batch(
                self._handle,
                user_id.encode(),
                src_ips, src_ports,
                dst_ips, dst_ports,
                protocols, bytes_arr,
                event_types, timestamps,
                n,
                ctypes.byref(alerts_out),
                ctypes.byref(num_alerts),
            )

            if num_alerts.value > 0 and alerts_out:
                # Guard against C bridge returning count larger than allocated
                max_alerts = n  # at most one alert per event
                if num_alerts.value > max_alerts:
                    logger.error("Bridge returned %d alerts for %d events (capped at %d)",
                                 num_alerts.value, n, max_alerts)
                    num_alerts.value = max_alerts
                alerts = []
                for i in range(num_alerts.value):
                    try:
                        alerts.append(json.loads(alerts_out[i].decode()))
                    except (json.JSONDecodeError, ValueError):
                        pass
                lib.ids_central_free_alerts(alerts_out, num_alerts.value)
                return alerts
        except Exception as exc:
            logger.error("Bridge batch call failed: %s", exc)

        return []


# Global singleton
_runtime = None


def get_runtime() -> CentralRuntime:
    global _runtime
    if _runtime is None:
        _runtime = CentralRuntime()
    return _runtime
