"""Constructors for the four telemetry types, in flat ECS-style fields.

Timestamps are epoch seconds while generating and are rendered to ISO-8601
when written. ``_scn`` tags an event with the scenario that produced it; it
is stripped before the event stream is written and lives only in the
separate ground-truth file.
"""
from __future__ import annotations

from typing import Any

RESULT_OK = "0"
RESULT_BAD_PASSWORD = "50126"
RESULT_MFA_DENIED = "500121"


def signin(ts: float, user: str, ip: str, *, ok: bool, app: str = "Portal",
           mfa: str = "approved", auth: str = "multiFactor", scn: str | None = None,
           result: str | None = None) -> dict[str, Any]:
    code = result or (RESULT_OK if ok else RESULT_BAD_PASSWORD)
    return {"_ts": ts, "_scn": scn, "event.dataset": "identity.signin",
            "event.outcome": "success" if code == RESULT_OK else "failure",
            "user.name": user, "source.ip": ip, "identity.app": app,
            "identity.result_code": code, "identity.mfa_result": mfa,
            "identity.auth_requirement": auth}


def logon(ts: float, host: str, user: str, src_ip: str, *, ok: bool, logon_type: int = 3,
          scn: str | None = None) -> dict[str, Any]:
    return {"_ts": ts, "_scn": scn, "event.dataset": "windows.security",
            "event.code": "4624" if ok else "4625",
            "event.outcome": "success" if ok else "failure",
            "host.name": host, "user.name": user, "source.ip": src_ip,
            "winlog.logon.type": str(logon_type)}


def dns(ts: float, host: str, src_ip: str, qname: str, *, qtype: str = "A",
        rcode: str = "NOERROR", scn: str | None = None) -> dict[str, Any]:
    return {"_ts": ts, "_scn": scn, "event.dataset": "network.dns",
            "host.name": host, "source.ip": src_ip, "dns.question.name": qname,
            "dns.question.type": qtype, "dns.response_code": rcode}


def conn(ts: float, host: str, src_ip: str, dst_ip: str, *, port: int = 443,
         bytes_out: int = 2000, bytes_in: int = 20000, duration: float = 1.0,
         scn: str | None = None) -> dict[str, Any]:
    return {"_ts": ts, "_scn": scn, "event.dataset": "network.connection",
            "host.name": host, "source.ip": src_ip, "destination.ip": dst_ip,
            "destination.port": port, "network.transport": "tcp",
            "source.bytes": int(bytes_out), "destination.bytes": int(bytes_in),
            "event.duration": round(duration, 3)}
