"""Processing pipeline: map Sigma's generic taxonomy onto this lab's schema.

Sigma rules are written against vendor-neutral field names
(``TargetUserName``, ``IpAddress``). A backend needs a pipeline that says
which log source a rule applies to and what each field is called in the
store. Events here use flat, ECS-style keys (``user.name``, ``source.ip``).
Fields not listed pass through unchanged, so enrichment fields such as
``user.privileged`` or ``source.geo.first_seen`` can be used directly.
"""
from __future__ import annotations

from collections.abc import Mapping

# (product, category, service) -> dataset name carried in event["event.dataset"]
LOGSOURCES: dict[tuple[str | None, str | None, str | None], str] = {
    ("windows", None, "security"): "windows.security",
    ("azure", None, "signinlogs"): "identity.signin",
    (None, "dns", None): "network.dns",
    (None, "network_connection", None): "network.connection",
}

_COMMON = {
    "Computer": "host.name",
    "ComputerName": "host.name",
    "Hostname": "host.name",
    "User": "user.name",
}

FIELD_MAP: dict[str, dict[str, str]] = {
    "windows.security": {
        "EventID": "event.code",
        "TargetUserName": "user.name",
        "IpAddress": "source.ip",
        "LogonType": "winlog.logon.type",
    },
    "identity.signin": {
        "UserPrincipalName": "user.name",
        "IpAddress": "source.ip",
        "ResultType": "identity.result_code",
        "AppDisplayName": "identity.app",
        "AuthenticationRequirement": "identity.auth_requirement",
        "MfaResult": "identity.mfa_result",
    },
    "network.dns": {
        "query": "dns.question.name",
        "record_type": "dns.question.type",
        "rcode": "dns.response_code",
    },
    "network.connection": {
        "DestinationIp": "destination.ip",
        "DestinationPort": "destination.port",
        "SourceIp": "source.ip",
    },
}


class UnknownLogsource(ValueError):
    pass


def resolve_dataset(logsource: Mapping[str, str]) -> str:
    key = (logsource.get("product"), logsource.get("category"), logsource.get("service"))
    if key in LOGSOURCES:
        return LOGSOURCES[key]
    raise UnknownLogsource(f"no dataset for logsource {dict(logsource)}")


def map_field(dataset: str, field: str) -> str:
    """Sigma field name -> event key for ``dataset``."""
    return FIELD_MAP.get(dataset, {}).get(field) or _COMMON.get(field) or field
