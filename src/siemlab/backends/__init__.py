"""Query backends: translate Sigma detection rules into SIEM query languages.

Only detection rules convert; correlation rules depend on windowing
semantics that differ per product and are left to the target platform's
own correlation features.
"""
from .base import Backend
from .kql import KqlBackend
from .splunk import SplunkBackend

BACKENDS: dict[str, type[Backend]] = {"kql": KqlBackend, "splunk": SplunkBackend}

__all__ = ["Backend", "BACKENDS", "KqlBackend", "SplunkBackend"]
