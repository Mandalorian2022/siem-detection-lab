"""A self-contained Sigma implementation: loader, condition parser, value
modifiers, processing pipeline, and an engine with correlation rules."""
from .engine import SigmaEngine
from .loader import SigmaCorrelation, SigmaRule, SigmaRuleError, load_file, load_rules

__all__ = ["SigmaEngine", "SigmaRule", "SigmaCorrelation", "SigmaRuleError",
           "load_file", "load_rules"]
