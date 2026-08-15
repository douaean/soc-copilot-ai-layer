"""
LangGraph node implementations.

One module per node. Each owns its business logic, declares the external
collaborator it needs as a ``Protocol``, and exposes a ``make_*_node``
factory that binds that collaborator. The graph module wires them together
and knows nothing about how any of them work.

Nodes never mutate the state they receive. They compute a patch and return
it; LangGraph merges it and hands the updated state to the next node.
"""

from .analyst import AnalystEngine, make_analyst_node
from .dashboard import make_dashboard_node
from .rule_checker import RuleRepository, make_rule_checker_node
from .rule_generator import RuleDrafter, make_rule_generator_node
from .sensitive_detection import SensitiveScanner, make_sensitive_detection_node
from .threat_intel import Retriever, ThreatIntelProvider, make_threat_intel_node

__all__ = [
    "AnalystEngine",
    "Retriever",
    "RuleDrafter",
    "RuleRepository",
    "SensitiveScanner",
    "ThreatIntelProvider",
    "make_analyst_node",
    "make_dashboard_node",
    "make_rule_checker_node",
    "make_rule_generator_node",
    "make_sensitive_detection_node",
    "make_threat_intel_node",
]
