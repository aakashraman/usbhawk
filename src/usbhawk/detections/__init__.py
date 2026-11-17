"""Module #4: detection-as-code. YAML hypotheses -> Sigma, Elastic (ES|QL), Microsoft Sentinel (KQL)."""

from .core import (RULES_DIR, Rule, evaluate, evaluate_stream, load_rules, parse_condition, resolve_vars,
                   rule_vars, run_rule_tests, validate_rule)
from .generators import TARGETS, build

__all__ = ["RULES_DIR", "Rule", "TARGETS", "build", "evaluate", "evaluate_stream", "load_rules", "parse_condition",
           "resolve_vars", "rule_vars", "run_rule_tests", "validate_rule"]
