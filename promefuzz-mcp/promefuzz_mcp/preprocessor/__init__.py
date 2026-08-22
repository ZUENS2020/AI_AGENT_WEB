"""
Preprocessor module.
"""

from .ast import ASTPreprocessor, Meta
from .api_extractor import APIExtractor, APICollection, APIFunction
from .callgraph import CallGraphBuilder
from .relevance import TypeRelevance, ClassRelevance, CallRelevance
from .complexity import ComplexityCalculator
from .incidental import IncidentalExtractor
from .sinks import find_call_paths, lookup_function_info, scan_dangerous_sinks

__all__ = [
    "ASTPreprocessor",
    "Meta",
    "APIExtractor",
    "APICollection",
    "APIFunction",
    "CallGraphBuilder",
    "TypeRelevance",
    "ClassRelevance",
    "CallRelevance",
    "ComplexityCalculator",
    "IncidentalExtractor",
    "scan_dangerous_sinks",
    "find_call_paths",
    "lookup_function_info",
]
