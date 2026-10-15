"""Deterministic scoring: typed inputs + versioned weights -> a score explained by named factors.

No model is ever called from this package. That is the product's core invariant.
"""

from vmp.scoring.inputs import FactorName, MissingInput, ScoringInput
from vmp.scoring.weights import DEFAULT_VERSION, Weights, load_weights

__all__ = [
    "DEFAULT_VERSION",
    "FactorName",
    "MissingInput",
    "ScoringInput",
    "Weights",
    "load_weights",
]
