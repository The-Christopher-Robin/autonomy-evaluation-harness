"""Anomaly detection, adaptive defence, and visual grounding modules."""

from .ml_model import AnomalyDetector  # noqa: F401
from .adaptive_defense import AdaptiveDefense  # noqa: F401
from .feature_engine import FeatureEngine  # noqa: F401

try:
    from .visual_grounding import VisualGrounder  # noqa: F401
except ImportError:
    pass
