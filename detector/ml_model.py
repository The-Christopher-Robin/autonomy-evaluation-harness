"""Isolation Forest anomaly detector for MAVLink traffic.

Trains on baseline (normal) feature vectors and scores new messages
with a normalised anomaly score in [0, 1]  (1 = normal, 0 = anomalous).
"""

import numpy as np
from sklearn.ensemble import IsolationForest

from framework.base import BaseDetector


class AnomalyDetector(BaseDetector):
    def __init__(self, contamination=0.01, n_estimators=150, random_state=42):
        self._model = IsolationForest(
            contamination=contamination,
            n_estimators=n_estimators,
            random_state=random_state,
        )
        self._is_trained = False
        self._offset = 0.0
        self._scale = 1.0

    @property
    def name(self) -> str:
        return "isolation_forest"

    @property
    def is_trained(self) -> bool:
        return self._is_trained

    def fit(self, feature_matrix):
        """Fit on baseline feature vectors (all assumed normal)."""
        X = np.asarray(feature_matrix, dtype=np.float64)
        if len(X) < 20:
            return
        self._model.fit(X)
        raw = self._model.decision_function(X)
        lo, hi = float(raw.min()), float(raw.max())
        self._scale = (hi - lo) if (hi - lo) > 0 else 1.0
        self._offset = lo
        self._is_trained = True

    def score(self, feature_vector):
        """Return normalised score in [0, 1].  1 = normal, 0 = anomalous."""
        if not self._is_trained:
            return 1.0
        X = np.asarray(feature_vector, dtype=np.float64).reshape(1, -1)
        raw = float(self._model.decision_function(X)[0])
        return max(0.0, min(1.0, (raw - self._offset) / self._scale))
