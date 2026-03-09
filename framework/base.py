"""Abstract base classes for the evaluation harness.

Every *attack*, *defense*, *detector*, and *platform* module implements
one of these interfaces so the orchestrator can run arbitrary combinations
without coupling to a specific protocol or algorithm.

Adding a new attack or defense only requires subclassing the appropriate
base and registering it with the orchestrator.
"""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BasePlatform(ABC):
    """Represents a simulated autonomous platform (vehicle, robot, etc.)."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Human-readable platform name."""

    @abstractmethod
    def start(self, *, target: str, rate: float, **kwargs: Any) -> None:
        """Begin emitting normal telemetry / command traffic."""

    @abstractmethod
    def stop(self) -> None:
        """Gracefully shut the platform down."""


class BaseAttack(ABC):
    """A single, configurable attack module."""

    @property
    @abstractmethod
    def name(self) -> str:
        """Short descriptive name shown in logs and metrics."""

    @property
    @abstractmethod
    def description(self) -> str:
        """One-line description of the attack vector."""

    @abstractmethod
    def execute(
        self,
        *,
        target: str,
        duration: float,
        rate: float,
        out_dir: str,
        **kwargs: Any,
    ) -> dict[str, Any]:
        """Run the attack for *duration* seconds, return per-attack metrics.

        Parameters
        ----------
        target   : protocol-specific address (e.g. ``"127.0.0.1:14550"``).
        duration : how long the attack runs (seconds).
        rate     : messages / iterations per second.
        out_dir  : directory for CSV / log output.

        Returns
        -------
        dict with at least ``{"messages_sent": int}``.
        """

    @abstractmethod
    def stop(self) -> None:
        """Interrupt a running attack early (best-effort)."""


class BaseDetector(ABC):
    """An anomaly-detection model that learns normal behaviour and
    scores new observations."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def fit(self, feature_matrix: Any) -> None:
        """Train / fit on baseline feature data."""

    @abstractmethod
    def score(self, feature_vector: Any) -> float:
        """Return a normalised anomaly score in ``[0, 1]``
        where **1 = normal** and **0 = maximally anomalous**."""

    @property
    @abstractmethod
    def is_trained(self) -> bool: ...


class BaseDefense(ABC):
    """A defence module that decides whether to block a message based
    on upstream detection signals."""

    @property
    @abstractmethod
    def name(self) -> str: ...

    @abstractmethod
    def evaluate(
        self,
        timestamp: float,
        msg_id: int,
        src: int,
        anomaly_score: float,
    ) -> bool:
        """Return ``True`` if the message should be **blocked**."""

    @abstractmethod
    def summary(self) -> dict[str, Any]:
        """Return a JSON-serialisable summary of defence activity."""
