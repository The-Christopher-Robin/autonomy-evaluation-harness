"""Sliding-window feature extraction for MAVLink message streams.

Extracts an 11-dimensional feature vector per message capturing rate,
entropy, source diversity, Markov transition probability, timing, and
per-type frequency ratios.
"""

import math
from collections import defaultdict, deque

MSG_ID_HEARTBEAT = 0
MSG_ID_PING = 4
MSG_ID_PARAM_REQUEST_LIST = 21
MSG_ID_COMMAND_LONG = 76
MSG_ID_STATUSTEXT = 253

TRACKED_IDS = [
    MSG_ID_HEARTBEAT,
    MSG_ID_PING,
    MSG_ID_PARAM_REQUEST_LIST,
    MSG_ID_COMMAND_LONG,
    MSG_ID_STATUSTEXT,
]

FEATURE_NAMES = [
    "msg_rate",
    "type_entropy",
    "src_system_count",
    "src_msg_rate",
    "markov_prob",
    "inter_arrival_delta",
    "ratio_heartbeat",
    "ratio_ping",
    "ratio_param_request",
    "ratio_command_long",
    "ratio_statustext",
]

NUM_FEATURES = len(FEATURE_NAMES)


class FeatureEngine:
    """Maintains a time-based sliding window and produces a feature vector
    for every incoming MAVLink message."""

    def __init__(self, window_seconds=2.0):
        self._window_sec = window_seconds
        self._buf: deque = deque()
        self._last_ts: float | None = None

    def extract(self, timestamp, msg_id, src_system, markov_prob=0.0):
        cutoff = timestamp - self._window_sec
        while self._buf and self._buf[0][0] < cutoff:
            self._buf.popleft()

        inter_arrival = (timestamp - self._last_ts) if self._last_ts is not None else 0.0
        self._buf.append((timestamp, msg_id, src_system))
        self._last_ts = timestamp

        n = len(self._buf)
        if n < 2:
            return [0.0] * NUM_FEATURES

        span = max(self._buf[-1][0] - self._buf[0][0], 1e-3)

        type_counts: dict[int, int] = defaultdict(int)
        src_set: set[int] = set()
        src_this = 0
        for _, mid, src in self._buf:
            type_counts[mid] += 1
            src_set.add(src)
            if src == src_system:
                src_this += 1

        msg_rate = n / span
        src_msg_rate = src_this / span

        entropy = 0.0
        for c in type_counts.values():
            p = c / n
            if p > 0:
                entropy -= p * math.log2(p)

        type_ratios = [type_counts.get(tid, 0) / n for tid in TRACKED_IDS]

        return [
            msg_rate,
            entropy,
            float(len(src_set)),
            src_msg_rate,
            markov_prob,
            inter_arrival,
            *type_ratios,
        ]
