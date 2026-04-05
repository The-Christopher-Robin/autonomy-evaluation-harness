"""OpenCV-based multimodal visual grounding for dashboard analysis.

Provides computer-vision utilities that analyse the matplotlib dashboard
frames produced by the detector.  This adds a visual / multimodal
dimension to the evaluation: confirming detector output against
dashboard visualisations.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import cv2
import numpy as np


class VisualGrounder:
    """Analyses dashboard visualisation frames using OpenCV to provide
    multimodal confirmation of detector outputs."""

    _RED_LO1 = np.array([0, 100, 100])
    _RED_HI1 = np.array([10, 255, 255])
    _RED_LO2 = np.array([160, 100, 100])
    _RED_HI2 = np.array([180, 255, 255])

    _BLUE_LO = np.array([100, 50, 50])
    _BLUE_HI = np.array([130, 255, 255])

    _PURPLE_LO = np.array([130, 50, 50])
    _PURPLE_HI = np.array([160, 255, 255])

    _ORANGE_LO = np.array([10, 100, 100])
    _ORANGE_HI = np.array([25, 255, 255])

    def __init__(self, min_contour_area: int = 100):
        self._min_area = min_contour_area

    # ------------------------------------------------------------------
    # public API
    # ------------------------------------------------------------------

    def analyze_dashboard_frame(self, image_path: str | Path) -> dict[str, Any]:
        """Analyse a single dashboard image for anomaly indicators.

        Returns a dict with detected anomaly regions, confidence scores,
        and per-panel statistics.
        """
        img = cv2.imread(str(image_path))
        if img is None:
            return {"error": f"Could not load image: {image_path}",
                    "anomaly_regions": []}

        hsv = cv2.cvtColor(img, cv2.COLOR_BGR2HSV)
        h, w = img.shape[:2]

        red_mask = cv2.bitwise_or(
            cv2.inRange(hsv, self._RED_LO1, self._RED_HI1),
            cv2.inRange(hsv, self._RED_LO2, self._RED_HI2),
        )
        purple_mask = cv2.inRange(hsv, self._PURPLE_LO, self._PURPLE_HI)
        orange_mask = cv2.inRange(hsv, self._ORANGE_LO, self._ORANGE_HI)

        red_regions = self._find_regions(red_mask, "alert")
        purple_regions = self._find_regions(purple_mask, "anomaly_score")
        orange_regions = self._find_regions(orange_mask, "defense_action")

        spike_count = self._count_spikes(purple_mask)

        panel_h = h // 3
        panels = {
            "accuracy_panel": self._panel_stats(img[:panel_h], hsv[:panel_h]),
            "anomaly_panel": self._panel_stats(
                img[panel_h:2 * panel_h], hsv[panel_h:2 * panel_h]),
            "defense_panel": self._panel_stats(img[2 * panel_h:], hsv[2 * panel_h:]),
        }

        red_ratio = float(np.count_nonzero(red_mask)) / (h * w)
        purple_ratio = float(np.count_nonzero(purple_mask)) / (h * w)
        confidence = min(1.0, red_ratio * 50 + len(red_regions) * 0.1)

        return {
            "image_path": str(image_path),
            "dimensions": {"width": w, "height": h},
            "anomaly_regions": red_regions + purple_regions,
            "defense_regions": orange_regions,
            "anomaly_spike_count": spike_count,
            "confidence_score": round(confidence, 4),
            "alert_pixel_ratio": round(red_ratio, 6),
            "anomaly_pixel_ratio": round(purple_ratio, 6),
            "panels": panels,
        }

    def compare_frames(
        self,
        frame_before: str | Path,
        frame_after: str | Path,
    ) -> dict[str, Any]:
        """Compare two dashboard frames and quantify visual changes."""
        img1 = cv2.imread(str(frame_before))
        img2 = cv2.imread(str(frame_after))

        if img1 is None or img2 is None:
            return {"error": "Could not load one or both images",
                    "changes_detected": False}

        if img1.shape != img2.shape:
            img2 = cv2.resize(img2, (img1.shape[1], img1.shape[0]))

        diff = cv2.absdiff(
            cv2.cvtColor(img1, cv2.COLOR_BGR2GRAY),
            cv2.cvtColor(img2, cv2.COLOR_BGR2GRAY),
        )
        _, thresh = cv2.threshold(diff, 30, 255, cv2.THRESH_BINARY)

        change_ratio = float(np.count_nonzero(thresh)) / thresh.size
        contours, _ = cv2.findContours(
            thresh, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        significant = [c for c in contours
                       if cv2.contourArea(c) > self._min_area]

        regions = []
        for c in significant:
            x, y, w, h = cv2.boundingRect(c)
            regions.append({"x": int(x), "y": int(y),
                            "width": int(w), "height": int(h),
                            "area": int(cv2.contourArea(c))})

        return {
            "changes_detected": len(significant) > 0,
            "change_ratio": round(change_ratio, 4),
            "significant_change_regions": len(significant),
            "change_regions": regions,
            "mean_diff": round(float(diff.mean()), 4),
        }

    def generate_visual_report(
        self, frames_dir: str | Path,
    ) -> dict[str, Any]:
        """Analyse every dashboard image in *frames_dir*."""
        frames_dir = Path(frames_dir)
        if not frames_dir.exists():
            return {"frames_analyzed": 0,
                    "summary": "Directory does not exist."}

        frame_files = sorted(
            f for f in frames_dir.iterdir()
            if f.suffix.lower() in (".png", ".jpg", ".jpeg")
        )

        analyses = [self.analyze_dashboard_frame(f) for f in frame_files]

        if not analyses:
            return {"frames_analyzed": 0,
                    "summary": "No image frames found."}

        total_regions = sum(len(a.get("anomaly_regions", [])) for a in analyses)
        total_spikes = sum(a.get("anomaly_spike_count", 0) for a in analyses)
        avg_conf = sum(a.get("confidence_score", 0) for a in analyses) / len(analyses)
        max_alert = max(a.get("alert_pixel_ratio", 0) for a in analyses)

        return {
            "frames_analyzed": len(analyses),
            "total_anomaly_regions": total_regions,
            "total_anomaly_spikes": total_spikes,
            "average_confidence": round(avg_conf, 4),
            "max_alert_pixel_ratio": round(max_alert, 6),
            "per_frame": analyses,
        }

    # ------------------------------------------------------------------
    # internal helpers
    # ------------------------------------------------------------------

    def _find_regions(self, mask: np.ndarray, label: str) -> list[dict]:
        contours, _ = cv2.findContours(
            mask, cv2.RETR_EXTERNAL, cv2.CHAIN_APPROX_SIMPLE)
        regions = []
        for c in contours:
            area = cv2.contourArea(c)
            if area < self._min_area:
                continue
            x, y, w, h = cv2.boundingRect(c)
            regions.append({"type": label, "x": int(x), "y": int(y),
                            "width": int(w), "height": int(h),
                            "area": int(area)})
        return regions

    def _count_spikes(self, mask: np.ndarray) -> int:
        projection = np.sum(mask > 0, axis=1)
        threshold = max(float(np.mean(projection)) * 2, 5)
        above = projection > threshold
        transitions = np.diff(above.astype(int))
        return int(np.sum(transitions == 1))

    @staticmethod
    def _panel_stats(panel_bgr: np.ndarray, panel_hsv: np.ndarray) -> dict:
        gray = cv2.cvtColor(panel_bgr, cv2.COLOR_BGR2GRAY)
        h, w = gray.shape[:2]
        return {
            "mean_intensity": round(float(gray.mean()), 2),
            "std_intensity": round(float(gray.std()), 2),
            "dimensions": {"width": w, "height": h},
        }
