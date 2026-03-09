import argparse
import time

from pymavlink import mavutil

MAVLINK_VERSION = 3


def build_parser():
    parser = argparse.ArgumentParser(description="Minimal MAVLink SITL substitute.")
    parser.add_argument("--udp", default="127.0.0.1:14550", help="Host:port for udpout.")
    parser.add_argument("--rate", type=float, default=10.0, help="Messages per second.")
    return parser


def main():
    args = build_parser().parse_args()
    conn = mavutil.mavlink_connection(f"udpout:{args.udp}")
    conn.mav.srcSystem = 1
    conn.mav.srcComponent = 1

    rate = max(args.rate, 1.0)
    period = 1.0 / rate
    seq = 0

    while True:
        conn.mav.heartbeat_send(
            mavutil.mavlink.MAV_TYPE_QUADROTOR,
            mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
            0,
            0,
            mavutil.mavlink.MAV_STATE_ACTIVE,
            MAVLINK_VERSION,
        )

        if seq % 5 == 0:
            conn.mav.ping_send(int(time.time() * 1e6), seq, 1, 1)

        if seq % 7 == 0:
            conn.mav.param_request_list_send(1, 1)

        if seq % 11 == 0:
            conn.mav.statustext_send(mavutil.mavlink.MAV_SEVERITY_INFO, b"SIM OK")

        seq += 1
        time.sleep(period)


if __name__ == "__main__":
    main()
