import argparse
import threading
import time

from pymavlink import mavutil

from framework.base import BasePlatform

MAVLINK_VERSION = 3


class SITLSimulator(BasePlatform):
    """MAVLink SITL substitute that emits normal telemetry traffic."""

    def __init__(self):
        self._conn = None
        self._running = False
        self._thread: threading.Thread | None = None

    @property
    def name(self) -> str:
        return "mavlink_sitl_simulator"

    def start(self, *, target: str, rate: float, **kwargs) -> None:
        self._conn = mavutil.mavlink_connection(f"udpout:{target}")
        self._conn.mav.srcSystem = 1
        self._conn.mav.srcComponent = 1
        self._running = True
        self._thread = threading.Thread(
            target=self._run, args=(rate,), daemon=True,
        )
        self._thread.start()

    def stop(self) -> None:
        self._running = False
        if self._thread is not None:
            self._thread.join(timeout=5)

    def _run(self, rate: float) -> None:
        rate = max(rate, 1.0)
        period = 1.0 / rate
        seq = 0
        while self._running:
            self._conn.mav.heartbeat_send(
                mavutil.mavlink.MAV_TYPE_QUADROTOR,
                mavutil.mavlink.MAV_AUTOPILOT_ARDUPILOTMEGA,
                0, 0,
                mavutil.mavlink.MAV_STATE_ACTIVE,
                MAVLINK_VERSION,
            )
            if seq % 5 == 0:
                self._conn.mav.ping_send(int(time.time() * 1e6), seq, 1, 1)
            if seq % 7 == 0:
                self._conn.mav.param_request_list_send(1, 1)
            if seq % 11 == 0:
                self._conn.mav.statustext_send(
                    mavutil.mavlink.MAV_SEVERITY_INFO, b"SIM OK")
            seq += 1
            time.sleep(period)


def build_parser():
    parser = argparse.ArgumentParser(description="Minimal MAVLink SITL substitute.")
    parser.add_argument("--udp", default="127.0.0.1:14550", help="Host:port for udpout.")
    parser.add_argument("--rate", type=float, default=10.0, help="Messages per second.")
    return parser


def main():
    args = build_parser().parse_args()
    sim = SITLSimulator()
    sim.start(target=args.udp, rate=args.rate)
    try:
        while True:
            time.sleep(1)
    except KeyboardInterrupt:
        pass
    finally:
        sim.stop()


if __name__ == "__main__":
    main()
