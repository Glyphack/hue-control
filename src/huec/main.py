"""Simple BLE controller for Hue lightstrip plus."""

from __future__ import annotations

import argparse
import asyncio
import logging
import os
import threading
import time
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from huec.lib.hue import (
    DEFAULT_DEVICE_NAME,
    HueLight,
)
from huec.lib.models import Config
from huec.lib.parsers import bin_to_hex, hex_to_bin
from huec.scripts.subscribe_all import subscribe_all

LOG_FORMAT = "%(asctime)s %(levelname)s %(message)s"
log = logging.getLogger("huec")


def configure_logging(debug: bool) -> None:
    logging.basicConfig(level=logging.WARNING, format=LOG_FORMAT, force=True)
    project_level = logging.DEBUG if debug else logging.WARNING
    log.setLevel(project_level)


def build_args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Control Hue lightstrip over BLE.")
    parser.add_argument(
        "--debug",
        action="store_true",
        help="Enable debug logging for BLE requests, responses, and validation steps.",
    )
    parser.add_argument(
        "-d",
        "--device",
        default=DEFAULT_DEVICE_NAME,
        help=f"BLE device name. Default is {DEFAULT_DEVICE_NAME}",
    )
    parser.add_argument("--timeout", type=float, default=15.0, help="BLE scan timeout.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "interactive",
        help="Start HTTP server and keep BLE connection open.",
    )

    power = subparsers.add_parser("power", help="Turn the light on or off.")
    power.add_argument("state", choices=["on", "off"], help="Power state.")

    color = subparsers.add_parser(
        "color",
        help="Control color and brightness",
    )
    color.add_argument(
        "--data",
        required=True,
        help="""Raw hex payload in the same format.
 To obtain the value use interactive command and use the color picker.""",
    )

    alarms = subparsers.add_parser(
        "alarms",
        help="Control alarms(routines) to turn the light on/off automatically.",
    )
    alarms_subparsers = alarms.add_subparsers(dest="alarms_command", required=True)

    alarms_subparsers.add_parser("list", help="List alarms.")

    alarms_enable = alarms_subparsers.add_parser("enable", help="Enable alarms.")
    alarms_enable_target = alarms_enable.add_mutually_exclusive_group(required=True)
    alarms_enable_target.add_argument(
        "--all",
        action="store_true",
        help="Enable all alarms.",
    )
    alarms_enable_target.add_argument(
        "--id",
        type=int,
        help="Enable alarm by ID.",
    )

    alarms_disable = alarms_subparsers.add_parser("disable", help="Disable alarms.")
    alarms_disable_target = alarms_disable.add_mutually_exclusive_group(required=True)
    alarms_disable_target.add_argument(
        "--all",
        action="store_true",
        help="Disable all alarms.",
    )
    alarms_disable_target.add_argument(
        "--id",
        type=int,
        help="Disable alarm by ID.",
    )

    alarms_delete = alarms_subparsers.add_parser("delete", help="Delete alarms.")
    alarms_delete_target = alarms_delete.add_mutually_exclusive_group(required=True)
    alarms_delete_target.add_argument(
        "--id",
        type=int,
        help="Delete alarm by ID.",
    )

    # These are not implemented yet.
    # wakeup = subparsers.add_parser(
    #     "wakeup", help="Create a wakeup command (temporarily disabled)."
    # )
    # wakeup.add_argument("--name", required=True, help="Name of the alarm")
    # wakeup.add_argument("--time", required=True, help=f"wakeup time in format {TIME_FORMAT}")
    # wakeup.add_argument(
    #     "--mode",
    #     choices=["sunrise", "full_bright"],
    #     required=True,
    #     help="Wakeup mode.",
    # )
    # wakeup.add_argument(
    #     "--fade-in",
    #     dest="fade_in",
    #     type=int,
    #     choices=[30],
    #     default=30,
    #     help="Fade-in time in minutes.",
    # )
    # wakeup.add_argument(
    #     "--edit",
    #     action="store_true",
    #     help="Edit this timer instead of creating it",
    #     default=False,
    # )
    # wakeup.add_argument(
    #     "--deactive",
    #     action="store_true",
    #     help="Create as inactive.",
    #     default=False,
    # )
    #
    # timer = subparsers.add_parser("timer", help="Create a timer command (temporarily disabled).")
    # timer.add_argument("--duration", required=True, help="Timer duration in seconds")
    # timer.add_argument(
    #     "--effect",
    #     choices=["flash", "on", "off"],
    #     required=True,
    #     help="Timer effect.",
    # )
    # timer.add_argument(
    #     "--deactive",
    #     action="store_true",
    #     help="Create as inactive.",
    # )
    #
    # sleep = subparsers.add_parser("sleep", help="Create a sleep command (temporarily disabled).")
    # sleep.add_argument("--time", required=True, help=f"sleep time in format {TIME_FORMAT}")
    # sleep.add_argument("--mode", help="Sleep mode.")
    # sleep.add_argument(
    #     "--deactive",
    #     action="store_true",
    #     help="Create as inactive.",
    # )

    dev = subparsers.add_parser("dev", help="Developer utilities.")
    dev_subparsers = dev.add_subparsers(dest="dev_command", required=True)

    dev_set = dev_subparsers.add_parser(
        "set-characteristic",
        help="Send raw hex data to a characteristic.",
    )
    dev_set.add_argument(
        "--characteristic",
        required=True,
        help="Characteristic UUID to write.",
    )
    dev_set.add_argument(
        "--data",
        required=True,
        help="Hex payload (e.g. '01ff 02').",
    )

    dev_subparsers.add_parser(
        "subscribe-all",
        help="Subscribe to all notifiable characteristics.",
    )

    return parser


async def run_interactive(light: HueLight) -> None:
    """Run interactive mode HTTP server using the existing BLE connection."""

    loop = asyncio.get_running_loop()

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)
            log.debug("interactive request path=%s query=%s", parsed.path, parsed.query)

            if parsed.path == "/" or parsed.path == "":
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()

                with open("auto_color.html", "rb") as f:
                    self.wfile.write(f.read())
                return

            if parsed.path == "/power":
                qs = parse_qs(parsed.query)
                if "state" in qs:
                    state = qs["state"][0]
                    try:
                        if state == "on":
                            future = asyncio.run_coroutine_threadsafe(
                                light.set_power(True),
                                loop,
                            )
                        elif state == "off":
                            future = asyncio.run_coroutine_threadsafe(
                                light.set_power(False),
                                loop,
                            )
                        else:
                            self.send_response(400)
                            self.end_headers()
                            self.wfile.write(b"Bad state")
                            return
                        future.result()
                    except Exception:
                        log.exception("Power control failed")

                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"OK")
                    return

            if parsed.path == "/send":
                qs = parse_qs(parsed.query)
                if "data" in qs:
                    hex_string = qs["data"][0]
                    try:
                        data_bytes = hex_to_bin(hex_string)
                    except ValueError:
                        self.send_response(400)
                        self.end_headers()
                        self.wfile.write(b"Bad hex")
                        return

                    try:
                        future = asyncio.run_coroutine_threadsafe(light.set_color(data_bytes), loop)
                        future.result()
                    except Exception:
                        log.exception("BLE write failed")

                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"OK")
                    return

            self.send_response(404)
            self.end_headers()

    threading.Thread(
        target=lambda: (time.sleep(0.02), os.system("open http://localhost:8000")),
        daemon=True,
    ).start()

    log.debug("interactive server running at http://localhost:8000")
    server = HTTPServer(("localhost", 8000), Handler)
    try:
        await asyncio.to_thread(server.serve_forever)
    finally:
        server.shutdown()
        server.server_close()


async def run(args: argparse.Namespace, config: Config) -> None:
    light = await HueLight.connect(config)
    try:
        await handle_command(args, light, config)
    finally:
        await light.disconnect()


async def handle_command(args: argparse.Namespace, light: HueLight, config: Config) -> None:
    if args.command == "interactive":
        await run_interactive(light)
        return

    if args.command == "power":
        await light.set_power(args.state == "on")
        return

    if args.command == "color":
        try:
            data = hex_to_bin(args.data)
        except ValueError as exc:
            raise SystemExit(f"Invalid hex payload: {args.data}.") from exc
        await light.set_color(data)
        return

    if args.command == "alarms":
        # Clarify in the docs that alarm ids are not stable and change
        if args.alarms_command == "list":
            alarms = await light.get_alarms()
            for alarm in alarms:
                log.debug(f"--- ID 0x{alarm._id:04x} ({alarm._id}) ---")
                log.debug(f"Name:'{alarm.properties.name}'")
                log.debug(f"Raw hex ({len(alarm.raw)} bytes):")
                log.debug(f"{bin_to_hex(alarm.raw)}")
                log.debug(f"Payload length: {alarm.payload_length}")
                log.debug(f"Payload: {bin_to_hex(alarm.payload)}")
                log.debug(f"Mystery bytes:  {bin_to_hex(alarm.properties.mystery_bytes)}")

            id_width = 8
            active_width = 6
            name_width = 20
            summary_rows = []
            for alarm in alarms:
                time_str = alarm.properties.timestamp.isoformat()
                if not alarm.is_wake_up_or_sleep():
                    duration = alarm.extract_timer_duration_seconds()
                    time_str = f"{time_str} ({duration}s)"
                active_str = "YES" if alarm.properties.active else "NO"
                name_str = alarm.properties.name[:name_width]
                summary_rows.append((alarm._id, active_str, name_str, time_str))

            timestamp_width = 26
            if summary_rows:
                timestamp_width = max(timestamp_width, max(len(row[3]) for row in summary_rows))

            le = id_width + active_width + name_width + timestamp_width + 6

            print("SUMMARY")
            print("=" * le)
            print(
                f"{'ID':>{id_width}}  {'Active':>{active_width}}  {'Name':<{name_width}}  "
                f"{'Timestamp':<{timestamp_width}}"
            )
            print("-" * le)
            for alarm_id, active_str, name_str, time_str in summary_rows:
                print(
                    f"{alarm_id:>{id_width}}  {active_str:>{active_width}}  "
                    f"{name_str:<{name_width}}  {time_str:<{timestamp_width}}"
                )
        if args.alarms_command == "enable":
            alarms = await light.get_alarms()
            if args.all:
                alarms = list(filter(lambda a: not a.properties.active, alarms))
            if args.id is not None:
                alarms = list(filter(lambda a: a._id == int(args.id), alarms))
            for alarm in alarms:
                enable_result = await light.enable_alarm(alarm)
                if not enable_result.is_ok():
                    print("Enable alarm failed")

        if args.alarms_command == "disable":
            alarms = await light.get_alarms()
            if args.all:
                alarms = list(filter(lambda a: a.properties.active, alarms))
            if args.id is not None:
                alarms = list(filter(lambda a: a._id == int(args.id), alarms))
            for alarm in alarms:
                disable_result = await light.disable_alarm(alarm)
                if not disable_result.is_ok():
                    print("Disable alarm failed")

        if args.alarms_command == "delete":
            id_result = await light.get_alarm_ids()
            ids = id_result.slot_ids
            if args.all:
                pass
            if args.id:
                ids = [ids.index(args.id)]

            for id in ids:
                log.debug(f"Delete alarm: {id}")
                delete_result = await light.delete_alarm(id)
                if not delete_result.is_ok():
                    print("Delete alarm failed")

    if args.command == "dev":
        await handle_dev(args, light, config)


async def handle_dev(args: argparse.Namespace, light: HueLight, config: Config) -> None:
    if args.dev_command == "set-characteristic":
        payload = hex_to_bin(args.data)
        await light.write_characteristic(args.characteristic, payload, response=True)
        return

    if args.dev_command == "subscribe-all":
        await subscribe_all(config.device_name, timeout=config.timeout)
        return


def main() -> None:
    parser = build_args()
    args = parser.parse_args()
    configure_logging(args.debug)
    log.debug("CLI args: %s", args)

    if args.command in {"wakeup", "timer", "sleep"}:
        raise SystemExit(f"The '{args.command}' command is temporarily disabled.")

    config = Config(device_name=args.device, timeout=args.timeout)
    log.debug("Using config=%s", config)

    try:
        asyncio.run(run(args, config))
    except KeyboardInterrupt:
        raise SystemExit(130) from None
    except SystemExit as exc:
        if isinstance(exc.code, str) and exc.code:
            print(exc.code)
            raise SystemExit(1) from None
        raise
    except Exception as exc:
        log.debug("Operation failed with config=%s", config, exc_info=True)
        print(f"Operation failed: {exc}")
        raise SystemExit(1) from None


if __name__ == "__main__":
    main()
