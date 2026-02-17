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

from lib.hue import (
    DEFAULT_BRIGHTNESS,
    DEFAULT_DEVICE_NAME,
    EXPECTED_CONFIRM_TRAILER,
    TIME_FORMAT,
    HueLight,
)
from lib.models import Alarm, Config
from lib.parsers import format_hex, parse_hex_payload
from scripts.subscribe_all import subscribe_all

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("hue-control")


def build_args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Control Hue lightstrip over BLE.")
    parser.add_argument(
        "-d",
        "--device",
        default=DEFAULT_DEVICE_NAME,
        help="BLE device name.",
    )
    parser.add_argument("--timeout", type=float, default=15.0, help="BLE scan timeout.")

    subparsers = parser.add_subparsers(dest="command", required=True)

    subparsers.add_parser(
        "customize",
        help="Start HTTP server and keep BLE connection open.",
    )

    power = subparsers.add_parser("power", help="Turn the light on or off.")
    power.add_argument("state", choices=["on", "off"], help="Power state.")

    rgb = subparsers.add_parser(
        "rgb",
        help="Set RGB via 0005 (less compatible than 0007).",
    )
    rgb.add_argument("--brightness", type=int, default=DEFAULT_BRIGHTNESS)
    rgb.add_argument("--red", type=int, default=0)
    rgb.add_argument("--green", type=int, default=0)
    rgb.add_argument("--blue", type=int, default=0)

    wakeup = subparsers.add_parser("wakeup", help="Create a wakeup command (temporarily disabled).")
    wakeup.add_argument("--name", required=True, help="Name of the alarm")
    wakeup.add_argument("--time", required=True, help=f"wakeup time in format {TIME_FORMAT}")
    wakeup.add_argument(
        "--mode",
        choices=["sunrise", "full_bright"],
        required=True,
        help="Wakeup mode.",
    )
    wakeup.add_argument(
        "--fade-in",
        dest="fade_in",
        type=int,
        choices=[30],
        default=30,
        help="Fade-in time in minutes.",
    )
    wakeup.add_argument(
        "--edit",
        action="store_true",
        help="Edit this timer instead of creating it",
        default=False,
    )
    wakeup.add_argument(
        "--deactive",
        action="store_true",
        help="Create as inactive.",
        default=False,
    )

    timer = subparsers.add_parser("timer", help="Create a timer command (temporarily disabled).")
    timer.add_argument("--duration", required=True, help="Timer duration in seconds")
    timer.add_argument(
        "--effect",
        choices=["flash", "on", "off"],
        required=True,
        help="Timer effect.",
    )
    timer.add_argument(
        "--deactive",
        action="store_true",
        help="Create as inactive.",
    )

    sleep = subparsers.add_parser("sleep", help="Create a sleep command (temporarily disabled).")
    sleep.add_argument("--time", required=True, help=f"sleep time in format {TIME_FORMAT}")
    sleep.add_argument("--mode", help="Sleep mode.")
    sleep.add_argument(
        "--deactive",
        action="store_true",
        help="Create as inactive.",
    )

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

    dev_subparsers.add_parser(
        "read-alarms",
        help="Read and dump all alarm slots from the lamp (temporarily disabled).",
    )

    dev_subparsers.add_parser(
        "delete-alarms",
        help="Delete all alarm slots from the lamp (temporarily disabled).",
    )

    dev_subparsers.add_parser(
        "enable-alarms",
        help="Enable all inactive alarm slots on the lamp (temporarily disabled).",
    )

    return parser


def run_customize_mode(config: Config) -> None:
    """Run customize mode with HTTP server directly calling BLE functions."""

    async def connect_light() -> HueLight:
        return await HueLight.connect(config)

    light = asyncio.run(connect_light())
    log.info("Connected to light for customize mode")

    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):  # noqa: N802
            parsed = urlparse(self.path)

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

                    async def set_power_async() -> None:
                        if state == "on":
                            await light.set_power(True, 0xFE)
                        elif state == "off":
                            await light.set_power(False, None)

                    try:
                        asyncio.run(set_power_async())
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
                        data_bytes = bytes.fromhex(hex_string)
                    except ValueError:
                        self.send_response(400)
                        self.end_headers()
                        self.wfile.write(b"Bad hex")
                        return

                    async def write_color_async() -> None:
                        await light.set_color(data_bytes)

                    try:
                        asyncio.run(write_color_async())
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

    print("Customize server running at http://localhost:8000")
    try:
        HTTPServer(("localhost", 8000), Handler).serve_forever()
    finally:
        asyncio.run(light.disconnect())


def print_alarm_report(slots: list[Alarm]) -> None:
    print("\n" + "=" * 70)
    print("ALARM DUMP REPORT")
    print("=" * 70)

    for slot in slots:
        print(f"\n--- Slot 0x{slot.slot_id:04x} ({slot.slot_id}) ---")
        print(f"  Raw hex ({len(slot.raw)} bytes):")
        print(f"    {format_hex(slot.raw)}")
        print(f"  Payload length: {slot.payload_length}")
        print(f"  Payload: {format_hex(slot.payload)}")
        print(f"  Active:         {slot.properties.active}")
        print(f"  Timestamp:      {slot.properties.timestamp}")
        print(f"  Name:           '{slot.properties.name}'")
        print(f"  Mystery bytes:  {format_hex(slot.properties.mystery_bytes)}")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"{'Slot':>8}  {'Active':>6}  {'Name':<20}  {'Timestamp':<26}")
    print("-" * 75)
    for slot in slots:
        time_str = slot.properties.timestamp.isoformat()
        active_str = "  YES" if slot.properties.active else "   NO"
        print(
            f"  0x{slot.slot_id:04x}  {active_str:>6}  {slot.properties.name:<20}  {time_str:<26}"
        )
    print()


async def run(args: argparse.Namespace, config: Config) -> None:
    light = await HueLight.connect(config)
    try:
        await handle_command(args, light, config)
    finally:
        await light.disconnect()


async def handle_command(args: argparse.Namespace, light: HueLight, config: Config) -> None:
    if args.command == "power":
        await light.set_power(args.state == "on", None)
        return

    if args.command != "dev":
        return

    if args.dev_command == "set-characteristic":
        payload = parse_hex_payload(args.data)
        await light.write_characteristic(args.characteristic, payload, response=True)
        return

    if args.dev_command == "read-alarms":
        alarms = await light.read_alarms()
        print_alarm_report(alarms)
        return

    if args.dev_command == "subscribe-all":
        await subscribe_all(config.device_name, timeout=config.timeout)
        return

    if args.dev_command == "delete-alarms":
        await light.read_alarms()
        ids_result = await light.list_alarm_ids()

        for slot_id in ids_result.slot_ids:
            delete_result = await light.delete_alarm(slot_id)

            print(f"\nDeleting slot 0x{slot_id:04x} -> write {format_hex(delete_result.command)}")
            print(
                f"  ACK:     {format_hex(delete_result.ack)}"
                f"  {'OK' if delete_result.ack_ok else 'UNEXPECTED'}"
            )
            print(
                f"  Confirm: {format_hex(delete_result.confirm)}"
                f"  {'OK' if delete_result.confirm_ok else 'UNEXPECTED'}"
            )

            if not delete_result.ack_ok:
                lo = slot_id & 0xFF
                hi = (slot_id >> 8) & 0xFF
                expected_ack = bytes([0x03, 0x00, lo, hi])
                print(f"  Expected ACK:     {format_hex(expected_ack)}")

            if not delete_result.confirm_ok:
                lo = slot_id & 0xFF
                hi = (slot_id >> 8) & 0xFF
                expected_confirm = bytes([0x04, lo, hi]) + EXPECTED_CONFIRM_TRAILER
                print(f"  Expected Confirm: {format_hex(expected_confirm)}")
        return

    if args.dev_command == "enable-alarms":
        alarms = await light.read_alarms()

        for alarm in alarms:
            if alarm.properties.active:
                continue
            await light.enable_alarm(alarm)
        return


def main() -> None:
    parser = build_args()
    args = parser.parse_args()

    if args.command in {"wakeup", "timer", "sleep"}:
        raise SystemExit(f"The '{args.command}' command is temporarily disabled.")

    config = Config(device_name=args.device, timeout=args.timeout)
    log.info("Using device '%s'", config.device_name)

    if args.command == "customize":
        print("Customize mode enabled.")
        try:
            run_customize_mode(config)
        except KeyboardInterrupt:
            log.info("Interrupted.")
        return

    try:
        asyncio.run(run(args, config))
    except KeyboardInterrupt:
        log.info("Interrupted.")
    except SystemExit:
        log.error("Operation failed with config=%s", config)
        raise
    except Exception:
        log.exception("Operation failed with config=%s", config)
        raise


if __name__ == "__main__":
    main()
