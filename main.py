"""Simple BLE controller for Hue lightstrip plus."""

from __future__ import annotations

import argparse
import asyncio
import logging
import threading
from dataclasses import dataclass
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from bleak import BleakClient, BleakScanner
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs
import webbrowser
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs

from scripts.set_characteristic import set_characteristic
from scripts.subscribe_all import subscribe_all

DEFAULT_DEVICE_NAME = "Hue lightstrip"
POWER_UUID = "932c32bd-0002-47a2-835a-a8d455b859dd"
COLOR_UUID = "932c32bd-0007-47a2-835a-a8d455b859dd"
RGB_UUID = "932c32bd-0005-47a2-835a-a8d455b859dd"
DEFAULT_BRIGHTNESS = 0xFE


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("hue-control")


@dataclass(frozen=True)
class Config:
    device_name: str
    timeout: float


@dataclass(frozen=True)
class WakeupCommand:
    time: str
    mode: str
    fade_in: int
    active: bool


@dataclass(frozen=True)
class TimerCommand:
    duration: str
    effect: str
    active: bool


@dataclass(frozen=True)
class SleepCommand:
    time: str
    mode: str | None
    active: bool


@dataclass
class HueLight:
    client: BleakClient
    name: str
    address: str

    @classmethod
    async def connect(cls, config: Config) -> HueLight:
        log.info("Scanning for '%s'...", config.device_name)
        device = await BleakScanner.find_device_by_name(config.device_name, timeout=config.timeout)
        if not device:
            raise SystemExit(f"Device '{config.device_name}' not found.")

        log.info("Found device: %s (%s)", device.name, device.address)
        client = BleakClient(device, timeout=config.timeout)
        await client.connect(timeout=config.timeout)
        log.info("Connected=%s", client.is_connected)
        return cls(
            client=client,
            name=device.name or config.device_name,
            address=device.address,
        )

    async def disconnect(self) -> None:
        if self.client.is_connected:
            await self.client.disconnect()

    async def read_power(self) -> bytes:
        readback = await self.client.read_gatt_char(POWER_UUID)
        readback_bytes = bytes(readback)
        log.info("READ uuid=%s data=0x%s", POWER_UUID, readback_bytes.hex())
        return readback_bytes

    async def _confirm_power(self, target_on: bool, value: bytes) -> None:
        target_label = "on" if target_on else "off"
        for _attempt in range(20):
            readback = await self.read_power()
            if readback:
                state_on = readback[0] != 0x00
                if state_on == target_on:
                    return
            log.warning("Power not set yet (%s), retrying in 0.3s...", target_label)
            await asyncio.sleep(0.3)
        log.error("Failed to confirm power %s after 20 attempts", target_label)

    async def set_power(self, on: bool, brightness: int | None) -> None:
        value = bytes([brightness if brightness is not None else 0x01]) if on else bytes([0x00])
        await self._write(POWER_UUID, value, note="power")
        await self._confirm_power(on, value)

    async def _write(self, uuid: str, data: bytes, note: str | None = None) -> None:
        suffix = f" ({note})" if note else ""
        log.info("WRITE uuid=%s response=False data=0x%s%s", uuid, data.hex(), suffix)
        await self.client.write_gatt_char(uuid, data, response=False)
        log.info("Done.")


def parse_hex_payload(value: str) -> bytes:
    cleaned = value.lower().replace("0x", "").replace(" ", "")
    if len(cleaned) % 2:
        raise SystemExit("Hex payload must have an even number of characters.")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise SystemExit(f"Invalid hex payload: {value}.") from exc


def require_int_range(name: str, value: int, min_value: int, max_value: int) -> int:
    if not min_value <= value <= max_value:
        raise SystemExit(f"{name} must be between {min_value} and {max_value}, got {value}.")
    return value


def build_wakeup_payload(command: WakeupCommand) -> None:
    pass


def build_timer_payload(command: TimerCommand) -> None:
    pass


def build_sleep_payload(command: SleepCommand) -> None:
    pass


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Control Hue lightstrip over BLE.")
    parser.add_argument(
        "-d",
        "--device",
        default=DEFAULT_DEVICE_NAME,
        help="BLE device name.",
    )
    parser.add_argument("--timeout", type=float, default=20.0, help="BLE scan timeout.")

    subparsers = parser.add_subparsers(dest="command")  # , required=True)

    power = subparsers.add_parser("power", help="Turn the light on or off.")
    power.add_argument("state", choices=["on", "off"], help="Power state.")
    power.add_argument("brightness", nargs="?", type=int, help="Brightness 1-255 when on.")

    parser.add_argument(
        "--customize",
        action="store_true",
        help="Start HTTP server and keep BLE connection open",
    )

    rgb = subparsers.add_parser(
        "rgb",
        help="Set RGB via 0005 (less compatible than 0007).",
    )
    rgb.add_argument("--brightness", type=int, default=DEFAULT_BRIGHTNESS)
    rgb.add_argument("--red", type=int, default=0)
    rgb.add_argument("--green", type=int, default=0)
    rgb.add_argument("--blue", type=int, default=0)

    wakeup = subparsers.add_parser("wakeup", help="Create a wakeup command.")
    wakeup.add_argument("--time", required=True, help="Human-readable wakeup time.")
    wakeup.add_argument(
        "--mode",
        choices=["sunrise", "fullbright"],
        required=True,
        help="Wakeup mode.",
    )
    wakeup.add_argument(
        "--fade-in",
        dest="fade_in",
        type=int,
        choices=[10, 20, 30],
        required=True,
        help="Fade-in time in minutes.",
    )
    wakeup.add_argument(
        "--deactive",
        action="store_true",
        help="Create as inactive.",
    )

    timer = subparsers.add_parser("timer", help="Create a timer command.")
    timer.add_argument("--duration", required=True, help="Timer duration.")
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

    sleep = subparsers.add_parser("sleep", help="Create a sleep command.")
    sleep.add_argument("--time", required=True, help="Human-readable sleep time.")
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

    return parser


def start_customize_server(
    loop: asyncio.AbstractEventLoop, queue: "asyncio.Queue[bytes]", light: HueLight
):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)

            # Serve HTML
            if parsed.path == "/" or parsed.path == "":
                self.send_response(200)
                self.send_header("Content-type", "text/html")
                self.end_headers()

                with open("auto_color.html", "rb") as f:
                    self.wfile.write(f.read())
                return

            # Handle power control
            if parsed.path == "/power":
                qs = parse_qs(parsed.query)
                if "state" in qs:
                    state = qs["state"][0]

                    if state == "on":
                        # default ON brightness
                        loop.call_soon_threadsafe(asyncio.create_task, light.set_power(True, 0xFE))
                    elif state == "off":
                        loop.call_soon_threadsafe(asyncio.create_task, light.set_power(False, None))

                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"OK")
                    return

            # Handle color send
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

                    loop.call_soon_threadsafe(queue.put_nowait, data_bytes)

                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"OK")
                    return

            self.send_response(404)
            self.end_headers()

    print("Customize server running at http://localhost:8000")
    HTTPServer(("localhost", 8000), Handler).serve_forever()


async def ble_writer(light: "HueLight", queue: "asyncio.Queue[bytes]") -> None:
    while True:
        data = await queue.get()
        try:
            await light.client.write_gatt_char(COLOR_UUID, data, response=False)
            log.info("HTTP->BLE write: 0x%s", data.hex())
        except Exception:
            log.exception("BLE write failed")
        finally:
            queue.task_done()


async def run(args: argparse.Namespace, config: Config) -> None:
    if args.command == "power":
        light = await HueLight.connect(config)
        try:
            brightness = None
            if args.state == "on" and args.brightness is not None:
                brightness = require_int_range("Brightness", args.brightness, 1, 255)
            await light.set_power(args.state == "on", brightness)
        finally:
            await light.disconnect()
        return

    if args.command == "wakeup":
        command = WakeupCommand(
            time=args.time,
            mode=args.mode,
            fade_in=args.fade_in,
            active=not args.deactive,
        )
        build_wakeup_payload(command)
        return

    if args.command == "timer":
        command = TimerCommand(
            duration=args.duration,
            effect=args.effect,
            active=not args.deactive,
        )
        build_timer_payload(command)
        return

    if args.command == "sleep":
        command = SleepCommand(
            time=args.time,
            mode=args.mode,
            active=not args.deactive,
        )
        build_sleep_payload(command)
        return

    if args.customize:
        light = await HueLight.connect(config)
        print("Customize mode enabled.")

        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[bytes] = asyncio.Queue()

        # Start async BLE writer
        writer_task = asyncio.create_task(ble_writer(light, queue))

        # Start blocking HTTP server in a thread
        t = threading.Thread(target=start_customize_server, args=(loop, queue, light), daemon=True)
        t.start()

        # Keep main asyncio task alive forever (until Ctrl+C)
        try:
            await asyncio.Event().wait()
        finally:
            writer_task.cancel()
        return

    if args.command == "dev":
        if args.dev_command == "set-characteristic":
            payload = parse_hex_payload(args.data)
            await set_characteristic(
                config.device_name,
                args.characteristic,
                payload,
                timeout=config.timeout,
            )
            return

        if args.dev_command == "subscribe-all":
            await subscribe_all(config.device_name, timeout=config.timeout)
            return


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    config = Config(device_name=args.device, timeout=args.timeout)
    log.info("Using device '%s'", config.device_name)
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
