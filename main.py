"""Simple BLE controller for Hue lightstrip plus."""

from __future__ import annotations

import argparse
import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from bleak import BleakClient, BleakScanner
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import urlparse, parse_qs


#LIGHT_NAME = "Hue lightstrip"
LIGHT_NAME = "3"
POWER_UUID = "932c32bd-0002-47a2-835a-a8d455b859dd"
COLOR_UUID = "932c32bd-0007-47a2-835a-a8d455b859dd"
RGB_UUID = "932c32bd-0005-47a2-835a-a8d455b859dd"

DEFAULT_COLOR_PREFIX = bytes([0x01, 0x01, 0x01, 0x02, 0x01])
DEFAULT_BRIGHTNESS = 0xFE
DEFAULT_TEMPERATURE = 0x015A


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("hue-control")

PRESET_COLORS = {
    "honolulu": (137, 146, 212, 91),
    "red": (254, 255, 0, 0),
    "green": (254, 0, 255, 0),
    "blue": (254, 0, 0, 255),
    "white": (254, 255, 255, 255),
}
PRESET_PAYLOADS = {
    # prefix + bri + r + g + b + temp(2 bytes, little endian)
    "honolulu": bytes([0x01, 0x01, 0x01, 0x02, 0x01, 0x5C, 0x04, 0xBB, 0x73, 0x74, 0x74]),
}



@dataclass(frozen=True)
class HueColor:
    brightness: int
    red: int
    green: int
    blue: int
    temperature: int
    prefix: bytes = DEFAULT_COLOR_PREFIX

    def to_bytes(self) -> bytes:
        temp_bytes = self.temperature.to_bytes(2, "little")
        return self.prefix + bytes([self.brightness, self.red, self.green, self.blue]) + temp_bytes

    def description(self) -> str:
        return (
            "bri={brightness} rgb=({red},{green},{blue}) temp={temperature}"
        ).format(
            brightness=self.brightness,
            red=self.red,
            green=self.green,
            blue=self.blue,
            temperature=self.temperature,
        )


@dataclass(frozen=True)
class ColorPayload:
    data: bytes
    note: str


@dataclass
class HueLight:
    client: BleakClient
    name: str
    address: str

    @classmethod
    async def connect(cls, name: str, timeout: float) -> "HueLight":
        log.info("Scanning for '%s'...", name)
        device = await BleakScanner.find_device_by_name(name, timeout=timeout)
        if not device:
            raise SystemExit(f"Device '{name}' not found.")

        log.info("Found device: %s (%s)", device.name, device.address)
        client = BleakClient(device, timeout=timeout)
        await client.connect(timeout=timeout)
        log.info("Connected=%s", client.is_connected)
        return cls(client=client, name=device.name or name, address=device.address)

    async def disconnect(self) -> None:
        if self.client.is_connected:
            await self.client.disconnect()

    async def set_power(self, on: bool, brightness: Optional[int]) -> None:
        if on:
            value = bytes([brightness if brightness is not None else 0x01])
        else:
            value = bytes([0x00])
        await self._write(POWER_UUID, value, note="power")

    async def set_color(self, color: HueColor) -> None:
        await self._write(COLOR_UUID, color.to_bytes(), note=color.description())

    async def set_color_payload(self, payload: ColorPayload) -> None:
        await self._write(COLOR_UUID, payload.data, note=payload.note)

    async def set_rgb(self, brightness: int, red: int, green: int, blue: int) -> None:
        """Set RGB via characteristic 0005 (less reliable than 0007)."""
        await self._write(
            RGB_UUID,
            bytes([brightness, red, green, blue]),
            note="rgb via 0005 (limited support)",
        )

    async def _write(self, uuid: str, data: bytes, note: Optional[str] = None) -> None:
        suffix = f" ({note})" if note else ""
        log.info("WRITE uuid=%s response=False data=0x%s%s", uuid, data.hex(), suffix)
        await self.client.write_gatt_char(uuid, data, response=False)
        log.info("Done.")


def start_customize_server(light: HueLight):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)

            if parsed.path == "/send":
                qs = parse_qs(parsed.query)

                if "data" in qs:
                    hex_string = qs["data"][0]
                    data_bytes = bytes.fromhex(hex_string)

                    asyncio.create_task(
                        light.client.write_gatt_char(
                            COLOR_UUID, data_bytes, response=False
                        )
                    )

                    self.send_response(200)
                    self.end_headers()
                    self.wfile.write(b"OK")
                    return

            self.send_response(404)
            self.end_headers()

    print("Customize server running at http://localhost:8000")
    HTTPServer(("localhost", 8000), Handler).serve_forever()



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


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Control Hue lightstrip over BLE.")
    parser.add_argument("--device", default=LIGHT_NAME, help="BLE device name.")
    parser.add_argument("--timeout", type=float, default=20.0, help="BLE scan timeout.")

    subparsers = parser.add_subparsers(dest="command")#, required=True)

    power = subparsers.add_parser("power", help="Turn the light on or off.")
    power.add_argument("state", choices=["on", "off"], help="Power state.")
    power.add_argument("brightness", nargs="?", type=int, help="Brightness 1-255 when on.")

    parser.add_argument('--color', choices=PRESET_COLORS.keys(),
                        default='honolulu', help='preset color name',)
    #parser.add_argument("--color", choices=PRESET_PAYLOADS.keys(), default="honolulu")
    parser.add_argument(
    "--customize", action="store_true", help="Start HTTP server and keep BLE connection open",
)



    

    rgb = subparsers.add_parser(
        "rgb",
        help="Set RGB via 0005 (less compatible than 0007).",
    )
    rgb.add_argument("--brightness", type=int, default=DEFAULT_BRIGHTNESS)
    rgb.add_argument("--red", type=int, default=0)
    rgb.add_argument("--green", type=int, default=0)
    rgb.add_argument("--blue", type=int, default=0)

    return parser




def start_customize_server(loop: asyncio.AbstractEventLoop, queue: "asyncio.Queue[bytes]"):
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            parsed = urlparse(self.path)

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

                    # Enqueue safely into the asyncio loop thread
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






async def run(args: argparse.Namespace) -> None:
    light = await HueLight.connect(args.device, timeout=args.timeout)

    if args.customize:
        print("Customize mode enabled.")

        loop = asyncio.get_running_loop()
        queue: asyncio.Queue[bytes] = asyncio.Queue()

        # Start async BLE writer
        writer_task = asyncio.create_task(ble_writer(light, queue))

        # Start blocking HTTP server in a thread
        t = threading.Thread(target=start_customize_server, args=(loop, queue), daemon=True)
        t.start()

        # Keep main asyncio task alive forever (until Ctrl+C)
        try:
            await asyncio.Event().wait()
        finally:
            writer_task.cancel()
        return

    

    if hasattr(args, "color") and args.color:
        brightness, red, green, blue = PRESET_COLORS[args.color]
        await light.set_rgb(brightness, red, green, blue)
        #payload = PRESET_PAYLOADS[args.color]
        #await light.set_color_payload(ColorPayload(payload, note=f"preset {args.color}"))
        return


    try:
        if args.command == "power":
            brightness = None
            if args.state == "on" and args.brightness is not None:
                brightness = require_int_range("Brightness", args.brightness, 1, 255)
            await light.set_power(args.state == "on", brightness)
            return

#        if args.command == "color":
            if args.raw:
                payload = ColorPayload(parse_hex_payload(args.raw), note="raw payload")
                await light.set_color_payload(payload)
                return

            brightness = require_int_range("Brightness", args.brightness, 1, 255)
            red = require_int_range("Red", args.red, 0, 255)
            green = require_int_range("Green", args.green, 0, 255)
            blue = require_int_range("Blue", args.blue, 0, 255)
            temperature = require_int_range("Temperature", args.temperature, 0, 65535)
            prefix = parse_hex_payload(args.prefix)
            color = HueColor(
                brightness=brightness,
                red=red,
                green=green,
                blue=blue,
                temperature=temperature,
                prefix=prefix,
            )
            await light.set_color(color)
            return

        if args.command == "rgb":
            brightness = require_int_range("Brightness", args.brightness, 1, 255)
            red = require_int_range("Red", args.red, 0, 255)
            green = require_int_range("Green", args.green, 0, 255)
            blue = require_int_range("Blue", args.blue, 0, 255)
            await light.set_rgb(brightness, red, green, blue)
            return
    finally:
        await light.disconnect()


def main() -> None:
    parser = build_parser()
    args = parser.parse_args()
    try:
        asyncio.run(run(args))
    except KeyboardInterrupt:
        log.info("Interrupted.")


if __name__ == "__main__":
    main()
