"""Simple BLE controller for Hue lightstrip plus."""

from __future__ import annotations

import argparse
import asyncio
import logging
from dataclasses import dataclass
from typing import Optional

from bleak import BleakClient, BleakScanner

LIGHT_NAME = "Hue lightstrip plus"
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

    subparsers = parser.add_subparsers(dest="command", required=True)

    power = subparsers.add_parser("power", help="Turn the light on or off.")
    power.add_argument("state", choices=["on", "off"], help="Power state.")
    power.add_argument("brightness", nargs="?", type=int, help="Brightness 1-255 when on.")

    color = subparsers.add_parser(
        "color",
        help="Set color via 0007 (brightness + RGB + temperature).",
    )
    color.add_argument("--brightness", type=int, default=DEFAULT_BRIGHTNESS)
    color.add_argument("--red", type=int, default=0)
    color.add_argument("--green", type=int, default=0)
    color.add_argument("--blue", type=int, default=0)
    color.add_argument(
        "--temperature",
        type=int,
        default=DEFAULT_TEMPERATURE,
        help="Color temperature as 0-65535.",
    )
    color.add_argument(
        "--prefix",
        default=DEFAULT_COLOR_PREFIX.hex(),
        help="Prefix bytes for 0007 payload (hex).",
    )
    color.add_argument(
        "--raw",
        help="Raw payload bytes for 0007 (hex). Overrides component fields.",
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


async def run(args: argparse.Namespace) -> None:
    light = await HueLight.connect(args.device, timeout=args.timeout)
    try:
        if args.command == "power":
            brightness = None
            if args.state == "on" and args.brightness is not None:
                brightness = require_int_range("Brightness", args.brightness, 1, 255)
            await light.set_power(args.state == "on", brightness)
            return

        if args.command == "color":
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
