"""Simple BLE controller for Hue lightstrip plus."""

from __future__ import annotations

import argparse
import asyncio
import enum
import logging
import os
import struct
import threading
import time
from dataclasses import dataclass
from datetime import UTC, datetime
from enum import StrEnum
from http.server import BaseHTTPRequestHandler, HTTPServer
from urllib.parse import parse_qs, urlparse

from bleak import BleakClient, BleakScanner

from scripts.subscribe_all import subscribe_all

DEFAULT_DEVICE_NAME = "Hue lightstrip plus"
POWER_UUID = "932c32bd-0002-47a2-835a-a8d455b859dd"
COLOR_UUID = "932c32bd-0007-47a2-835a-a8d455b859dd"
RGB_UUID = "932c32bd-0005-47a2-835a-a8d455b859dd"
TIMER_UUID = "9da2ddf1-0001-44d0-909c-3f3d3cb34a7b"
DEFAULT_BRIGHTNESS = 0xFE
TIME_FORMAT = "%Y-%m-%d %H:%M"
NOTIFICATION_TIMEOUT = 10.0

EXPECTED_DELETE_ACK_TYPE = 0x03
EXPECTED_DELETE_CONFIRM_TYPE = 0x04
EXPECTED_CONFIRM_TRAILER = bytes([0xFF, 0xFF])


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("hue-control")


@dataclass(frozen=True)
class Config:
    device_name: str
    timeout: float


class WakeUpMode(StrEnum):
    sunrise = enum.auto()
    full_bright = enum.auto()


@dataclass(frozen=True)
class WakeupCommand:
    name: str
    time: datetime
    mode: WakeUpMode
    fade_in: int
    active: bool
    edit: bool


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
class AlarmProperties:
    active: bool
    timestamp: datetime
    mystery_bytes: bytes
    name: str


@dataclass
class Alarm:
    slot_id: int
    raw: bytes
    payload: bytes
    payload_length: int
    properties: AlarmProperties


@dataclass
class HueLight:
    client: BleakClient
    name: str
    address: str
    timer_notification_queue: asyncio.Queue[bytes] = asyncio.Queue()

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

    async def _confirm_power(self, target_on: bool) -> None:
        target_label = "on" if target_on else "off"
        for _ in range(20):
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
        await self._confirm_power(on)

    async def _write(self, uuid: str, data: bytes, note: str | None = None) -> None:
        suffix = f" ({note})" if note else ""
        formatted_hex = " ".join(data.hex()[i : i + 2] for i in range(0, len(data.hex()), 2))
        log.info("WRITE uuid=%s response=False data=0x%s%s", uuid, formatted_hex, suffix)
        await self.client.write_gatt_char(uuid, data, response=True)
        log.info("WRITE Complete")

    async def set_alarm(self, data: bytes, note: str | None = None) -> None:
        suffix = f" ({note})" if note else ""
        formatted_hex = " ".join(data.hex()[i : i + 4] for i in range(0, len(data.hex()), 4))
        log.info(
            "WRITE uuid=%s response=False data=0x%s%s",
            TIMER_UUID,
            data.hex(),
            suffix,
        )
        log.info("      formatted: %s", formatted_hex)
        # TODO: This does not work so disabled
        # await self.client.write_gatt_char(TIMER_UUID, data, response=False)

    async def list_alarm_ids(self) -> list[int]:
        """Parse the slot list notification response.

        Format: [0x00=type] [status] [unknown] [count] [slot_id LE16]...
        """
        LIST_TIMERS_MSG = bytes([0x00])
        await self.client.write_gatt_char(TIMER_UUID, LIST_TIMERS_MSG, response=True)

        data = await asyncio.wait_for(
            self.timer_notification_queue.get(), timeout=NOTIFICATION_TIMEOUT
        )

        slot_ids = parse_alarm_ids(data)
        return slot_ids

    async def read_alarms(self) -> list[Alarm]:
        """Connect to the lamp, read all alarm slots, and return parsed data."""

        client = self.client
        slot_ids = await self.list_alarm_ids()

        slots: list[Alarm] = []
        for slot_id in slot_ids:
            lo = slot_id & 0xFF
            hi = (slot_id >> 8) & 0xFF
            TIMER_INFO_MSG = bytes([0x02, lo, hi, 0x00, 0x00])
            await client.write_gatt_char(TIMER_UUID, TIMER_INFO_MSG, response=True)
            response = await asyncio.wait_for(
                self.timer_notification_queue.get(), timeout=NOTIFICATION_TIMEOUT
            )
            try:
                slot = parse_alarm(response)
            except ValueError as exc:
                print(f"  Error parsing slot {response}: {exc}")
                continue
            slots.append(slot)

        return slots

    async def enable_alarm(self, alarm: Alarm):
        msg = alarm.payload

        # TODO: Needs testing
        await self._write(TIMER_UUID, msg, "Enabling Timer")

        # TODO: Print this and get the value and confirm the response
        ack = await asyncio.wait_for(
            self.timer_notification_queue.get(),
            timeout=NOTIFICATION_TIMEOUT,
        )
        print(f"  ACK:     {format_hex(ack)}")
        # TODO: Print this and get the value and confirm the response
        confirm = await asyncio.wait_for(
            self.timer_notification_queue.get(), timeout=NOTIFICATION_TIMEOUT
        )
        print(f"  Confirm: {format_hex(confirm)}")

        return


def parse_hex_payload(value: str) -> bytes:
    cleaned = value.lower().replace("0x", "").replace(" ", "").replace("\n", "")
    if len(cleaned) % 2:
        raise SystemExit("Hex payload must have an even number of characters.")
    try:
        return bytes.fromhex(cleaned)
    except ValueError as exc:
        raise SystemExit(f"Invalid hex payload: {value}.") from exc


def parse_alarm_ids(data: bytes) -> list[int]:
    if len(data) < 4:
        raise ValueError(f"Slot list response too short: {len(data)} bytes")
    if data[0] != 0x00:
        raise ValueError(f"Expected response type 0x00 for slot list, got 0x{data[0]:02x}")
    if data[1] != 0x00:
        raise ValueError(f"Slot list status not OK: 0x{data[1]:02x}")

    count = data[3]
    slot_ids = []
    for i in range(count):
        offset = 4 + i * 2
        if offset + 2 > len(data):
            break
        slot_ids.append(struct.unpack_from("<H", data, offset)[0])

    return slot_ids


def require_int_range(name: str, value: int, min_value: int, max_value: int) -> int:
    if not min_value <= value <= max_value:
        raise SystemExit(f"{name} must be between {min_value} and {max_value}, got {value}.")
    return value


def datetime_to_hex_little_endian(dt):
    """
    Convert a datetime object to 32-bit Unix timestamp in little endian hex format.

    Args:
        dt: datetime object

    Returns:
        String in format like "D8B6 8E69"
    """
    timestamp = int(dt.timestamp())
    packed = struct.pack("<I", timestamp)
    hex_string = packed.hex().upper()
    formatted = f"{hex_string[0:4]} {hex_string[4:8]}"

    return formatted


def encode_string(text):
    length = len(text)
    length_hex = format(length, "02x")
    text_hex = text.encode("ascii").hex()

    return length_hex + text_hex


def build_wakeup_payload(command: WakeupCommand) -> bytes:
    if command.mode == WakeUpMode.sunrise:
        print(command.time)
        t = datetime_to_hex_little_endian(command.time)
        print(t)
        n = encode_string(command.name)
        e = "0100" if command.active else "0000"
        print(command.edit)
        c = "0000" if command.edit else "FF00"
        return parse_hex_payload(
            f"""
            01FF {c} {e} {t} 0009
            0101 0106 0109 0801 5B19 0194
            D184 84B7 5143 DAA8 67A9 2F02
            110C 8D00 FFFF FFFF {n} 01
            """
        )

    raise AssertionError()


def build_timer_payload(command: TimerCommand) -> None:
    pass


def build_sleep_payload(command: SleepCommand) -> None:
    pass


def build_args() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Control Hue lightstrip over BLE.")
    parser.add_argument(
        "-d",
        "--device",
        default=DEFAULT_DEVICE_NAME,
        help="BLE device name.",
    )
    parser.add_argument("--timeout", type=float, default=15.0, help="BLE scan timeout.")

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
    wakeup.add_argument("--name", required=True, help="Name of the alarm")
    wakeup.add_argument("--time", required=True, help=f"wakeup time in format {TIME_FORMAT}")
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

    timer = subparsers.add_parser("timer", help="Create a timer command.")
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

    sleep = subparsers.add_parser("sleep", help="Create a sleep command.")
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
        help="Read and dump all alarm slots from the lamp.",
    )

    dev_subparsers.add_parser(
        "delete-alarms",
        help="Delete all alarm slots from the lamp.",
    )

    dev_subparsers.add_parser(
        "enable-alarms",
        help="Enable all inactive alarm slots on the lamp.",
    )

    return parser


def run_customize_mode(config: Config) -> None:
    """Run customize mode with HTTP server directly calling BLE functions."""

    async def connect_light():
        return await HueLight.connect(config)

    # Connect to light once at startup
    light = asyncio.run(connect_light())
    log.info("Connected to light for customize mode")

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

                    async def set_power_async():
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

                    async def write_color_async():
                        await light.client.write_gatt_char(COLOR_UUID, data_bytes, response=False)
                        log.info("HTTP->BLE write: 0x%s", data_bytes.hex())

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

    # Open browser after short delay
    threading.Thread(
        target=lambda: (time.sleep(0.02), os.system("open http://localhost:8000")),
        daemon=True,
    ).start()

    print("Customize server running at http://localhost:8000")
    try:
        HTTPServer(("localhost", 8000), Handler).serve_forever()
    finally:
        asyncio.run(light.disconnect())


def parse_alarm(data: bytes) -> Alarm:
    """Parse an individual alarm slot notification response."""
    if len(data) < 6:
        raise ValueError(f"Alarm slot response too short: {len(data)} bytes")
    if data[0] != 0x02:
        raise ValueError(f"Expected response type 0x02, got 0x{data[0]:02x}")
    if data[1] != 0x00:
        raise ValueError(f"Alarm slot status not OK: 0x{data[1]:02x}")

    slot_id = struct.unpack_from("<H", data, 2)[0]
    payload_length = data[4]
    payload = data[8:]
    assert len(payload) == payload_length, (
        f"Alarm slot payload length {payload_length} exceeds response payload {len(payload)}"
    )

    core = parse_alarm_properties(data)

    return Alarm(
        slot_id=slot_id,
        raw=data,
        payload=payload,
        payload_length=payload_length,
        properties=core,
    )


def format_hex(data: bytes) -> str:
    return " ".join(f"{b:04x}" for b in data)


def parse_alarm_properties(data: bytes) -> AlarmProperties:
    """Parse enabled flag, time stamp, and the leading mystery bytes from full response."""
    ACTIVE_INDEX = 9
    TIMESTAMP_START = 11

    if len(data) < TIMESTAMP_START + 1:
        raise ValueError(
            f"Alarm response too short: {len(data)} bytes, need at least {TIMESTAMP_START + 4}"
        )

    active_value = data[ACTIVE_INDEX]
    if active_value not in (0x00, 0x01):
        raise ValueError(f"Invalid active flag: 0x{active_value:02x}, expected 0x00 or 0x01")

    timestamp_value = struct.unpack_from("<I", data, TIMESTAMP_START)[0]
    try:
        timestamp = datetime.fromtimestamp(timestamp_value, tz=UTC)
    except (OSError, ValueError) as exc:
        raise ValueError(f"Invalid timestamp value: {timestamp_value}") from exc

    name = parse_alarm_name(data)
    name_length_index, _ = find_alarm_name_segment(data)

    mystery_bytes = data[TIMESTAMP_START + 4 : name_length_index]

    return AlarmProperties(
        active=active_value == 0x01, timestamp=timestamp, mystery_bytes=mystery_bytes, name=name
    )


# TODO: Refactor. Just iterate back on the data, first byte is 0 then it's some characters.
# Keep coming back and add characters until you find a number that
# matches the number of characters you matched.
def find_alarm_name_segment(data: bytes) -> tuple[int, bytes]:
    """Find name segment in full response data (searches in payload portion starting at byte 6)."""
    PAYLOAD_START = 6
    if len(data) < PAYLOAD_START:
        raise ValueError("Alarm response too short for payload")

    for marker_index in range(len(data) - 1, PAYLOAD_START - 1, -1):
        if data[marker_index] != 0x00:
            continue

        collected = bytearray()
        for index in range(marker_index - 1, PAYLOAD_START - 1, -1):
            value = data[index]
            if value == len(collected):
                if not collected:
                    raise ValueError("Alarm payload invalid name length")
                name_bytes = data[index + 1 : marker_index]
                if not is_printable_ascii(name_bytes):
                    raise ValueError(f"Alarm payload name not printable: {name_bytes.hex()}")
                return index, name_bytes
            if not (0x20 <= value <= 0x7E):
                break
            collected.append(value)

    raise ValueError("Alarm payload name not found")


def parse_alarm_name(data: bytes) -> str:
    """Parse alarm name from full response by scanning backward for 0x00, then length+name bytes."""
    _, name_bytes = find_alarm_name_segment(data)
    return name_bytes.decode("ascii")


def is_printable_ascii(data: bytes) -> bool:
    return all(0x20 <= b <= 0x7E for b in data)


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


def check_delete_ack(slot_id: int, data: bytes) -> bool:
    """Check if delete ACK matches expected: 03 00 <lo> <hi>."""
    lo = slot_id & 0xFF
    hi = (slot_id >> 8) & 0xFF
    expected = bytes([EXPECTED_DELETE_ACK_TYPE, 0x00, lo, hi])
    return data == expected


def check_delete_confirm(slot_id: int, data: bytes) -> bool:
    """Check if delete confirmation matches expected: 04 <lo> <hi> FF FF."""
    lo = slot_id & 0xFF
    hi = (slot_id >> 8) & 0xFF
    expected = bytes([EXPECTED_DELETE_CONFIRM_TYPE, lo, hi]) + EXPECTED_CONFIRM_TRAILER
    return data == expected


async def run(args: argparse.Namespace, c: Config) -> None:
    light = await HueLight.connect(c)

    def on_notify(_, data: bytearray):
        light.timer_notification_queue.put_nowait(bytes(data))

    # Sub to timer to get responses when interacting with timers
    await light.client.start_notify(TIMER_UUID, on_notify)

    await handle_command(args, light, c)

    await light.client.stop_notify(TIMER_UUID)


async def handle_command(args: argparse.Namespace, light: HueLight, c: Config):
    if args.command == "power":
        try:
            brightness = None
            if args.state == "on" and args.brightness is not None:
                brightness = require_int_range("Brightness", args.brightness, 1, 255)
            await light.set_power(args.state == "on", brightness)
        finally:
            await light.disconnect()

    if args.command == "wakeup":
        command = WakeupCommand(
            name=args.name,
            time=datetime.strptime(args.time, TIME_FORMAT),
            mode=WakeUpMode(args.mode),
            fade_in=args.fade_in,
            active=not args.deactive,
            edit=args.edit,
        )
        await light.set_alarm(build_wakeup_payload(command))

    if args.command == "timer":
        command = TimerCommand(
            duration=args.duration,
            effect=args.effect,
            active=not args.deactive,
        )
        build_timer_payload(command)

    if args.command == "sleep":
        command = SleepCommand(
            time=args.time,
            mode=args.mode,
            active=not args.deactive,
        )
        build_sleep_payload(command)

    if args.command == "dev":
        if args.dev_command == "set-characteristic":
            payload = parse_hex_payload(args.data)
            await light._write(args.characteristic, payload)

        if args.dev_command == "read-alarms":
            alarms = await light.read_alarms()
            print_alarm_report(alarms)

        if args.dev_command == "subscribe-all":
            # TODO: Inline this like the other dev commands
            await subscribe_all(c.device_name, timeout=c.timeout)

        if args.dev_command == "delete-alarms":
            alarms = await light.read_alarms()
            ids = await light.list_alarm_ids()

            for id in ids:
                # TODO: Explain what is this
                lo = id & 0xFF
                hi = (id >> 8) & 0xFF
                cmd = bytes([0x03, lo, hi])
                print(f"\nDeleting slot 0x{id:04x} -> write {format_hex(cmd)}")
                await light.client.write_gatt_char(TIMER_UUID, cmd, response=True)

                ack = await asyncio.wait_for(
                    light.timer_notification_queue.get(),
                    timeout=NOTIFICATION_TIMEOUT,
                )
                confirm = await asyncio.wait_for(
                    light.timer_notification_queue.get(), timeout=NOTIFICATION_TIMEOUT
                )
                ack_ok = check_delete_ack(id, ack)
                confirm_ok = check_delete_confirm(id, confirm)

                print(f"  ACK:     {format_hex(ack)}  {'OK' if ack_ok else 'UNEXPECTED'}")
                print(f"  Confirm: {format_hex(confirm)}  {'OK' if confirm_ok else 'UNEXPECTED'}")

                if not ack_ok:
                    expected_ack = bytes([0x03, 0x00, lo, hi])
                    print(f"  Expected ACK:     {format_hex(expected_ack)}")
                if not confirm_ok:
                    expected_conf = bytes([0x04, lo, hi]) + EXPECTED_CONFIRM_TRAILER
                    print(f"  Expected Confirm: {format_hex(expected_conf)}")

        if args.dev_command == "enable-alarms":
            alarms = await light.read_alarms()

            for alarm in alarms:
                if alarm.properties.active:
                    continue
                await light.enable_alarm(alarm)


def main() -> None:
    parser = build_args()
    args = parser.parse_args()
    config = Config(device_name=args.device, timeout=args.timeout)
    log.info("Using device '%s'", config.device_name)

    # Handle customize mode separately (not in async context)
    if args.customize:
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
