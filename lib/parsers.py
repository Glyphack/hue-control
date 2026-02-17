"""Payload parsing and encoding helpers for Hue lamp control."""

from __future__ import annotations

import struct
from datetime import UTC, datetime

from lib.models import (
    Alarm,
    AlarmProperties,
    SleepCommand,
    TimerCommand,
    WakeupCommand,
    WakeUpMode,
)

EXPECTED_DELETE_ACK_TYPE = 0x03
EXPECTED_DELETE_CONFIRM_TYPE = 0x04
EXPECTED_CONFIRM_TRAILER = bytes([0xFF, 0xFF])


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


def datetime_to_hex_little_endian(dt: datetime) -> str:
    timestamp = int(dt.timestamp())
    packed = struct.pack("<I", timestamp)
    hex_string = packed.hex().upper()
    return f"{hex_string[0:4]} {hex_string[4:8]}"


def encode_string(text: str) -> str:
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


def build_timer_payload(command: TimerCommand) -> bytes:
    raise NotImplementedError("Timer payload builder is not implemented yet.")


def build_sleep_payload(command: SleepCommand) -> bytes:
    raise NotImplementedError("Sleep payload builder is not implemented yet.")


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
    if len(payload) != payload_length:
        raise ValueError(
            f"Alarm slot payload length {payload_length} exceeds response payload {len(payload)}"
        )

    properties = parse_alarm_properties(data)

    return Alarm(
        slot_id=slot_id,
        raw=data,
        payload=payload,
        payload_length=payload_length,
        properties=properties,
    )


def format_hex(data: bytes) -> str:
    return " ".join(f"{b:04x}" for b in data)


def parse_alarm_properties(data: bytes) -> AlarmProperties:
    """Parse enabled flag, time stamp, and mystery bytes from full response."""
    active_index = 9
    timestamp_start = 11

    if len(data) < timestamp_start + 1:
        raise ValueError(
            f"Alarm response too short: {len(data)} bytes, need at least {timestamp_start + 4}"
        )

    active_value = data[active_index]
    if active_value not in (0x00, 0x01):
        raise ValueError(f"Invalid active flag: 0x{active_value:02x}, expected 0x00 or 0x01")

    timestamp_value = struct.unpack_from("<I", data, timestamp_start)[0]
    try:
        timestamp = datetime.fromtimestamp(timestamp_value, tz=UTC)
    except (OSError, ValueError) as exc:
        raise ValueError(f"Invalid timestamp value: {timestamp_value}") from exc

    name = parse_alarm_name(data)
    name_length_index, _ = find_alarm_name_segment(data)
    mystery_bytes = data[timestamp_start + 4 : name_length_index]

    return AlarmProperties(
        active=active_value == 0x01,
        timestamp=timestamp,
        mystery_bytes=mystery_bytes,
        name=name,
    )


def find_alarm_name_segment(data: bytes) -> tuple[int, bytes]:
    """Find name segment in full response data (searches payload portion from byte 6)."""
    payload_start = 6
    if len(data) < payload_start:
        raise ValueError("Alarm response too short for payload")

    for marker_index in range(len(data) - 1, payload_start - 1, -1):
        if data[marker_index] != 0x00:
            continue

        collected = bytearray()
        for index in range(marker_index - 1, payload_start - 1, -1):
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
    _, name_bytes = find_alarm_name_segment(data)
    return name_bytes.decode("ascii")


def is_printable_ascii(data: bytes) -> bool:
    return all(0x20 <= b <= 0x7E for b in data)


def check_delete_ack(slot_id: int, data: bytes) -> bool:
    lo = slot_id & 0xFF
    hi = (slot_id >> 8) & 0xFF
    expected = bytes([EXPECTED_DELETE_ACK_TYPE, 0x00, lo, hi])
    return data == expected


def check_delete_confirm(slot_id: int, data: bytes) -> bool:
    lo = slot_id & 0xFF
    hi = (slot_id >> 8) & 0xFF
    expected = bytes([EXPECTED_DELETE_CONFIRM_TYPE, lo, hi]) + EXPECTED_CONFIRM_TRAILER
    return data == expected
