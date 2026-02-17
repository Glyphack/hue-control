"""Payload parsing and encoding helpers for Hue lamp control."""

from __future__ import annotations

import logging
import struct
from datetime import UTC, datetime

from huec.lib.models import (
    Alarm,
    AlarmProperties,
)

EXPECTED_DELETE_ACK_TYPE = 0x03
EXPECTED_DELETE_CONFIRM_TYPE = 0x04
EXPECTED_CONFIRM_TRAILER = bytes([0xFF, 0xFF])
log = logging.getLogger("huec")


def hex_to_bin(value: str) -> bytes:
    cleaned = value.lower().replace("0x", "").replace(" ", "").replace("\n", "")
    assert len(cleaned) % 2 == 0, "Hex payload must have an even number of characters."
    assert all(c in "0123456789abcdef" for c in cleaned), f"Invalid hex payload: {value}."
    return bytes.fromhex(cleaned)


def bin_to_hex(data, width=16):
    s = "\n"
    for i in range(0, len(data), width):
        chunk = data[i : i + width]
        hex_str = " ".join(f"{b:02x}" for b in chunk)
        s += f"{hex_str:48}\n"
    return s


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
        _id=slot_id,
        raw=data,
        payload=payload,
        payload_length=payload_length,
        properties=properties,
    )


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
        # Trailing marker is usually 0x00, but some enabled alarms use 0x01.
        if data[marker_index] not in (0x00, 0x01):
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


def build_enable_non_timer_command(alarm: Alarm) -> bytes:
    """Build an enable payload for wakeup/sleep alarms."""
    if len(alarm.payload) < 7:
        raise ValueError(
            f"Alarm payload for slot 0x{alarm._id:04x} is too short: {len(alarm.payload)}"
        )

    payload = bytearray(alarm.payload)
    payload[1] = 0x01
    payload[-1] = 0x01
    now_timestamp = int(datetime.now(tz=UTC).timestamp())
    scheduled_timestamp = struct.unpack_from("<I", payload, 3)[0]
    while scheduled_timestamp <= now_timestamp:
        scheduled_timestamp += 24 * 60 * 60
    struct.pack_into("<I", payload, 3, scheduled_timestamp)

    lo = alarm._id & 0xFF
    hi = (alarm._id >> 8) & 0xFF
    return bytes([0x01, lo, hi]) + bytes(payload)


def build_enable_timer_command(alarm: Alarm) -> bytes:
    """Build an enable payload for timers by scheduling from now + duration."""
    if len(alarm.payload) < 7:
        raise ValueError(
            f"Alarm payload for slot 0x{alarm._id:04x} is too short: {len(alarm.payload)}"
        )

    payload = bytearray(alarm.payload)
    payload[1] = 0x01
    payload[-1] = 0x01
    duration_seconds = alarm.extract_timer_duration_seconds()
    now_timestamp = int(datetime.now(tz=UTC).timestamp())
    struct.pack_into("<I", payload, 3, now_timestamp + duration_seconds)

    lo = alarm._id & 0xFF
    hi = (alarm._id >> 8) & 0xFF
    return bytes([0x01, lo, hi]) + bytes(payload)


def build_enable_alarm_command(alarm: Alarm) -> bytes:
    """Backwards-compatible wrapper that dispatches timer/non-timer enable payloads."""
    if alarm.is_wake_up_or_sleep():
        return build_enable_non_timer_command(alarm)
    return build_enable_timer_command(alarm)


def build_disable_alarm_command(alarm: Alarm) -> bytes:
    """Build a timer write payload that disables an existing alarm slot."""
    if len(alarm.payload) < 7:
        raise ValueError(
            f"Alarm payload for slot 0x{alarm._id:04x} is too short: {len(alarm.payload)}"
        )

    payload = bytearray(alarm.payload)
    payload[1] = 0x00
    payload[-1] = 0x00

    lo = alarm._id & 0xFF
    hi = (alarm._id >> 8) & 0xFF
    return bytes([0x01, lo, hi]) + bytes(payload)


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
