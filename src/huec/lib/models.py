"""Data models for Hue lamp control and alarm operations."""

from __future__ import annotations

import enum
import struct
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum


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
    _id: int
    raw: bytes
    payload: bytes
    payload_length: int
    properties: AlarmProperties

    def is_wake_up_or_sleep(self) -> bool:
        """Wakeup/sleep alarms contain a fixed FFFF_FFFF marker."""
        return b"\xff\xff\xff\xff" in self.payload

    def extract_timer_duration_seconds(self) -> int:
        """Read timer duration from the two bytes before the nearest 00 00 pre-name marker."""
        name_length_index, _ = self._find_name_segment()
        marker_index = name_length_index - 2
        if marker_index < 2:
            raise ValueError(
                f"Timer marker out of bounds for slot 0x{self._id:04x}: {self.raw.hex()}"
            )
        if self.raw[marker_index] != 0x00 or self.raw[marker_index + 1] != 0x00:
            raise ValueError(f"Timer duration marker not found before name: {self.raw.hex()}")
        return struct.unpack_from("<H", self.raw, marker_index - 2)[0]

    def _find_name_segment(self) -> tuple[int, bytes]:
        payload_start = 6
        if len(self.raw) < payload_start:
            raise ValueError("Alarm response too short for payload")

        for marker_index in range(len(self.raw) - 1, payload_start - 1, -1):
            if self.raw[marker_index] not in (0x00, 0x01):
                continue

            collected = bytearray()
            for index in range(marker_index - 1, payload_start - 1, -1):
                value = self.raw[index]
                if value == len(collected):
                    if not collected:
                        raise ValueError("Alarm payload invalid name length")
                    name_bytes = self.raw[index + 1 : marker_index]
                    if not self._is_printable_ascii(name_bytes):
                        raise ValueError(f"Alarm payload name not printable: {name_bytes.hex()}")
                    return index, name_bytes
                if not (0x20 <= value <= 0x7E):
                    break
                collected.append(value)

        raise ValueError("Alarm payload name not found")

    @staticmethod
    def _is_printable_ascii(data: bytes) -> bool:
        return all(0x20 <= b <= 0x7E for b in data)


@dataclass(frozen=True)
class AlarmListResult:
    raw: bytes
    slot_ids: list[int]


@dataclass(frozen=True)
class AlarmEnableResult:
    slot_id: int
    ack: bytes
    ack_ok: bool
    confirm: bytes
    confirm_ok: bool

    def is_ok(self):
        return self.ack_ok and self.confirm_ok


@dataclass(frozen=True)
class AlarmDeleteResult:
    slot_id: int
    command: bytes
    ack: bytes
    confirm: bytes
    ack_ok: bool
    confirm_ok: bool

    def is_ok(self):
        return self.ack_ok and self.confirm_ok
