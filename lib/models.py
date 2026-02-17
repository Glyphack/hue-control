"""Data models for Hue lamp control and alarm operations."""

from __future__ import annotations

import enum
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
    slot_id: int
    raw: bytes
    payload: bytes
    payload_length: int
    properties: AlarmProperties


@dataclass(frozen=True)
class AlarmListResult:
    raw: bytes
    slot_ids: list[int]


@dataclass(frozen=True)
class AlarmEnableResult:
    slot_id: int
    ack: bytes
    confirm: bytes


@dataclass(frozen=True)
class AlarmDeleteResult:
    slot_id: int
    command: bytes
    ack: bytes
    confirm: bytes
    ack_ok: bool
    confirm_ok: bool
