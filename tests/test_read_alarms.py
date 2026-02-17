"""Unit tests for alarm parsing logic in lib.parsers."""

from datetime import UTC, datetime

import pytest

from huec.lib.models import Alarm
from huec.lib.parsers import (
    hex_to_bin,
    parse_alarm,
    parse_alarm_ids,
)

SLOT_LIST_RESPONSE_TYPE = 0x00
OK_STATUS = 0x00

MORNING_UP = hex_to_bin("""
02 00 2c 00 35 00 00 00 00 01 00 60 55 95 69 00
09 01 01 01 06 01 09 08 01 7d 22 01 d4 0c 13 8d
81 b9 4a 4c aa 42 b9 9a ce c6 2d 88 00 ff ff ff
ff 0a 4d 6f 72 6e 69 6e 67 20 75 70 01
""")
MORNING_OFF = hex_to_bin("""
02 00 2d 00 3b 00 00 00 00 01 00 70 63 95 69 00
0e 01 01 00 02 01 01 03 02 4c 02 05 02 70 17 23
01 1f 80 03 9c 24 03 43 64 b7 5f 63 be f1 0c ea
3b 01 ff ff ff ff 0b 4d 6f 72 6e 69 6e 67 20 6f
66 66 01
""")
INACTIVE_TIMER = hex_to_bin("")
ALARM_SLOTS_HEX = hex_to_bin("00 00 07 02 2c 00 2d 00")


def assert_alarm_details(
    alarm: Alarm,
    *,
    slot_id: int,
    payload_length: int,
    active: bool,
    timestamp: datetime,
    name: str,
) -> None:
    assert alarm._id, slot_id
    assert alarm.payload_length, payload_length
    assert alarm.properties.active, active
    assert alarm.properties.timestamp, timestamp
    assert alarm.properties.name, name


def test_parse_three_slots():
    slot_ids = parse_alarm_ids(ALARM_SLOTS_HEX)
    assert slot_ids, [0x0019, 0x001A, 0x001B]


def test_morning_up():
    alarm = parse_alarm(MORNING_UP)
    assert_alarm_details(
        alarm,
        slot_id=0x002C,
        payload_length=0x35,
        active=True,
        timestamp=datetime(2026, 2, 16, 6, 0, 0, tzinfo=UTC),
        name="Morning up",
    )


def test_parse_morning_off_alarm():
    alarm = parse_alarm(MORNING_OFF)
    assert_alarm_details(
        alarm,
        slot_id=0x001B,
        payload_length=0x3B,
        active=True,
        timestamp=datetime(2026, 2, 16, 7, 0, 0, tzinfo=UTC),
        name="Morning off",
    )


@pytest.mark.skip("implement with real data")
def test_parse_inactive_timer():
    """Parses a 5-minute timer named "T" that is inactive."""
    alarm = parse_alarm(INACTIVE_TIMER)
    assert_alarm_details(
        alarm,
        slot_id=0x0019,
        payload_length=0x24,
        active=False,
        timestamp=datetime(2026, 2, 15, 9, 14, 47, tzinfo=UTC),
        name="T",
    )
