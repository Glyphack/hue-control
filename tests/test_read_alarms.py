"""Unit tests for alarm parsing logic in main.py."""

import unittest
from datetime import UTC, datetime

from main import Alarm, AlarmProperties, parse_alarm, parse_alarm_ids

SLOT_LIST_RESPONSE_TYPE = 0x00
OK_STATUS = 0x00

# Real responses captured in alarm_dump.txt.
# Format: [type=0x02] [status=0x00] [slot_id LE16] [payload_len] [2 unknown bytes] [payload...]
MORNING_UP_HEX = (
    "02001a003500000000010060b29269000901010106010908017d2201d40c138d81b94a4caa42"
    "b99acec62d8800ffffffff0a4d6f726e696e6720757000"
)
# Active wakeup alarm in slot 0x001B.
MORNING_OFF_HEX = (
    "02001b003b00000000010070c09269000e01010002010103024c020502701723011f80039c2403"
    "4364b75f63bef10cea3b01ffffffff0b4d6f726e696e67206f666600"
)
# Inactive 5-minute timer in slot 0x0019 named "T".
INACTIVE_TIMER_HEX = (
    "0200190024000000000000878e91690101021901187a96a366474a73a8f10539fde09319032c010000015400"
)


def make_slot_list_response(slot_ids: list[int]) -> bytes:
    response = bytearray([SLOT_LIST_RESPONSE_TYPE, OK_STATUS, 0x00, len(slot_ids)])
    for slot_id in slot_ids:
        response.extend(slot_id.to_bytes(2, "little"))
    return bytes(response)


def parse_alarm_hex(hex_data: str) -> Alarm:
    return parse_alarm(bytes.fromhex(hex_data))


class TestParseAlarmIds(unittest.TestCase):
    """Tests for parse_alarm_ids()."""

    def test_parse_three_slots(self):
        slot_ids = parse_alarm_ids(make_slot_list_response([0x0019, 0x001A, 0x001B]))
        self.assertEqual(slot_ids, [0x0019, 0x001A, 0x001B])

    def test_parse_empty_slot_list(self):
        slot_ids = parse_alarm_ids(make_slot_list_response([]))
        self.assertEqual(slot_ids, [])

    def test_parse_single_slot(self):
        slot_ids = parse_alarm_ids(make_slot_list_response([0x0042]))
        self.assertEqual(slot_ids, [0x0042])

    def test_response_too_short(self):
        data = bytes([SLOT_LIST_RESPONSE_TYPE, OK_STATUS])
        with self.assertRaises(ValueError) as ctx:
            parse_alarm_ids(data)
        self.assertIn("too short", str(ctx.exception))


class TestParseAlarm(unittest.TestCase):
    """Tests for parse_alarm() using real alarm payloads."""

    def assert_alarm_details(
        self,
        alarm: Alarm,
        *,
        slot_id: int,
        payload_length: int,
        active: bool,
        timestamp: datetime,
        name: str,
    ) -> None:
        self.assertEqual(alarm.slot_id, slot_id)
        self.assertEqual(alarm.payload_length, payload_length)
        self.assertEqual(alarm.properties.active, active)
        self.assertEqual(alarm.properties.timestamp, timestamp)
        self.assertEqual(alarm.properties.name, name)

    def test_parse_morning_up_alarm(self):
        alarm = parse_alarm_hex(MORNING_UP_HEX)
        self.assert_alarm_details(
            alarm,
            slot_id=0x001A,
            payload_length=0x35,
            active=True,
            timestamp=datetime(2026, 2, 16, 6, 0, 0, tzinfo=UTC),
            name="Morning up",
        )

    def test_parse_morning_off_alarm(self):
        alarm = parse_alarm_hex(MORNING_OFF_HEX)
        self.assert_alarm_details(
            alarm,
            slot_id=0x001B,
            payload_length=0x3B,
            active=True,
            timestamp=datetime(2026, 2, 16, 7, 0, 0, tzinfo=UTC),
            name="Morning off",
        )

    def test_parse_inactive_timer(self):
        """Parses a 5-minute timer named "T" that is inactive."""
        alarm = parse_alarm_hex(INACTIVE_TIMER_HEX)
        self.assert_alarm_details(
            alarm,
            slot_id=0x0019,
            payload_length=0x24,
            active=False,
            timestamp=datetime(2026, 2, 15, 9, 14, 47, tzinfo=UTC),
            name="T",
        )

    def test_invalid_response_type(self):
        data = bytes([SLOT_LIST_RESPONSE_TYPE, OK_STATUS, 0x1A, 0x00, 0x35, 0x00] + [0x00] * 10)
        with self.assertRaises(ValueError) as ctx:
            parse_alarm(data)
        self.assertIn("Expected response type 0x02", str(ctx.exception))

    def test_response_too_short(self):
        data = bytes([0x02, OK_STATUS, 0x1A])
        with self.assertRaises(ValueError) as ctx:
            parse_alarm(data)
        self.assertIn("too short", str(ctx.exception))


class TestAlarmDataclass(unittest.TestCase):
    """Tests for the Alarm dataclass."""

    def test_properties_active_flag_roundtrip(self):
        active_properties = AlarmProperties(
            active=True,
            timestamp=datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC),
            mystery_bytes=b"",
            name="test",
        )
        active_alarm = Alarm(
            slot_id=1,
            raw=b"",
            payload=b"",
            payload_length=0,
            properties=active_properties,
        )
        self.assertTrue(active_alarm.properties.active)

        inactive_properties = AlarmProperties(
            active=False,
            timestamp=datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC),
            mystery_bytes=b"",
            name="test",
        )
        inactive_alarm = Alarm(
            slot_id=2,
            raw=b"",
            payload=b"",
            payload_length=0,
            properties=inactive_properties,
        )
        self.assertFalse(inactive_alarm.properties.active)


if __name__ == "__main__":
    unittest.main()
