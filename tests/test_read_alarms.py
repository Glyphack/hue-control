"""Unit tests for alarm parsing logic in scripts/read_alarms.py.

Tests use real alarm data captured from BLE device responses (alarm_dump.txt).
"""

import unittest
from datetime import UTC, datetime

from main import (
    Alarm,
    AlarmProperties,
    parse_alarm,
    parse_alarm_ids,
)


class TestParseSlotList(unittest.TestCase):
    """Tests for parse_slot_list() function."""

    def test_parse_three_slots(self):
        """Test parsing a slot list with 3 slots."""
        # Format: [type=0x00] [status=0x00] [unknown] [count] [slot_id LE16]...
        # 3 slots: 0x0019, 0x001a, 0x001b
        data = bytes([0x00, 0x00, 0x00, 0x03, 0x19, 0x00, 0x1A, 0x00, 0x1B, 0x00])
        slot_ids = parse_alarm_ids(data)

        self.assertEqual(slot_ids, [0x0019, 0x001A, 0x001B])

    def test_parse_empty_slot_list(self):
        """Test parsing an empty slot list."""
        data = bytes([0x00, 0x00, 0x00, 0x00])
        slot_ids = parse_alarm_ids(data)

        self.assertEqual(slot_ids, [])

    def test_parse_single_slot(self):
        """Test parsing a slot list with one slot."""
        data = bytes([0x00, 0x00, 0x00, 0x01, 0x42, 0x00])
        slot_ids = parse_alarm_ids(data)

        self.assertEqual(slot_ids, [0x0042])

    def test_response_too_short(self):
        """Test that too-short response raises ValueError."""
        data = bytes([0x00, 0x00])
        with self.assertRaises(ValueError) as ctx:
            parse_alarm_ids(data)
        self.assertIn("too short", str(ctx.exception))


class TestParseAlarmSlot(unittest.TestCase):
    """Tests for parse_alarm_slot() using real alarm data from alarm_dump.txt."""

    def test_parse_morning_up_alarm(self):
        """Test parsing 'Morning up' alarm (slot 0x001a) - active alarm."""
        # Real hex data from alarm_dump.txt for slot 0x001a
        hex_data = "02001a003500000000010060b29269000901010106010908017d2201d40c138d81b94a4caa42b99acec62d8800ffffffff0a4d6f726e696e6720757000"
        raw = bytes.fromhex(hex_data)

        slot = parse_alarm(raw)

        # Verify basic slot properties
        self.assertEqual(slot.slot_id, 0x001A)
        self.assertEqual(slot.payload_length, 0x35)
        self.assertEqual(len(slot.raw), len(raw))
        self.assertEqual(slot.raw, raw)

        # Verify alarm core properties
        self.assertTrue(slot.properties.active)
        # Unix timestamp 0x6992b260 = 1768127136
        expected_timestamp = datetime(2026, 2, 16, 6, 0, 0, tzinfo=UTC)
        self.assertEqual(slot.properties.timestamp, expected_timestamp)

        # Verify alarm name
        self.assertEqual(slot.properties.name, "Morning up")

        # Verify convenience property
        self.assertTrue(slot.properties.active)

    def test_parse_morning_off_alarm(self):
        """Test parsing 'Morning off' alarm (slot 0x001b) - active alarm."""
        # Real hex data from alarm_dump.txt for slot 0x001b
        hex_data = "02001b003b00000000010070c09269000e01010002010103024c020502701723011f80039c24034364b75f63bef10cea3b01ffffffff0b4d6f726e696e67206f666600"
        raw = bytes.fromhex(hex_data)

        slot = parse_alarm(raw)

        # Verify basic slot properties
        self.assertEqual(slot.slot_id, 0x001B)
        self.assertEqual(slot.payload_length, 0x3B)

        # Verify alarm core properties
        self.assertTrue(slot.properties.active)
        # Unix timestamp 0x6992c070 = 1768127600
        expected_timestamp = datetime(2026, 2, 16, 7, 0, 0, tzinfo=UTC)
        self.assertEqual(slot.properties.timestamp, expected_timestamp)

        # Verify alarm name
        self.assertEqual(slot.properties.name, "Morning off")

    def test_parse_short_name_inactive_alarm(self):
        """Test parsing alarm with short name 'T' (slot 0x0019) - inactive alarm."""
        # Real hex data from alarm_dump.txt for slot 0x0019
        hex_data = "0200190024000000000000878e91690101021901187a96a366474a73a8f10539fde09319032c010000015400"
        raw = bytes.fromhex(hex_data)

        slot = parse_alarm(raw)

        # Verify basic slot properties
        self.assertEqual(slot.slot_id, 0x0019)
        self.assertEqual(slot.payload_length, 0x24)

        # Verify alarm core properties
        self.assertFalse(slot.properties.active)
        # Unix timestamp 0x69918e87 = 1768868999
        expected_timestamp = datetime(2026, 2, 15, 9, 14, 47, tzinfo=UTC)
        self.assertEqual(slot.properties.timestamp, expected_timestamp)

        # Verify alarm name (single character)
        self.assertEqual(slot.properties.name, "T")

        # Verify convenience property
        self.assertFalse(slot.properties.active)

    def test_invalid_response_type(self):
        """Test that invalid response type raises ValueError."""
        # Use slot list response type (0x00) instead of alarm slot type (0x02)
        data = bytes([0x00, 0x00, 0x1A, 0x00, 0x35, 0x00] + [0x00] * 10)
        with self.assertRaises(ValueError) as ctx:
            parse_alarm(data)
        self.assertIn("Expected response type 0x02", str(ctx.exception))

    def test_response_too_short(self):
        """Test that too-short response raises ValueError."""
        data = bytes([0x02, 0x00, 0x1A])
        with self.assertRaises(ValueError) as ctx:
            parse_alarm(data)
        self.assertIn("too short", str(ctx.exception))

    def test_payload_length_mismatch(self):
        """Test that payload length exceeding actual payload raises ValueError."""
        # Header claims payload length 0xFF but only provides 5 bytes
        data = bytes([0x02, 0x00, 0x1A, 0x00, 0xFF, 0x00, 0x01, 0x02, 0x03, 0x04, 0x05])
        with self.assertRaises(ValueError) as ctx:
            parse_alarm(data)
        self.assertIn("payload length", str(ctx.exception).lower())


class TestAlarmSlotDataclass(unittest.TestCase):
    """Tests for AlarmSlot dataclass properties."""

    def test_active_property_delegates_to_core(self):
        """Test that AlarmSlot.active property delegates to core.active."""
        core_active = AlarmProperties(
            active=True,
            timestamp=datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC),
            mystery_bytes=b"",
            name="test",
        )
        slot_active = Alarm(
            slot_id=1,
            raw=b"",
            payload=b"",
            payload_length=0,
            properties=core_active,
        )
        self.assertTrue(slot_active.properties.active)

        core_inactive = AlarmProperties(
            active=False,
            timestamp=datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC),
            name="test",
            mystery_bytes=b"",
        )
        slot_inactive = Alarm(
            slot_id=2, raw=b"", payload=b"", payload_length=0, properties=core_inactive
        )
        self.assertFalse(slot_inactive.properties.active)


if __name__ == "__main__":
    unittest.main()
