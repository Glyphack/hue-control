"""Unit tests for data models in lib.models."""

import unittest
from datetime import UTC, datetime

from lib.models import (
    Alarm,
    AlarmDeleteResult,
    AlarmEnableResult,
    AlarmListResult,
    AlarmProperties,
    Config,
)


class TestConfigDataclass(unittest.TestCase):
    def test_config_fields(self):
        config = Config(device_name="Hue lightstrip plus", timeout=15.0)
        self.assertEqual(config.device_name, "Hue lightstrip plus")
        self.assertEqual(config.timeout, 15.0)


class TestAlarmOperationDataclasses(unittest.TestCase):
    def test_alarm_list_result_roundtrip(self):
        result = AlarmListResult(raw=b"\x00\x00\x00\x01\x1a\x00", slot_ids=[0x001A])
        self.assertEqual(result.raw, b"\x00\x00\x00\x01\x1a\x00")
        self.assertEqual(result.slot_ids, [0x001A])

    def test_alarm_enable_result_roundtrip(self):
        result = AlarmEnableResult(slot_id=0x001A, ack=b"\x03\x00\x1a\x00", confirm=b"\x04")
        self.assertEqual(result.slot_id, 0x001A)
        self.assertEqual(result.ack, b"\x03\x00\x1a\x00")
        self.assertEqual(result.confirm, b"\x04")

    def test_alarm_delete_result_roundtrip(self):
        result = AlarmDeleteResult(
            slot_id=0x001A,
            command=b"\x03\x1a\x00",
            ack=b"\x03\x00\x1a\x00",
            confirm=b"\x04\x1a\x00\xff\xff",
            ack_ok=True,
            confirm_ok=True,
        )
        self.assertEqual(result.slot_id, 0x001A)
        self.assertEqual(result.command, b"\x03\x1a\x00")
        self.assertTrue(result.ack_ok)
        self.assertTrue(result.confirm_ok)


class TestAlarmDataclass(unittest.TestCase):
    def test_alarm_properties_and_alarm_data(self):
        properties = AlarmProperties(
            active=True,
            timestamp=datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC),
            mystery_bytes=b"\x01\x02",
            name="Alarm",
        )
        alarm = Alarm(
            slot_id=0x001A,
            raw=b"\x02\x00",
            payload=b"\x10\x20",
            payload_length=2,
            properties=properties,
        )
        self.assertEqual(alarm.slot_id, 0x001A)
        self.assertEqual(alarm.properties.name, "Alarm")
        self.assertEqual(alarm.payload_length, 2)


if __name__ == "__main__":
    unittest.main()
