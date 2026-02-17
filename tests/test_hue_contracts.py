"""Contract tests for HueLight result dataclasses."""

from __future__ import annotations

import unittest
from datetime import UTC, datetime
from typing import cast
from unittest.mock import AsyncMock

from bleak import BleakClient

from lib.hue import TIMER_UUID, HueLight
from lib.models import (
    Alarm,
    AlarmDeleteResult,
    AlarmEnableResult,
    AlarmListResult,
    AlarmProperties,
)


class TestHueLightContracts(unittest.IsolatedAsyncioTestCase):
    @staticmethod
    def make_light() -> tuple[HueLight, AsyncMock]:
        client_mock = AsyncMock()
        light = HueLight(client=cast(BleakClient, client_mock), name="Hue", address="00:11:22")
        light._timer_notifications_started = True
        return light, client_mock

    async def test_list_alarm_ids_returns_alarm_list_result(self):
        light, client_mock = self.make_light()
        light.timer_notification_queue.put_nowait(
            bytes([0x00, 0x00, 0x00, 0x02, 0x1A, 0x00, 0x1B, 0x00])
        )

        result = await light.list_alarm_ids()

        self.assertIsInstance(result, AlarmListResult)
        self.assertEqual(result.slot_ids, [0x001A, 0x001B])
        client_mock.write_gatt_char.assert_awaited_once_with(
            TIMER_UUID,
            bytes([0x00]),
            response=True,
        )

    async def test_enable_alarm_returns_alarm_enable_result(self):
        light, client_mock = self.make_light()
        light.timer_notification_queue.put_nowait(bytes([0x03, 0x00, 0x1A, 0x00]))
        light.timer_notification_queue.put_nowait(bytes([0x04, 0x1A, 0x00, 0xFF, 0xFF]))

        alarm = Alarm(
            slot_id=0x001A,
            raw=b"",
            payload=b"\xaa\xbb",
            payload_length=2,
            properties=AlarmProperties(
                active=False,
                timestamp=datetime(2025, 1, 1, 0, 0, 0, tzinfo=UTC),
                mystery_bytes=b"",
                name="Test",
            ),
        )

        result = await light.enable_alarm(alarm)

        self.assertIsInstance(result, AlarmEnableResult)
        self.assertEqual(result.slot_id, 0x001A)
        self.assertEqual(result.ack, bytes([0x03, 0x00, 0x1A, 0x00]))
        self.assertEqual(result.confirm, bytes([0x04, 0x1A, 0x00, 0xFF, 0xFF]))
        client_mock.write_gatt_char.assert_awaited_once_with(
            TIMER_UUID,
            b"\xaa\xbb",
            response=True,
        )

    async def test_delete_alarm_returns_alarm_delete_result(self):
        light, client_mock = self.make_light()
        light.timer_notification_queue.put_nowait(bytes([0x03, 0x00, 0x1A, 0x00]))
        light.timer_notification_queue.put_nowait(bytes([0x04, 0x1A, 0x00, 0xFF, 0xFF]))

        result = await light.delete_alarm(0x001A)

        self.assertIsInstance(result, AlarmDeleteResult)
        self.assertEqual(result.slot_id, 0x001A)
        self.assertEqual(result.command, bytes([0x03, 0x1A, 0x00]))
        self.assertTrue(result.ack_ok)
        self.assertTrue(result.confirm_ok)
        client_mock.write_gatt_char.assert_awaited_once_with(
            TIMER_UUID,
            bytes([0x03, 0x1A, 0x00]),
            response=True,
        )


if __name__ == "__main__":
    unittest.main()
