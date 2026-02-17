"""Hue BLE control primitives."""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from functools import wraps

from bleak import BleakClient, BleakScanner

from lib.models import Alarm, AlarmDeleteResult, AlarmEnableResult, AlarmListResult, Config
from lib.parsers import (
    check_delete_ack,
    check_delete_confirm,
    format_hex,
    parse_alarm,
    parse_alarm_ids,
)

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

log = logging.getLogger("hue-control")


class PowerStateMismatchError(RuntimeError):
    """Raised when power readback does not match desired state."""


def retry_async(
    *,
    attempts: int,
    delay_seconds: float,
    operation: str,
) -> Callable[[Callable[..., Awaitable[None]]], Callable[..., Awaitable[None]]]:
    """Retry async operations that raise exceptions."""
    if attempts < 1:
        raise ValueError("attempts must be >= 1")

    def decorator(func: Callable[..., Awaitable[None]]) -> Callable[..., Awaitable[None]]:
        @wraps(func)
        async def wrapper(*args, **kwargs) -> None:
            last_error: Exception | None = None
            for attempt in range(1, attempts + 1):
                try:
                    await func(*args, **kwargs)
                    return
                except Exception as exc:
                    last_error = exc
                    if attempt == attempts:
                        break
                    log.warning(
                        "%s failed (attempt %d/%d): %s. Retrying in %.1fs...",
                        operation,
                        attempt,
                        attempts,
                        exc,
                        delay_seconds,
                    )
                    await asyncio.sleep(delay_seconds)

            assert last_error is not None
            raise RuntimeError(f"{operation} failed after {attempts} attempts.") from last_error

        return wrapper

    return decorator


@dataclass
class HueLight:
    client: BleakClient
    name: str
    address: str
    timer_notification_queue: asyncio.Queue[bytes] = field(default_factory=asyncio.Queue)
    _timer_notifications_started: bool = field(default=False, init=False, repr=False)

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
        ins = cls(
            client=client,
            name=device.name or config.device_name,
            address=device.address,
        )
        await ins.ensure_timer_notifications_started()
        return ins

    async def disconnect(self) -> None:
        if not self.client.is_connected:
            return

        await self.stop_timer_notifications()
        await self.client.disconnect()

    def _on_timer_notification(self, _, data: bytearray) -> None:
        self.timer_notification_queue.put_nowait(bytes(data))

    async def ensure_timer_notifications_started(self) -> None:
        if self._timer_notifications_started:
            return

        await self.client.start_notify(TIMER_UUID, self._on_timer_notification)
        self._timer_notifications_started = True

    async def stop_timer_notifications(self) -> None:
        if not self._timer_notifications_started:
            return

        await self.client.stop_notify(TIMER_UUID)
        self._timer_notifications_started = False

    async def next_timer_notification(self, timeout: float = NOTIFICATION_TIMEOUT) -> bytes:
        return await asyncio.wait_for(self.timer_notification_queue.get(), timeout=timeout)

    async def write_characteristic(
        self,
        uuid: str,
        data: bytes,
        *,
        response: bool = True,
        note: str | None = None,
    ) -> None:
        suffix = f" ({note})" if note else ""
        formatted_hex = " ".join(data.hex()[i : i + 2] for i in range(0, len(data.hex()), 2))
        log.info("WRITE uuid=%s response=%s data=0x%s%s", uuid, response, formatted_hex, suffix)
        await self.client.write_gatt_char(uuid, data, response=response)
        log.info("WRITE Complete")

    async def read_power(self) -> bytes:
        readback = await self.client.read_gatt_char(POWER_UUID)
        readback_bytes = bytes(readback)
        log.info("READ uuid=%s data=0x%s", POWER_UUID, readback_bytes.hex())
        return readback_bytes

    @retry_async(attempts=20, delay_seconds=0.3, operation="Setting power")
    async def set_power(self, on: bool, brightness: int | None) -> None:
        value = bytes([brightness if brightness is not None else 0x01]) if on else bytes([0x00])
        await self.write_characteristic(POWER_UUID, value, note="power")
        readback = await self.read_power()
        if not readback:
            raise PowerStateMismatchError("Power readback was empty.")

        current_on = readback[0] != 0x00
        if current_on != on:
            desired = "on" if on else "off"
            actual = "on" if current_on else "off"
            raise PowerStateMismatchError(
                f"Power readback mismatch: expected {desired}, got {actual}."
            )

    async def set_color(self, data: bytes) -> None:
        await self.write_characteristic(COLOR_UUID, data, response=False, note="color")
        log.info("HTTP->BLE write: 0x%s", data.hex())

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

    async def list_alarm_ids(self) -> AlarmListResult:
        """Parse the slot list notification response.

        Format: [0x00=type] [status] [unknown] [count] [slot_id LE16]...
        """
        list_timers_msg = bytes([0x00])
        await self.write_characteristic(TIMER_UUID, list_timers_msg, response=True)

        data = await self.next_timer_notification()
        slot_ids = parse_alarm_ids(data)
        return AlarmListResult(raw=data, slot_ids=slot_ids)

    async def read_alarms(self) -> list[Alarm]:
        """Read and parse all alarm slots."""
        slot_result = await self.list_alarm_ids()

        slots: list[Alarm] = []
        for slot_id in slot_result.slot_ids:
            lo = slot_id & 0xFF
            hi = (slot_id >> 8) & 0xFF
            timer_info_msg = bytes([0x02, lo, hi, 0x00, 0x00])
            await self.write_characteristic(TIMER_UUID, timer_info_msg, response=True)
            response = await self.next_timer_notification()
            try:
                slot = parse_alarm(response)
            except ValueError as exc:
                print(f"  Error parsing slot {response}: {exc}")
                continue
            slots.append(slot)

        return slots

    async def enable_alarm(self, alarm: Alarm) -> AlarmEnableResult:
        msg = alarm.payload
        await self.write_characteristic(TIMER_UUID, msg, note="Enabling Alarm", response=True)

        ack = b""
        confirm = b""
        try:
            ack = await self.next_timer_notification()
            print(f"  ACK:     {format_hex(ack)}")

            confirm = await self.next_timer_notification()
            print(f"  Confirm: {format_hex(confirm)}")
        except:
            logging.exception("did not recive the notification expected")

        return AlarmEnableResult(slot_id=alarm.slot_id, ack=ack, confirm=confirm)

    async def delete_alarm(self, slot_id: int) -> AlarmDeleteResult:
        lo = slot_id & 0xFF
        hi = (slot_id >> 8) & 0xFF
        command = bytes([0x03, lo, hi])
        await self.write_characteristic(TIMER_UUID, command, response=True, note="Delete alarm")

        ack = await self.next_timer_notification()
        confirm = await self.next_timer_notification()
        ack_ok = check_delete_ack(slot_id, ack)
        confirm_ok = check_delete_confirm(slot_id, confirm)

        return AlarmDeleteResult(
            slot_id=slot_id,
            command=command,
            ack=ack,
            confirm=confirm,
            ack_ok=ack_ok,
            confirm_ok=confirm_ok,
        )
