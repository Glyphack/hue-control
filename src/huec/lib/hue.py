"""Hue BLE control primitives."""

from __future__ import annotations

import asyncio
import logging
import sys
from collections.abc import Awaitable, Callable, Coroutine
from dataclasses import dataclass, field
from functools import wraps
from typing import Any

from bleak import BleakClient, BleakScanner
from bleak.exc import BleakError

from huec.lib.models import (
    Alarm,
    AlarmDeleteResult,
    AlarmEnableResult,
    AlarmListResult,
    Config,
)
from huec.lib.parsers import (
    bin_to_hex,
    build_disable_alarm_command,
    build_enable_alarm_command,
    check_delete_ack,
    check_delete_confirm,
    parse_alarm,
    parse_alarm_ids,
)

DEFAULT_DEVICE_NAME = "Hue lightstrip plus"
POWER_UUID = "932c32bd-0002-47a2-835a-a8d455b859dd"
COLOR_UUID = "932c32bd-0007-47a2-835a-a8d455b859dd"
RGB_UUID = "932c32bd-0005-47a2-835a-a8d455b859dd"
TIMER_UUID = "9da2ddf1-0001-44d0-909c-3f3d3cb34a7b"
TIME_FORMAT = "%Y-%m-%d %H:%M"
NOTIFICATION_TIMEOUT = 10.0

log = logging.getLogger("huec")


class PowerStateMismatchError(RuntimeError):
    """Raised when power readback does not match desired state."""


def retry_async(
    *,
    attempts: int,
    delay_seconds: float,
    operation: str,
) -> Callable[[Callable[..., Awaitable[None]]], Callable[..., Coroutine[Any, Any, None]]]:
    """Retry async operations that raise exceptions."""
    if attempts < 1:
        raise ValueError("attempts must be >= 1")

    def decorator(
        func: Callable[..., Awaitable[None]],
    ) -> Callable[..., Coroutine[Any, Any, None]]:
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
        log.debug("Scanning for '%s'...", config.device_name)
        device = await BleakScanner.find_device_by_name(config.device_name, timeout=config.timeout)
        if not device:
            raise SystemExit(f"Device '{config.device_name}' not found.")

        log.debug("Found device: %s (%s)", device.name, device.address)
        client = BleakClient(device, timeout=config.timeout)
        await client.connect(timeout=config.timeout)
        log.debug("Connected=%s", client.is_connected)
        ins = cls(
            client=client,
            name=device.name or config.device_name,
            address=device.address,
        )
        await ins.ensure_timer_notifications_started()
        return ins

    async def reconnect(self) -> None:
        """Re-establish the BLE connection after it has gone stale."""
        log.info("Reconnecting to %s (%s)...", self.name, self.address)
        try:
            await self.client.disconnect()
        except Exception:
            pass
        self._timer_notifications_started = False
        self.client = BleakClient(self.address)
        await self.client.connect()
        await self.ensure_timer_notifications_started()
        log.info("Reconnected successfully.")

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
        resp = await asyncio.wait_for(self.timer_notification_queue.get(), timeout=timeout)
        log.debug("Alarm notification: %s", bin_to_hex(resp))
        return resp

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
        log.debug("WRITE uuid=%s response=%s data=0x%s%s", uuid, response, formatted_hex, suffix)
        try:
            await self.client.write_gatt_char(uuid, data, response=response)
        except BleakError as exc:
            log.warning("BLE write failed (%s), reconnecting...", exc)
            await self.reconnect()
            await self.client.write_gatt_char(uuid, data, response=response)
        log.debug("WRITE complete uuid=%s", uuid)

    async def read_characteristic(self, uuid: str) -> bytes:
        try:
            readback = await self.client.read_gatt_char(uuid)
        except BleakError as exc:
            log.warning("BLE read failed (%s), reconnecting...", exc)
            await self.reconnect()
            readback = await self.client.read_gatt_char(uuid)
        readback_bytes = bytes(readback)
        log.debug("READ uuid=%s data=0x%s", uuid, readback_bytes.hex())
        return readback_bytes

    async def read_power(self) -> bytes:
        return await self.read_characteristic(POWER_UUID)

    async def read_color(self) -> bytes:
        return await self.read_characteristic(COLOR_UUID)

    @retry_async(attempts=20, delay_seconds=0.3, operation="Setting power")
    async def set_power(self, on: bool) -> None:
        value = bytes([0x01]) if on else bytes([0x00])
        await self.write_characteristic(POWER_UUID, value, note="power")
        readback = await self.read_power()
        if not readback:
            raise PowerStateMismatchError("Power readback was empty.")

        current_on = readback[0] != 0x00
        log.debug(
            "Power validation desired=%s actual=%s readback=%s",
            on,
            current_on,
            bin_to_hex(readback),
        )
        if current_on != on:
            desired = "on" if on else "off"
            actual = "on" if current_on else "off"
            raise PowerStateMismatchError(
                f"Power readback mismatch: expected {desired}, got {actual}."
            )

    async def set_color(self, data: bytes) -> None:
        await self.write_characteristic(COLOR_UUID, data, response=False, note="color")
        log.debug("HTTP->BLE write payload=0x%s", data.hex())

    async def set_alarm(self, data: bytes, note: str | None = None) -> None:
        suffix = f" ({note})" if note else ""
        formatted_hex = " ".join(data.hex()[i : i + 4] for i in range(0, len(data.hex()), 4))
        log.debug(
            "WRITE uuid=%s response=False data=0x%s%s",
            TIMER_UUID,
            data.hex(),
            suffix,
        )
        log.debug("Formatted alarm payload: %s", formatted_hex)
        # TODO: This does not work so disabled
        # await self.client.write_gatt_char(TIMER_UUID, data, response=False)

    async def get_alarm_ids(self) -> AlarmListResult:
        """Parse the slot list notification response.

        Format: [0x00=type] [status] [unknown] [count] [slot_id LE16]...
        """
        list_timers_msg = bytes([0x00])
        await self.write_characteristic(TIMER_UUID, list_timers_msg, response=True)

        data = await self.next_timer_notification()
        slot_ids = parse_alarm_ids(data)
        return AlarmListResult(raw=data, slot_ids=slot_ids)

    async def get_alarms(self) -> list[Alarm]:
        """Read and parse all alarm slots."""
        slot_result = await self.get_alarm_ids()

        slots: list[Alarm] = []
        for slot_id in slot_result.slot_ids:
            try:
                slot = await self.get_alarm(slot_id)
            except ValueError as exc:
                print(f"Error parsing slot 0x{slot_id:04x}: {exc}", file=sys.stderr)
                continue
            slots.append(slot)

        return slots

    async def get_alarm(self, slot_id: int) -> Alarm:
        lo = slot_id & 0xFF
        hi = (slot_id >> 8) & 0xFF
        timer_info_msg = bytes([0x02, lo, hi, 0x00, 0x00])
        await self.write_characteristic(TIMER_UUID, timer_info_msg, response=True)
        response = await self.next_timer_notification()
        return parse_alarm(response)

    async def _send_alarm_command(
        self,
        alarm: Alarm,
        msg: bytes,
        *,
        note: str,
    ) -> AlarmEnableResult:
        await self.write_characteristic(TIMER_UUID, msg, note=note, response=False)

        ack = b""
        ack_ok = False
        confirm = b""
        confirm_ok = False
        try:
            ack = await self.next_timer_notification()
            if len(ack) >= 2 and ack[0] == 0x01 and ack[1] == 0x00:
                ack_ok = True
        except TimeoutError:
            ack_ok = False

        try:
            confirm = await self.next_timer_notification()
            confirm_ok = True
            # TODO: Validate confirm
        except TimeoutError:
            confirm_ok = False

        return AlarmEnableResult(
            slot_id=alarm._id, ack=ack, ack_ok=ack_ok, confirm=confirm, confirm_ok=confirm_ok
        )

    async def enable_alarm(self, alarm: Alarm) -> AlarmEnableResult:
        msg = build_enable_alarm_command(alarm)
        return await self._send_alarm_command(alarm, msg, note="Enabling timer")

    async def disable_alarm(self, alarm: Alarm) -> AlarmEnableResult:
        msg = build_disable_alarm_command(alarm)
        return await self._send_alarm_command(alarm, msg, note="Disabling Alarm")

    async def delete_alarm(self, a_id: int) -> AlarmDeleteResult:
        lo = a_id & 0xFF
        hi = (a_id >> 8) & 0xFF
        command = bytes([0x03, lo, hi])
        await self.write_characteristic(TIMER_UUID, command, response=True, note="Delete alarm")

        ack = await self.next_timer_notification()
        confirm = await self.next_timer_notification()
        ack_ok = check_delete_ack(a_id, ack)
        confirm_ok = check_delete_confirm(a_id, confirm)
        log.debug(
            "Delete validation slot=0x%04x ack_ok=%s confirm_ok=%s ack=%s confirm=%s",
            a_id,
            ack_ok,
            confirm_ok,
            bin_to_hex(ack),
            bin_to_hex(confirm),
        )
        r = AlarmDeleteResult(
            slot_id=a_id,
            command=command,
            ack=ack,
            confirm=confirm,
            ack_ok=ack_ok,
            confirm_ok=confirm_ok,
        )

        return r
