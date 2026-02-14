"""Read all alarm slots and enable any that are currently inactive.

Enable protocol (on Timer UUID):
  Write:   01 <slot_lo> <slot_hi> 00 01 00 <alarm_payload_from_offset_5>
  Notify1: 01 00 <slot_lo> <slot_hi> 00   (enable ACK)
  Notify2: 04 <slot_lo> <slot_hi> 00 03 00  (enable confirmation)

The alarm payload bytes from offset 5 onward are the timestamp, fixed bytes,
mystery bytes, day mask, name, and trailer — everything after the active flag.
"""

import asyncio
from dataclasses import dataclass

from bleak import BleakClient, BleakScanner

from scripts.read_alarms import (
    NOTIFICATION_TIMEOUT,
    TIMER_UUID,
    AlarmSlot,
    format_hex,
    parse_alarm_slot,
    parse_slot_list,
)

ENABLE_COMMAND_TYPE = 0x01
ACTIVE_FLAG = bytes([0x01, 0x00])


@dataclass
class EnableResponse:
    slot_id: int
    ack: bytes
    confirm: bytes


async def enable_alarms(device_name: str, timeout: float = 20.0) -> None:
    """Connect to the lamp, read all alarm slots, and enable inactive ones."""
    dev = await BleakScanner.find_device_by_name(device_name, timeout=timeout)
    if not dev:
        raise SystemExit(f"Device '{device_name}' not found.")
    print(f"Found: {dev.name} ({dev.address})")

    notification_queue: asyncio.Queue[bytes] = asyncio.Queue()

    def on_notify(_char, data: bytearray):
        notification_queue.put_nowait(bytes(data))

    async with BleakClient(dev, timeout=timeout) as client:
        print(f"Connected: {client.is_connected}")
        await client.start_notify(TIMER_UUID, on_notify)

        # Step 1: Get slot list
        await client.write_gatt_char(TIMER_UUID, bytes([0x00]), response=True)
        response = await asyncio.wait_for(notification_queue.get(), timeout=NOTIFICATION_TIMEOUT)
        slot_ids = parse_slot_list(response)
        print(f"Found {len(slot_ids)} alarm(s): {[f'0x{s:04x}' for s in slot_ids]}")

        if not slot_ids:
            print("No alarms found.")
            await client.stop_notify(TIMER_UUID)
            return

        # Step 2: Read each slot and collect inactive ones
        slots: list[AlarmSlot] = []
        for slot_id in slot_ids:
            lo = slot_id & 0xFF
            hi = (slot_id >> 8) & 0xFF
            cmd = bytes([0x02, lo, hi, 0x00, 0x00])
            await client.write_gatt_char(TIMER_UUID, cmd, response=True)
            response = await asyncio.wait_for(
                notification_queue.get(), timeout=NOTIFICATION_TIMEOUT
            )
            slots.append(parse_alarm_slot(response))

        inactive = [s for s in slots if not s.active]
        if not inactive:
            print("All alarms are already active.")
            await client.stop_notify(TIMER_UUID)
            return

        print(f"\n{len(inactive)} inactive alarm(s) to enable:")
        for s in inactive:
            print(f"  Slot 0x{s.slot_id:04x} '{s.name}'")

        # Step 3: Enable each inactive alarm
        # The raw response is: [0x02] [0x00] [slot_id LE16] [payload_len] [0x00] [payload...]
        # Payload layout: [0: unknown] [1-2: flags] [3-4: active] [5+: rest]
        # Enable command: [0x01] [slot_lo] [slot_hi] [0x00] [active=0x01 0x00] [payload from offset 5]
        results: list[EnableResponse] = []
        for slot in inactive:
            payload = slot.raw[6:]  # strip header (type, status, slot_id LE16, payload_len, 0x00)
            rest_of_payload = payload[5:]  # skip unknown byte, flags (2), active (2)

            lo = slot.slot_id & 0xFF
            hi = (slot.slot_id >> 8) & 0xFF
            cmd = bytes([ENABLE_COMMAND_TYPE, lo, hi, 0x00]) + ACTIVE_FLAG + rest_of_payload

            print(f"\nEnabling slot 0x{slot.slot_id:04x} -> write {format_hex(cmd)}")
            await client.write_gatt_char(TIMER_UUID, cmd, response=True)

            ack = await asyncio.wait_for(notification_queue.get(), timeout=NOTIFICATION_TIMEOUT)
            print(f"  ACK:     {format_hex(ack)}")
            confirm = await asyncio.wait_for(notification_queue.get(), timeout=NOTIFICATION_TIMEOUT)
            print(f"  Confirm: {format_hex(confirm)}")

            results.append(EnableResponse(slot.slot_id, ack, confirm))

        await client.stop_notify(TIMER_UUID)

    # Summary
    print(f"\nEnabled {len(results)} alarm(s).")
    for r in results:
        print(f"  Slot 0x{r.slot_id:04x}: ack={format_hex(r.ack)} confirm={format_hex(r.confirm)}")
