"""Connect to the lamp, read all alarm slots via the Timer characteristic, and print a report.

Protocol: write-then-notification pattern on Timer UUID 9da2ddf1-0001-44d0-909c-3f3d3cb34a7b.
  1. Subscribe to notifications
  2. Write 0x00 to get slot list
  3. Write 02 <lo> <hi> 00 00 for each slot to get alarm data
  4. Parse and print results
"""

import asyncio
import struct
from dataclasses import dataclass, field
from datetime import UTC, datetime

from bleak import BleakClient, BleakScanner

TIMER_UUID = "9da2ddf1-0001-44d0-909c-3f3d3cb34a7b"
NOTIFICATION_TIMEOUT = 10.0


@dataclass
class AlarmSlot:
    slot_id: int
    raw: bytes
    payload_length: int
    active: bool
    timestamp: int
    time_str: str
    mystery_bytes: bytes
    name: str
    day_mask: bytes = field(default_factory=bytes)


def parse_slot_list(data: bytes) -> list[int]:
    """Parse the slot list notification response.

    Format: [0x00=type] [status] [unknown] [count] [slot_id LE16]...
    """
    if len(data) < 4:
        raise ValueError(f"Slot list response too short: {len(data)} bytes")
    if data[0] != 0x00:
        raise ValueError(f"Expected response type 0x00 for slot list, got 0x{data[0]:02x}")
    if data[1] != 0x00:
        raise ValueError(f"Slot list status not OK: 0x{data[1]:02x}")

    count = data[3]
    slot_ids = []
    for i in range(count):
        offset = 4 + i * 2
        if offset + 2 > len(data):
            break
        slot_ids.append(struct.unpack_from("<H", data, offset)[0])
    return slot_ids


def parse_alarm_slot(data: bytes) -> AlarmSlot:
    """Parse an individual alarm slot notification response.

    Format: [0x02=type] [status] [slot_id LE16] [payload_len] [0x00]
            [payload: flags, active, timestamp LE32, mystery bytes, day mask, name, trailer]
    """
    if len(data) < 6:
        raise ValueError(f"Alarm slot response too short: {len(data)} bytes")
    if data[0] != 0x02:
        raise ValueError(f"Expected response type 0x02, got 0x{data[0]:02x}")
    if data[1] != 0x00:
        raise ValueError(f"Alarm slot status not OK: 0x{data[1]:02x}")

    slot_id = struct.unpack_from("<H", data, 2)[0]
    payload_length = data[4]
    payload = data[6:]

    # Payload offsets (verified against actual lamp data):
    #   0:     unknown byte
    #   1-2:   edit/create flags (2 bytes)
    #   3-4:   active flag (LE16: 0x0100=active, 0x0000=inactive)
    #   5-8:   Unix timestamp (LE32)
    #   9-18:  10 fixed bytes (00 09 01 01 01 06 01 09 08 01)
    #   19-37: 19 mystery bytes
    #   38:    unknown byte (varies: 00, 01, ff)
    #   39-42: day mask (4 bytes, e.g. FF FF FF FF)
    #   43:    name length
    #   44+:   name (ASCII, name_length bytes)
    #   last:  trailer (01)

    active = False
    timestamp = 0
    time_str = "?"
    mystery_bytes = b""
    name = ""
    day_mask = b""

    if len(payload) >= 5:
        active_val = struct.unpack_from("<H", payload, 3)[0]
        active = active_val != 0

    if len(payload) >= 9:
        timestamp = struct.unpack_from("<I", payload, 5)[0]
        try:
            time_str = datetime.fromtimestamp(timestamp, tz=UTC).strftime("%Y-%m-%d %H:%M:%S UTC")
        except (OSError, ValueError):
            time_str = f"invalid ({timestamp})"

    if len(payload) >= 38:
        mystery_bytes = payload[19:38]

    if len(payload) >= 43:
        day_mask = payload[39:43]

    if len(payload) >= 44:
        name_len = payload[43]
        if len(payload) >= 44 + name_len:
            try:
                name = payload[44 : 44 + name_len].decode("ascii")
            except UnicodeDecodeError:
                name = f"<hex:{payload[44 : 44 + name_len].hex()}>"

    return AlarmSlot(
        slot_id=slot_id,
        raw=data,
        payload_length=payload_length,
        active=active,
        timestamp=timestamp,
        time_str=time_str,
        mystery_bytes=mystery_bytes,
        name=name,
        day_mask=day_mask,
    )


def format_hex(data: bytes) -> str:
    return " ".join(f"{b:02x}" for b in data)


def print_alarm_report(slots: list[AlarmSlot]) -> None:
    print("\n" + "=" * 70)
    print("ALARM DUMP REPORT")
    print("=" * 70)

    for slot in slots:
        print(f"\n--- Slot 0x{slot.slot_id:04x} ({slot.slot_id}) ---")
        print(f"  Raw hex ({len(slot.raw)} bytes):")
        print(f"    {format_hex(slot.raw)}")
        print(f"  Payload length: {slot.payload_length}")
        print(f"  Active:         {slot.active}")
        print(f"  Timestamp:      {slot.timestamp} ({slot.time_str})")
        print(f"  Name:           '{slot.name}'")
        print(f"  Day mask:       {format_hex(slot.day_mask)}")
        print(f"  Mystery bytes:  {format_hex(slot.mystery_bytes)}")

    print("\n" + "=" * 70)
    print("SUMMARY")
    print("=" * 70)
    print(f"{'Slot':>8}  {'Active':>6}  {'Name':<20}  {'Timestamp':<26}  Mystery (hex)")
    print("-" * 100)
    for slot in slots:
        print(
            f"  0x{slot.slot_id:04x}  {'  YES' if slot.active else '   NO':>6}"
            f"  {slot.name:<20}  {slot.time_str:<26}  {format_hex(slot.mystery_bytes)}"
        )
    print()


def save_raw_dump(slots: list[AlarmSlot], path: str = "alarm_dump.txt") -> None:
    with open(path, "w") as f:
        for slot in slots:
            f.write(f"slot=0x{slot.slot_id:04x} raw={slot.raw.hex()}\n")
    print(f"Raw hex saved to {path}")


async def read_alarms(device_name: str, timeout: float = 20.0) -> list[AlarmSlot]:
    """Connect to the lamp, read all alarm slots, and return parsed data."""
    dev = await BleakScanner.find_device_by_name(device_name, timeout=timeout)
    if not dev:
        raise SystemExit(f"Device '{device_name}' not found.")
    print(f"Found: {dev.name} ({dev.address})")

    notification_queue: asyncio.Queue[bytes] = asyncio.Queue()

    def on_notify(_char, data: bytearray):
        notification_queue.put_nowait(bytes(data))

    async with BleakClient(dev, timeout=timeout) as client:
        print(f"Connected: {client.is_connected}")

        # Step 1: Subscribe to Timer notifications
        await client.start_notify(TIMER_UUID, on_notify)
        print(f"Subscribed to Timer ({TIMER_UUID})")

        # Step 2: Request slot list
        print("\nRequesting alarm slot list...")
        await client.write_gatt_char(TIMER_UUID, bytes([0x00]), response=True)
        response = await asyncio.wait_for(notification_queue.get(), timeout=NOTIFICATION_TIMEOUT)
        print(f"  Slot list response: {format_hex(response)}")
        slot_ids = parse_slot_list(response)
        print(f"  Found {len(slot_ids)} slot(s): {[f'0x{s:04x}' for s in slot_ids]}")

        # Step 3: Query each slot
        slots: list[AlarmSlot] = []
        for slot_id in slot_ids:
            lo = slot_id & 0xFF
            hi = (slot_id >> 8) & 0xFF
            cmd = bytes([0x02, lo, hi, 0x00, 0x00])
            print(f"\n  Querying slot 0x{slot_id:04x} -> write {format_hex(cmd)}")
            await client.write_gatt_char(TIMER_UUID, cmd, response=True)
            response = await asyncio.wait_for(
                notification_queue.get(), timeout=NOTIFICATION_TIMEOUT
            )
            print(f"  Response ({len(response)} bytes): {format_hex(response)}")
            slot = parse_alarm_slot(response)
            slots.append(slot)

        # Step 4: Unsubscribe
        await client.stop_notify(TIMER_UUID)

    # Report
    print_alarm_report(slots)
    save_raw_dump(slots)
    return slots
