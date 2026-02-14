"""Read all alarm slots then delete them one by one.

Delete protocol (on Timer UUID):
  Write:   03 <lo> <hi>        (slot ID as LE16)
  Notify1: 03 00 <lo> <hi>     (delete ACK)
  Notify2: 04 <lo> <hi> FF FF  (delete confirmation)
"""

import asyncio
from dataclasses import dataclass

from bleak import BleakClient, BleakScanner

from scripts.read_alarms import (
    NOTIFICATION_TIMEOUT,
    TIMER_UUID,
    format_hex,
    parse_slot_list,
)

EXPECTED_DELETE_ACK_TYPE = 0x03
EXPECTED_DELETE_CONFIRM_TYPE = 0x04
EXPECTED_CONFIRM_TRAILER = bytes([0xFF, 0xFF])


@dataclass
class DeleteResponse:
    slot_id: int
    ack: bytes
    confirm: bytes
    ack_ok: bool
    confirm_ok: bool


def check_delete_ack(slot_id: int, data: bytes) -> bool:
    """Check if delete ACK matches expected: 03 00 <lo> <hi>."""
    lo = slot_id & 0xFF
    hi = (slot_id >> 8) & 0xFF
    expected = bytes([EXPECTED_DELETE_ACK_TYPE, 0x00, lo, hi])
    return data == expected


def check_delete_confirm(slot_id: int, data: bytes) -> bool:
    """Check if delete confirmation matches expected: 04 <lo> <hi> FF FF."""
    lo = slot_id & 0xFF
    hi = (slot_id >> 8) & 0xFF
    expected = bytes([EXPECTED_DELETE_CONFIRM_TYPE, lo, hi]) + EXPECTED_CONFIRM_TRAILER
    return data == expected


async def delete_alarms(device_name: str, timeout: float = 20.0) -> None:
    """Connect to the lamp, read all alarm slot IDs, and delete each one."""
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

        # Read slot list
        await client.write_gatt_char(TIMER_UUID, bytes([0x00]), response=True)
        response = await asyncio.wait_for(notification_queue.get(), timeout=NOTIFICATION_TIMEOUT)
        slot_ids = parse_slot_list(response)
        print(f"Found {len(slot_ids)} alarm(s): {[f'0x{s:04x}' for s in slot_ids]}")

        if not slot_ids:
            print("Nothing to delete.")
            await client.stop_notify(TIMER_UUID)
            return

        # Delete each slot
        results: list[DeleteResponse] = []
        for slot_id in slot_ids:
            lo = slot_id & 0xFF
            hi = (slot_id >> 8) & 0xFF
            cmd = bytes([0x03, lo, hi])
            print(f"\nDeleting slot 0x{slot_id:04x} -> write {format_hex(cmd)}")
            await client.write_gatt_char(TIMER_UUID, cmd, response=True)

            ack = await asyncio.wait_for(notification_queue.get(), timeout=NOTIFICATION_TIMEOUT)
            confirm = await asyncio.wait_for(notification_queue.get(), timeout=NOTIFICATION_TIMEOUT)
            ack_ok = check_delete_ack(slot_id, ack)
            confirm_ok = check_delete_confirm(slot_id, confirm)
            results.append(DeleteResponse(slot_id, ack, confirm, ack_ok, confirm_ok))

            print(f"  ACK:     {format_hex(ack)}  {'OK' if ack_ok else 'UNEXPECTED'}")
            print(f"  Confirm: {format_hex(confirm)}  {'OK' if confirm_ok else 'UNEXPECTED'}")

            if not ack_ok:
                expected_ack = bytes([0x03, 0x00, lo, hi])
                print(f"  Expected ACK:     {format_hex(expected_ack)}")
            if not confirm_ok:
                expected_conf = bytes([0x04, lo, hi]) + EXPECTED_CONFIRM_TRAILER
                print(f"  Expected Confirm: {format_hex(expected_conf)}")

        await client.stop_notify(TIMER_UUID)

    # Summary
    all_ok = all(r.ack_ok and r.confirm_ok for r in results)
    print(f"\nDeleted {len(results)} alarm(s). All responses matched expected: {all_ok}")
    if not all_ok:
        print("UNEXPECTED RESPONSES:")
        for r in results:
            if not r.ack_ok or not r.confirm_ok:
                ack_hex = format_hex(r.ack)
                conf_hex = format_hex(r.confirm)
                print(f"  Slot 0x{r.slot_id:04x}: ack={ack_hex} confirm={conf_hex}")
