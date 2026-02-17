"""Write a hex payload to any characteristic.

Use this via the main CLI:
`main.py dev set-characteristic --device ... --characteristic ... --data ...`.
"""

import logging

from bleak import BleakClient, BleakScanner

log = logging.getLogger("huec")


async def set_characteristic(
    device_name: str,
    characteristic_uuid: str,
    data: bytes,
    timeout: float = 20.0,
) -> None:
    """Connect to a BLE device by name and write raw data to a characteristic."""
    device = await BleakScanner.find_device_by_name(device_name, timeout=timeout)
    if not device:
        raise SystemExit(f"Device '{device_name}' not found.")

    async with BleakClient(device, timeout=timeout) as client:
        await client.write_gatt_char(characteristic_uuid, data, response=False)
    log.debug(
        "set-characteristic write complete device=%s uuid=%s payload=0x%s",
        device_name,
        characteristic_uuid,
        data.hex(),
    )
