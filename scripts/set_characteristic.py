"""Write a hex payload to any characteristic.

Use this via the main CLI:
`main.py dev set-characteristic --device ... --characteristic ... --data ...`.
"""

from bleak import BleakClient, BleakScanner


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

    print(f"Wrote 0x{data.hex()} to {characteristic_uuid} ({device_name}).")
