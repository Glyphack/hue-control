"""Test this sub that worked for read"""

import asyncio
from bleak import BleakClient, BleakScanner

DEVICE_NAME = "Hue lightstrip plus"
CHAR_UUID = "932c32bd-0007-47a2-835a-a8d455b859dd"

DATA = bytes([0x01, 0x01, 0x01, 0x02, 0x01, 0xFE, 0x03, 0x02, 0x5A, 0x01])


async def main():
    dev = await BleakScanner.find_device_by_name(DEVICE_NAME, timeout=20)
    print(f"\n=== FOUND: {dev.name} {dev.address} ===")
    client = BleakClient(dev)
    await client.connect(timeout=20)
    print(f"Connected: {client.is_connected}")

    print(f"WRITE {CHAR_UUID} 0x{DATA.hex()}")
    await client.write_gatt_char(CHAR_UUID, DATA, response=False)
    print("Written successfully")

    await client.disconnect()


asyncio.run(main())
