# Similar to color.py but uses characteristic 0007 instead of 0005 to set the light color.
import asyncio
import binascii
from bleak import BleakClient, BleakScanner

DEVICE_NAME = "Hue lightstrip plus"
COLOR_CHAR = "932c32bd-0007-47a2-835a-a8d455b859dd"


def bri_rgb(bri: int, r: int, g: int, b: int) -> bytes:
    return bytes([bri, r, g, b])


async def scan_and_connect():
    dev = await BleakScanner.find_device_by_name(DEVICE_NAME, timeout=20)
    print(f"\n=== FOUND: {dev.name} {dev.address} ===")
    client = BleakClient(dev)
    await client.connect(timeout=20)
    print(f"Connected: {client.is_connected}")
    return client


async def write_and_wait(client, data, name: str):
    hx = binascii.hexlify(data).decode()
    print(f"WRITE {COLOR_CHAR} 0x{hx} ({name})")
    await client.write_gatt_char(COLOR_CHAR, data, response=False)
    input("Press Enter to continue...")


async def main():
    client = await scan_and_connect()
    print("\n=== FIXED COLORS (bri,R,G,B) ===")

    colors = [
        (bytes([0x01, 0x01, 0x01, 0x02, 0x01, 0xFE, 0x03, 0x02, 0x5A, 0x01]), "read"),
        (
            bytes([0x01, 0x01, 0x01, 0x02, 0x01, 0x5C, 0x04, 0xBB, 0x73, 0x74, 0x74]),
            "honolulu",
        ),
    ]

    for color, name in colors:
        await write_and_wait(client, color, name)

    print("\n=== DONE ===")
    await client.disconnect()


asyncio.run(main())
