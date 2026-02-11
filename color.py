import asyncio
import binascii
from bleak import BleakClient, BleakScanner

DEVICE_NAME = "Hue lightstrip plus"
COLOR_CHAR = "932c32bd-0005-47a2-835a-a8d455b859dd"


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
        (bytes([0xFF, 0xFF, 0xFF, 0xFF]), "read"),
        (bri_rgb(137, 146, 212, 91), "honolulu"),
        # (bri_rgb(254, 255, 0, 0), "RED"),
        # (bri_rgb(254, 0, 255, 0), "GREEN"),
        # (bri_rgb(254, 0, 0, 255), "BLUE"),
        # (bri_rgb(254, 255, 255, 255), "WHITE"),
        # (bri_rgb(254, 255, 165, 0), "ORANGE"),
        # (bri_rgb(254, 0, 255, 255), "CYAN"),
        # (bri_rgb(254, 255, 0, 255), "MAGENTA"),
        # (bri_rgb(254, 255, 255, 0), "YELLOW"),
    ]

    for color, name in colors:
        await write_and_wait(client, color, name)

    print("\n=== DONE ===")
    await client.disconnect()


asyncio.run(main())
