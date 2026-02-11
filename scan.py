import asyncio
import binascii
from bleak import BleakClient, BleakScanner

DEVICE_NAME = "Hue lightstrip plus"
PAYLOADS = [
    b"\xfe\xff\x00\x00",  # red (full brightness)
    b"\xfe\x00\xff\x00",  # green
    b"\xfe\x00\x00\xff",  # blue
    b"\xfe\xff\xff\xff",  # white
    b"\xfe\x80\x80\x80",  # dim gray
    b"\xfe\xff\x00\xff",  # magenta
    b"\xfe\x00\xff\xff",  # cyan
    b"\xfe\xff\xff\x00",  # yellow
]

CONTROL_CHAR = "932c32bd-0005-47a2-835a-a8d455b859dd"


async def scan_and_connect():
    dev = await BleakScanner.find_device_by_name(DEVICE_NAME, timeout=20)
    print(f"\n=== FOUND: {dev.name} {dev.address} ===")
    client = BleakClient(dev)
    await client.connect(timeout=20)
    print(f"Connected: {client.is_connected}")
    return client


async def write_and_wait(client, data):
    hx = binascii.hexlify(data).decode()
    print(f"WRITE {CONTROL_CHAR} 0x{hx}")
    await client.write_gatt_char(CONTROL_CHAR, data, response=False)
    input("Press Enter to continue...")


async def main():
    client = await scan_and_connect()
    print("\n=== TESTING PAYLOADS (watch the light) ===")
    for data in PAYLOADS:
        await write_and_wait(client, data)
    print("\n=== DONE ===")
    await client.disconnect()


asyncio.run(main())
