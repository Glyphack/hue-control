import asyncio
import logging
import sys

from bleak import BleakClient, BleakScanner

LIGHT_NAME = "Hue lightstrip plus"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("probe")


async def main():
    if len(sys.argv) != 3:
        raise SystemExit(f"Usage: {sys.argv[0]} <uuid> <hex-value>\n  e.g. {sys.argv[0]} 932c32bd-0002-47a2-835a-a8d455b859dd 01")

    uuid = sys.argv[1]
    try:
        value = bytes.fromhex(sys.argv[2])
    except ValueError:
        raise SystemExit(f"Invalid hex value: {sys.argv[2]}")

    log.info("Scanning for '%s'...", LIGHT_NAME)
    device = await BleakScanner.find_device_by_name(LIGHT_NAME, timeout=20.0)
    if not device:
        raise SystemExit(f"Device '{LIGHT_NAME}' not found.")

    log.info("Found device: %s (%s)", device.name, device.address)

    async with BleakClient(device, timeout=20.0) as client:
        log.info("Connected=%s", client.is_connected)
        log.info("WRITE uuid=%s data=0x%s", uuid, value.hex())
        await client.write_gatt_char(uuid, value, response=False)
        log.info("Done.")


asyncio.run(main())
