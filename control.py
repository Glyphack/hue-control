# /// script
# dependencies = [
#   "bleak>=2.1.1",
# ]
# ///
import asyncio
import logging
import sys

from bleak import BleakClient, BleakScanner

LIGHT_NAME = "Hue lightstrip plus"
POWER = "932c32bd-0002-47a2-835a-a8d455b859dd"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
)
log = logging.getLogger("turn-on")


async def main():
    value = bytes([0x01])
    if len(sys.argv) > 1:
        if sys.argv[1] == "on":
            if len(sys.argv) > 2:
                try:
                    brightness = int(sys.argv[2])
                    if not 1 <= brightness <= 255:
                        raise SystemExit(
                            f"Brightness must be between 1 and 255, got {brightness}."
                        )
                    value = bytes([brightness])
                except ValueError:
                    raise SystemExit(
                        f"Invalid brightness value: {sys.argv[2]}. Must be a number 1-255."
                    )
            else:
                value = bytes([0x01])
        elif sys.argv[1] == "off":
            value = bytes([0x00])
        else:
            raise SystemExit(
                f"Invalid argument: {sys.argv[1]}. Use 'on [1-255]' or 'off'."
            )

    log.info("Scanning for '%s'...", LIGHT_NAME)
    device = await BleakScanner.find_device_by_name(LIGHT_NAME, timeout=20.0)
    if not device:
        raise SystemExit(f"Device '{LIGHT_NAME}' not found.")

    log.info("Found device: %s (%s)", device.name, device.address)

    async with BleakClient(device, timeout=20.0) as client:
        log.info("Connected=%s", client.is_connected)
        log.info("WRITE uuid=%s response=False data=0x%02x", POWER, value[0])
        await client.write_gatt_char(POWER, value, response=False)
        log.info("Done.")


asyncio.run(main())
