"""Connect to the light, subscribe to all notifiable characteristics, and print values."""

import asyncio

from bleak import BleakClient, BleakScanner


def notification_handler(char, data: bytearray):
    print(f"NOTIFY [{char.uuid}] 0x{data.hex()}")


async def subscribe_all(device_name: str, timeout: float = 20.0) -> None:
    dev = await BleakScanner.find_device_by_name(device_name, timeout=timeout)
    if not dev:
        raise SystemExit(f"Device '{device_name}' not found.")
    print(f"\n=== FOUND: {dev.name} {dev.address} ===")

    async with BleakClient(dev, timeout=timeout) as client:
        print(f"Connected: {client.is_connected}\n")

        subscribed = []
        for service in client.services:
            for char in service.characteristics:
                if "notify" in char.properties or "indicate" in char.properties:
                    try:
                        await client.start_notify(char, notification_handler)
                        subscribed.append(char)
                        print(
                            "Subscribed: {uuid}  [{desc}]  properties={props}".format(
                                uuid=char.uuid,
                                desc=char.description or "?",
                                props=char.properties,
                            )
                        )
                    except Exception as exc:
                        print(f"Failed to subscribe {char.uuid}: {exc}")

        if not subscribed:
            print("No notifiable characteristics found.")
            return

        print(f"\nListening on {len(subscribed)} characteristic(s)... (Ctrl+C to stop)\n")
        try:
            await asyncio.Event().wait()
        except KeyboardInterrupt:
            pass


def run_subscribe_all(device_name: str, timeout: float = 20.0) -> None:
    asyncio.run(subscribe_all(device_name, timeout=timeout))
