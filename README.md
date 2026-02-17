# Hue Control

Control Phillips Hue lights from your computer. No phone or Hue Bridge required!

## Setup

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and run the script with `uv run main.py`.

Factory reset the lamp, then pair it using Bluetooth.

- macOS: pair from Bluetooth settings.
- Linux: pair with `bluetoothctl`.

Then use the cli tool to control hue light.


Make sure to pass the name of your light when controlling it.

Turn on your light with:

```bash
uv run main.py --device "Hue lightstrip" power on
```

## Usage

```text
uv run main.py --help
usage: main.py [-h] [--debug] [-d DEVICE] [--timeout TIMEOUT]
               {interactive,power,color,alarms,dev} ...

Control Hue lightstrip over BLE.

positional arguments:
  {interactive,power,color,alarms,dev}
    interactive         Start HTTP server and keep BLE connection open.
    power               Turn the light on or off.
    color               Control color and brightness
    alarms              Control alarms(routines) to turn the light on/off
                        automatically.
    dev                 Developer utilities.

options:
  -h, --help            show this help message and exit
  --debug               Enable debug logging for BLE requests, responses, and
                        validation steps.
  -d, --device DEVICE   BLE device name. Default is Hue lightstrip plus
  --timeout TIMEOUT     BLE scan timeout.
```
