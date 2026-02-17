# Hue Control

Control Phillips Hue lights from your computer. No phone or Hue Bridge required!

## Setup

Install [uv](https://docs.astral.sh/uv/getting-started/installation/) and run the script with `uvx huec`.

Factory reset the lamp, then pair it using Bluetooth.

- Linux: pair with `bluetoothctl`. Then use `huec`
- macOS: just run the power on command once and you get a prompt to pair with the light. Pair and then after that the app can connect to your light.

Then use the cli tool to control hue light.


Make sure to pass the name of your light when controlling it.

Turn on your light with:

```bash
uvx huec --device "Hue lightstrip" power on
```

## Usage

```text
uvx huec --help
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

## Development

I tested it on my hue lightstrip and it works.
If you have another hue light and it does not work file an issue.
