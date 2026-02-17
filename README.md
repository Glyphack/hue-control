# Hue Lightstrip Control

Install `uv` and run the script with `uv run main.py`.

Examples:

```bash
uv run main.py customize
uv run main.py power on
uv run main.py power off
```

## Structure

- `main.py`: CLI/customize adapter and command routing.
- `lib/models.py`: dataclasses and enums for config/commands/alarms.
- `lib/parsers.py`: payload parsing/encoding and alarm response helpers.
- `lib/hue.py`: async BLE lamp control logic and protocol constants.

## Pairing

Factory reset the lamp, then pair it using Bluetooth.

- macOS: pair from Bluetooth settings.
- Linux: pair with `bluetoothctl`.
