# Hue Lightstrip Control

Install `uv` and run the script with `uv run main.py`.


If you run:
```bash
uv run main.py --customize
```
an html webpage will open which will give you pretty much everything you will need, including presets, power-off, brightness control, etc... .






Examples:

```bash
uv run main.py power on
uv run main.py power off
```

## Pairing

Factory reset the lamp, then pair it using Bluetooth.

- macOS: pair from Bluetooth settings.
- Linux: pair with `bluetoothctl`.
Macos I just reset factory the light and then opened blendr and read rgb value I prompted a page to connect to it.
