# Hue Control Payload Decode

This is the control payload to set alarm for hue light and we are trying to code it.

## Sunrise Mode (47 Bytes Total)

Byte index 0-1: `01 FF` (etc.) write counter (you confirmed: doesn't matter).
Byte index 2-3: `FF 00` unknown (fixed in your samples).
Byte index 4-5: `01 00` active/inactive flag (you confirmed).
Byte index 6-9: `XX XX XX XX` Unix timestamp (little-endian, 32-bit) = alarm time.
Byte index 10-11: `00 09` mode = sunrise.
Byte index 12-19: `01 01 01 06...` unknown fixed bytes (possibly days-of-week, repeat settings).
Byte index 20: `5B/65/7D` fade duration (sunrise): 30min → `0x5B` (91), 20min → `0x65` (101), 10min → `0x7D` (125).
Byte index 21-22: `19 01` unknown (fixed in your samples).
Byte index 23-38: 16 bytes protected/MAC block (changes with any parameter).
Byte index 39-46: `00 FF FF FF...` separator + name metadata (you confirmed).

Example: wake up 07:00 sunrise fade in 30 min.

```
01FF FF00 0100 D8B6 8E69 0009 0101 0106 0109 0801 5B19 0194 D184 84B7 5143 DAA8 67A9 2F02 110C 8D00 FFFF FFFF 0141 01
```

## Full Brightness Mode (52 Bytes Total)

Byte index 0-1: `01 FF` (etc.) write counter.
Byte index 2-3: `FF 00` unknown.
Byte index 4-5: `01 00` active/inactive.
Byte index 6-9: `XX XX XX XX` Unix timestamp (little-endian) = alarm time.
Byte index 10-11: `00 0E` mode = full brightness.
Byte index 12-17: `01 01 01 02...` unknown fixed header.
Byte index 18-19: `01 FE` unknown.
Byte index 20-21: `03 02` unknown.
Byte index 22: `BF` unknown (fixed).
Byte index 23: `01` unknown.
Byte index 24-25: `05 02` fade parameter marker.
Byte index 26-27: `XX XX` fade duration in deciseconds (little-endian): 10min → `0x1770`, 20min → `0x2EE0`, 30min → `0x4650`.
Byte index 28-43: 16 bytes protected/MAC block.
Byte index 44-51: `00 FF FF FF...` separator + name metadata.

Example: wake up 07:00 full brightness fade in 30 min.

```
010C 0000 0100 D8B6 8E69 000E 0101 0102 01FE 0302 BF01 0502 5046 1901 2114 F58F E794 40F1 86C4 BF6A 8529 73C4 00FF FFFF FF01 4101
```
