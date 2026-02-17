from datetime import datetime
from types import SimpleNamespace

from huec.lib.parsers import bin_to_hex, build_enable_alarm_command, hex_to_bin, parse_alarm

TIMER_DISABLED = hex_to_bin("""
02 00 38 00 28 00 00 00 00 00 01 b9 ba 94 69 01
01 02 1d 01 50 c1 53 49 69 60 40 b1 b3 38 46 6b
c3 bb 42 58 03 2c 01 00 00 05 54 69 6d 65 72 01
""")


def test_enable_timer(monkeypatch):
    a = parse_alarm(TIMER_DISABLED)
    monkeypatch.setattr(
        "huec.lib.parsers.datetime",
        SimpleNamespace(now=lambda tz=None: datetime.fromisoformat("2026-02-17T20:00:00+00:00")),
    )
    msg = build_enable_alarm_command(a)
    assert (
        bin_to_hex(msg).split()
        == """
01 38 00 00 01 01 ec c9 94 69 01 01 02 1d 01 50
c1 53 49 69 60 40 b1 b3 38 46 6b c3 bb 42 58 03
2c 01 00 00 05 54 69 6d 65 72 01
""".split()
    )
