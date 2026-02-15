from __future__ import annotations

from collections.abc import Iterable
from dataclasses import dataclass
from datetime import date, datetime
from decimal import ROUND_HALF_UP, Decimal, InvalidOperation

SUPPORTED_CURRENCIES = {"EUR", "XAF"}


def parse_iso_date(value: str) -> date:
    return date.fromisoformat(value)


def month_key(d: date) -> tuple[int, int]:
    return (d.year, d.month)


def parse_money_to_cents(amount: str, currency: str) -> int:
    if currency not in SUPPORTED_CURRENCIES:
        raise ValueError("Moneda no soportada")
    try:
        dec = Decimal(amount.replace(",", "."))
    except (InvalidOperation, AttributeError):
        raise ValueError("Importe inválido") from None
    if dec <= 0:
        raise ValueError("El importe debe ser mayor que 0")
    cents = (dec.quantize(Decimal("0.01"), rounding=ROUND_HALF_UP) * 100).to_integral_value()
    return int(cents)


def cents_to_str(cents: int) -> str:
    dec = (Decimal(cents) / Decimal(100)).quantize(Decimal("0.01"), rounding=ROUND_HALF_UP)
    return format(dec, "f")


def sum_cents(values: Iterable[int]) -> int:
    total = 0
    for v in values:
        total += int(v)
    return total


@dataclass(frozen=True)
class DateRange:
    start: date
    end_exclusive: date


def month_range(year: int, month: int) -> DateRange:
    start = date(year, month, 1)
    if month == 12:
        end = date(year + 1, 1, 1)
    else:
        end = date(year, month + 1, 1)
    return DateRange(start=start, end_exclusive=end)


def utc_now_iso() -> str:
    return datetime.utcnow().replace(microsecond=0).isoformat() + "Z"
