import os
import sqlite3
from pathlib import Path

import pytest

from app.db import init_db
from app.services import (
    close_month,
    create_user,
    ensure_month_open,
    new_id,
    recalc_debt_remaining_cents,
)


def _connect(db_path: Path) -> sqlite3.Connection:
    conn = sqlite3.connect(db_path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    return conn


@pytest.fixture()
def conn(tmp_path: Path) -> sqlite3.Connection:
    db_path = tmp_path / "test.sqlite3"
    os.environ["MIS_FINANZAS_DB_PATH"] = str(db_path)
    init_db()
    conn = _connect(db_path)
    try:
        yield conn
    finally:
        conn.close()
        os.environ.pop("MIS_FINANZAS_DB_PATH", None)


def _seed_user(conn: sqlite3.Connection) -> str:
    return create_user(conn, email="a@b.com", password="123456").user_id


def _seed_company(conn: sqlite3.Connection, user_id: str, *, currency: str = "EUR") -> str:
    company_id = new_id()
    conn.execute(
        """
        INSERT INTO companies
          (id, user_id, name, currency, precio_hora_dia_cents, precio_hora_noche_cents,
           irpf_porcentaje, otros_descuentos_cents, pagas_prorrateadas)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (company_id, user_id, "Empresa", currency, 1000, 1200, 10.0, 5000, 0),
    )
    return company_id


def test_close_month_creates_bank_movement_and_blocks_month(conn: sqlite3.Connection) -> None:
    user_id = _seed_user(conn)
    company_id = _seed_company(conn, user_id)

    conn.execute(
        """
        INSERT INTO work_entries
          (id, user_id, company_id, date, horas_dia, horas_noche, bonus_cents, pluses_cents,
           anticipos_cents, bruto_dia_cents)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (new_id(), user_id, company_id, "2026-02-10", 0, 0, 0, 0, 10000, 100000),
    )

    conn.execute(
        """
        INSERT INTO expenses
          (id, user_id, date, category, concept, amount_cents, currency, afecta_banco)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (new_id(), user_id, "2026-02-11", "Cat", "Concepto", 2000, "EUR", 0),
    )

    closure_id = close_month(conn, user_id=user_id, year=2026, month=2)
    assert closure_id

    movement = conn.execute(
        """
        SELECT date, type, amount_cents, currency, month_closure_id
        FROM bank_movements
        WHERE user_id = ? AND type = 'ingresoMesCerrado'
        """,
        (user_id,),
    ).fetchone()
    assert movement is not None
    assert movement["date"] == "2026-02-28"
    assert movement["currency"] == "EUR"
    assert int(movement["amount_cents"]) == 73000
    assert movement["month_closure_id"] == closure_id

    with pytest.raises(ValueError):
        ensure_month_open(conn, user_id, date_from_iso("2026-02-01"))


def date_from_iso(value: str):
    from datetime import date

    return date.fromisoformat(value)


def test_close_month_twice_fails(conn: sqlite3.Connection) -> None:
    user_id = _seed_user(conn)
    _seed_company(conn, user_id)
    close_month(conn, user_id=user_id, year=2026, month=1)
    with pytest.raises(ValueError):
        close_month(conn, user_id=user_id, year=2026, month=1)


def test_debt_remaining_is_updated(conn: sqlite3.Connection) -> None:
    user_id = _seed_user(conn)
    debt_id = new_id()
    conn.execute(
        "INSERT INTO debts (id, user_id, creditor, total_cents, currency) VALUES (?, ?, ?, ?, ?)",
        (debt_id, user_id, "Banco", 10000, "EUR"),
    )
    conn.execute(
        """
        INSERT INTO debt_payments (id, user_id, debt_id, date, amount_cents)
        VALUES (?, ?, ?, ?, ?)
        """,
        (new_id(), user_id, debt_id, "2026-01-02", 3000),
    )
    total, remaining = recalc_debt_remaining_cents(conn, user_id=user_id, debt_id=debt_id)
    assert total == 10000
    assert remaining == 7000
