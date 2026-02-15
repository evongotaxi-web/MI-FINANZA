from __future__ import annotations

import json
import sqlite3
import uuid
from collections import defaultdict
from dataclasses import dataclass
from datetime import date, timedelta
from typing import Optional

from app.security import hash_password, verify_password
from app.utils import SUPPORTED_CURRENCIES, DateRange, month_range, parse_iso_date


def new_id() -> str:
    return str(uuid.uuid4())


@dataclass(frozen=True)
class AuthResult:
    user_id: str
    role: str


def create_user(conn: sqlite3.Connection, email: str, password: str) -> AuthResult:
    email_norm = email.strip().lower()
    if not email_norm or "@" not in email_norm:
        raise ValueError("Email inválido")
    if len(password) < 6:
        raise ValueError("Contraseña demasiado corta")
    user_id = new_id()
    try:
        conn.execute(
            """
            INSERT INTO users (id, email, password_hash, role, is_active, updated_at)
            VALUES (?, ?, ?, ?, ?, (strftime('%Y-%m-%dT%H:%M:%fZ','now')))
            """,
            (user_id, email_norm, hash_password(password), ROLE_FREE, 1),
        )
    except sqlite3.IntegrityError:
        raise ValueError("Ese email ya existe") from None
    row = conn.execute(
        "SELECT role FROM users WHERE id = ?",
        (user_id,),
    ).fetchone()
    return AuthResult(user_id=user_id, role=str(row["role"] if row else ROLE_FREE))


def authenticate(conn: sqlite3.Connection, email: str, password: str) -> Optional[AuthResult]:
    email_norm = email.strip().lower()
    row = conn.execute(
        """
        SELECT id, password_hash, role, is_active, deleted_at
        FROM users
        WHERE email = ?
        """,
        (email_norm,),
    ).fetchone()
    if not row:
        return None
    if int(row["is_active"] or 0) != 1:
        return None
    if row["deleted_at"]:
        return None
    if not verify_password(password, row["password_hash"]):
        return None
    return AuthResult(user_id=row["id"], role=str(row["role"] or ROLE_FREE))


ROLE_FREE = "ROLE_FREE"
ROLE_PREMIUM = "ROLE_PREMIUM"
ROLE_ADMIN = "ROLE_ADMIN"
ROLE_SUPER_ADMIN = "ROLE_SUPER_ADMIN"
ROLE_OWNER = "ROLE_OWNER"

ROLE_LEVEL: dict[str, int] = {
    ROLE_FREE: 10,
    ROLE_PREMIUM: 20,
    ROLE_ADMIN: 30,
    ROLE_SUPER_ADMIN: 40,
    ROLE_OWNER: 50,
}


def role_level(role: str) -> int:
    return ROLE_LEVEL.get(role, 0)


@dataclass(frozen=True)
class UserRecord:
    id: str
    email: str
    role: str
    is_active: bool
    deleted_at: Optional[str]
    created_at: str


def get_user(conn: sqlite3.Connection, *, user_id: str) -> UserRecord:
    row = conn.execute(
        """
        SELECT id, email, role, is_active, deleted_at, created_at
        FROM users
        WHERE id = ?
        """,
        (user_id,),
    ).fetchone()
    if not row:
        raise ValueError("Usuario no encontrado")
    return UserRecord(
        id=str(row["id"]),
        email=str(row["email"]),
        role=str(row["role"] or ROLE_FREE),
        is_active=int(row["is_active"] or 0) == 1,
        deleted_at=str(row["deleted_at"]) if row["deleted_at"] else None,
        created_at=str(row["created_at"]),
    )


def get_user_by_email(conn: sqlite3.Connection, *, email: str) -> Optional[UserRecord]:
    email_norm = email.strip().lower()
    if not email_norm or "@" not in email_norm:
        return None
    row = conn.execute(
        """
        SELECT id, email, role, is_active, deleted_at, created_at
        FROM users
        WHERE email = ?
        """,
        (email_norm,),
    ).fetchone()
    if not row:
        return None
    return UserRecord(
        id=str(row["id"]),
        email=str(row["email"]),
        role=str(row["role"] or ROLE_FREE),
        is_active=int(row["is_active"] or 0) == 1,
        deleted_at=str(row["deleted_at"]) if row["deleted_at"] else None,
        created_at=str(row["created_at"]),
    )


def get_user_by_firebase_uid(
    conn: sqlite3.Connection,
    *,
    firebase_uid: str,
) -> Optional[UserRecord]:
    firebase_uid_norm = firebase_uid.strip()
    if not firebase_uid_norm:
        return None
    row = conn.execute(
        """
        SELECT id, email, role, is_active, deleted_at, created_at
        FROM users
        WHERE firebase_uid = ?
        """,
        (firebase_uid_norm,),
    ).fetchone()
    if not row:
        return None
    return UserRecord(
        id=str(row["id"]),
        email=str(row["email"]),
        role=str(row["role"] or ROLE_FREE),
        is_active=int(row["is_active"] or 0) == 1,
        deleted_at=str(row["deleted_at"]) if row["deleted_at"] else None,
        created_at=str(row["created_at"]),
    )


def link_firebase_uid(
    conn: sqlite3.Connection,
    *,
    user_id: str,
    firebase_uid: str,
    auth_provider: Optional[str] = None,
) -> None:
    conn.execute(
        """
        UPDATE users
        SET firebase_uid = ?, auth_provider = COALESCE(?, auth_provider),
            updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        WHERE id = ?
        """,
        (firebase_uid.strip(), auth_provider, user_id),
    )


def create_user_firebase(
    conn: sqlite3.Connection,
    *,
    email: str,
    password: str,
    firebase_uid: str,
    auth_provider: str,
) -> AuthResult:
    email_norm = email.strip().lower()
    if not email_norm:
        raise ValueError("Email inválido")
    user_id = new_id()
    try:
        conn.execute(
            """
            INSERT INTO users (
              id, email, password_hash, role, is_active, firebase_uid, auth_provider, updated_at
            )
            VALUES (?, ?, ?, ?, ?, ?, ?, (strftime('%Y-%m-%dT%H:%M:%fZ','now')))
            """,
            (
                user_id,
                email_norm,
                hash_password(password),
                ROLE_FREE,
                1,
                firebase_uid,
                auth_provider,
            ),
        )
    except sqlite3.IntegrityError:
        raise ValueError("Ese email ya existe") from None
    row = conn.execute("SELECT role FROM users WHERE id = ?", (user_id,)).fetchone()
    return AuthResult(user_id=user_id, role=str(row["role"] if row else ROLE_FREE))

def can_manage_user(*, actor_role: str, target_role: str) -> bool:
    return role_level(actor_role) > role_level(target_role)


def ensure_can_manage_user(*, actor_role: str, target_role: str) -> None:
    if not can_manage_user(actor_role=actor_role, target_role=target_role):
        raise ValueError("No puedes actuar sobre tu mismo rol o uno superior")


def audit_log(
    conn: sqlite3.Connection,
    *,
    actor_user_id: Optional[str],
    action: str,
    target_user_id: Optional[str] = None,
    changes: Optional[dict[str, object]] = None,
    ip: Optional[str] = None,
    user_agent: Optional[str] = None,
) -> str:
    actor_email: Optional[str] = None
    target_email: Optional[str] = None
    if actor_user_id:
        row = conn.execute("SELECT email FROM users WHERE id = ?", (actor_user_id,)).fetchone()
        if row:
            actor_email = str(row["email"])
    if target_user_id:
        row = conn.execute("SELECT email FROM users WHERE id = ?", (target_user_id,)).fetchone()
        if row:
            target_email = str(row["email"])

    log_id = new_id()
    conn.execute(
        """
        INSERT INTO audit_logs
          (
            id, actor_user_id, actor_email, action, target_user_id, target_email,
            changes_json, ip, user_agent
          )
        VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            log_id,
            actor_user_id,
            actor_email,
            action,
            target_user_id,
            target_email,
            json.dumps(changes or {}, ensure_ascii=False, separators=(",", ":")),
            ip,
            user_agent,
        ),
    )
    return log_id


def ensure_month_open(conn: sqlite3.Connection, user_id: str, d: date) -> None:
    y, m = d.year, d.month
    row = conn.execute(
        "SELECT 1 FROM month_closures WHERE user_id = ? AND year = ? AND month = ?",
        (user_id, y, m),
    ).fetchone()
    if row:
        raise ValueError("Mes cerrado: no se puede modificar")


def compute_bruto_dia_cents(
    *,
    horas_dia: float,
    horas_noche: float,
    precio_hora_dia_cents: int,
    precio_hora_noche_cents: int,
    bonus_cents: int,
    pluses_cents: int,
) -> int:
    bruto = round(horas_dia * precio_hora_dia_cents) + round(horas_noche * precio_hora_noche_cents)
    bruto += int(bonus_cents) + int(pluses_cents)
    return int(bruto)


def get_company(conn: sqlite3.Connection, *, user_id: str, company_id: str) -> sqlite3.Row:
    row = conn.execute(
        """
        SELECT id, user_id, name, currency, precio_hora_dia_cents, precio_hora_noche_cents,
               irpf_porcentaje, otros_descuentos_cents, pagas_prorrateadas
        FROM companies
        WHERE id = ? AND user_id = ?
        """,
        (company_id, user_id),
    ).fetchone()
    if not row:
        raise ValueError("Empresa no encontrada")
    return row


def month_income_breakdown(
    conn: sqlite3.Connection, *, user_id: str, year: int, month: int
) -> dict[str, dict[str, int]]:
    r = month_range(year, month)
    rows = conn.execute(
        """
        SELECT c.id as company_id,
               c.name as company_name,
               c.currency as currency,
               c.irpf_porcentaje as irpf_porcentaje,
               c.otros_descuentos_cents as otros_descuentos_cents,
               SUM(w.bruto_dia_cents) as bruto_mes_cents,
               SUM(w.anticipos_cents) as anticipos_mes_cents
        FROM work_entries w
        JOIN companies c ON c.id = w.company_id
        WHERE w.user_id = ?
          AND w.date >= ? AND w.date < ?
        GROUP BY c.id, c.name, c.currency, c.irpf_porcentaje, c.otros_descuentos_cents
        ORDER BY c.name ASC
        """,
        (user_id, r.start.isoformat(), r.end_exclusive.isoformat()),
    ).fetchall()

    out: dict[str, dict[str, int]] = {}
    for row in rows:
        bruto = int(row["bruto_mes_cents"] or 0)
        irpf_cents = int(round(bruto * (float(row["irpf_porcentaje"] or 0) / 100.0)))
        otros_desc = int(row["otros_descuentos_cents"] or 0)
        neto_estimado = bruto - irpf_cents - otros_desc
        anticipos = int(row["anticipos_mes_cents"] or 0)
        neto_final = neto_estimado - anticipos
        out[str(row["company_id"])] = {
            "companyName": str(row["company_name"]),
            "currency": str(row["currency"]),
            "brutoMesCents": bruto,
            "irpfCents": irpf_cents,
            "otrosDescuentosCents": otros_desc,
            "netoEstimadoCents": neto_estimado,
            "anticiposCents": anticipos,
            "netoFinalCents": neto_final,
        }
    return out


def month_income_net_by_currency(
    conn: sqlite3.Connection, *, user_id: str, year: int, month: int
) -> dict[str, int]:
    breakdown = month_income_breakdown(conn, user_id=user_id, year=year, month=month)
    totals: dict[str, int] = defaultdict(int)
    for item in breakdown.values():
        totals[item["currency"]] += int(item["netoFinalCents"])
    return dict(totals)


def month_expenses_by_currency(
    conn: sqlite3.Connection, *, user_id: str, year: int, month: int
) -> dict[str, int]:
    r = month_range(year, month)
    rows = conn.execute(
        """
        SELECT currency, SUM(amount_cents) as total_cents
        FROM expenses
        WHERE user_id = ?
          AND date >= ? AND date < ?
        GROUP BY currency
        """,
        (user_id, r.start.isoformat(), r.end_exclusive.isoformat()),
    ).fetchall()
    return {row["currency"]: int(row["total_cents"] or 0) for row in rows}


def month_expenses_not_in_bank_by_currency(
    conn: sqlite3.Connection, *, user_id: str, year: int, month: int
) -> dict[str, int]:
    r = month_range(year, month)
    rows = conn.execute(
        """
        SELECT currency, SUM(amount_cents) as total_cents
        FROM expenses
        WHERE user_id = ?
          AND date >= ? AND date < ?
          AND afecta_banco = 0
        GROUP BY currency
        """,
        (user_id, r.start.isoformat(), r.end_exclusive.isoformat()),
    ).fetchall()
    return {row["currency"]: int(row["total_cents"] or 0) for row in rows}


def is_month_closed(conn: sqlite3.Connection, *, user_id: str, year: int, month: int) -> bool:
    row = conn.execute(
        "SELECT 1 FROM month_closures WHERE user_id = ? AND year = ? AND month = ?",
        (user_id, year, month),
    ).fetchone()
    return bool(row)


def close_month(conn: sqlite3.Connection, *, user_id: str, year: int, month: int) -> str:
    if is_month_closed(conn, user_id=user_id, year=year, month=month):
        raise ValueError("No se puede cerrar el mes dos veces")

    closure_id = new_id()
    conn.execute(
        "INSERT INTO month_closures (id, user_id, year, month) VALUES (?, ?, ?, ?)",
        (closure_id, user_id, year, month),
    )

    income_net = month_income_net_by_currency(conn, user_id=user_id, year=year, month=month)
    expenses_not_in_bank = month_expenses_not_in_bank_by_currency(
        conn, user_id=user_id, year=year, month=month
    )

    amounts_by_currency: dict[str, int] = defaultdict(int)
    for currency, neto in income_net.items():
        amounts_by_currency[currency] += int(neto)
    for currency, exp in expenses_not_in_bank.items():
        amounts_by_currency[currency] -= int(exp)

    r: DateRange = month_range(year, month)
    movement_date = (r.end_exclusive - timedelta(days=1)).isoformat()
    for currency, amount_cents in amounts_by_currency.items():
        if currency not in SUPPORTED_CURRENCIES:
            continue
        if amount_cents == 0:
            continue
        conn.execute(
            """
            INSERT INTO bank_movements
              (id, user_id, date, type, amount_cents, currency, note, month_closure_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id(),
                user_id,
                movement_date,
                "ingresoMesCerrado",
                int(amount_cents),
                currency,
                f"Cierre {year:04d}-{month:02d}",
                closure_id,
            ),
        )
    return closure_id


def bank_balance_by_currency(conn: sqlite3.Connection, *, user_id: str) -> dict[str, int]:
    rows = conn.execute(
        """
        SELECT currency, SUM(amount_cents) as total_cents
        FROM bank_movements
        WHERE user_id = ?
        GROUP BY currency
        """,
        (user_id,),
    ).fetchall()
    return {row["currency"]: int(row["total_cents"] or 0) for row in rows}


def recalc_debt_remaining_cents(
    conn: sqlite3.Connection, *, user_id: str, debt_id: str
) -> tuple[int, int]:
    debt = conn.execute(
        "SELECT total_cents FROM debts WHERE id = ? AND user_id = ?",
        (debt_id, user_id),
    ).fetchone()
    if not debt:
        raise ValueError("Deuda no encontrada")
    paid = conn.execute(
        """
        SELECT SUM(amount_cents) as paid_cents
        FROM debt_payments
        WHERE debt_id = ? AND user_id = ?
        """,
        (debt_id, user_id),
    ).fetchone()
    paid_cents = int(paid["paid_cents"] or 0) if paid else 0
    total_cents = int(debt["total_cents"])
    remaining = total_cents - paid_cents
    return (total_cents, remaining)


def parse_date_or_raise(value: str) -> date:
    try:
        return parse_iso_date(value)
    except Exception:
        raise ValueError("Fecha inválida (usa YYYY-MM-DD)") from None
