from __future__ import annotations

import os
import sqlite3
from collections.abc import Iterator
from pathlib import Path


def _db_path() -> Path:
    raw = os.environ.get("MIS_FINANZAS_DB_PATH")
    if raw:
        return Path(raw).expanduser().resolve()
    return (Path(__file__).resolve().parent.parent / "data" / "mis_finanzas.sqlite3").resolve()


def _connect() -> sqlite3.Connection:
    path = _db_path()
    path.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(path, check_same_thread=False)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA foreign_keys = ON;")
    conn.execute("PRAGMA journal_mode = WAL;")
    conn.execute("PRAGMA synchronous = NORMAL;")
    return conn


def init_db() -> None:
    conn = _connect()
    try:
        conn.executescript(_SCHEMA_SQL)
        _apply_migrations(conn)
        conn.commit()
    finally:
        conn.close()


def get_db() -> Iterator[sqlite3.Connection]:
    conn = _connect()
    try:
        yield conn
        conn.commit()
    finally:
        conn.close()


_SCHEMA_SQL = """
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL UNIQUE,
  password_hash TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);

CREATE TABLE IF NOT EXISTS companies (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  name TEXT NOT NULL,
  currency TEXT NOT NULL DEFAULT 'EUR',
  precio_hora_dia_cents INTEGER NOT NULL,
  precio_hora_noche_cents INTEGER NOT NULL,
  irpf_porcentaje REAL NOT NULL,
  otros_descuentos_cents INTEGER NOT NULL DEFAULT 0,
  pagas_prorrateadas INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(user_id, name)
);
CREATE INDEX IF NOT EXISTS idx_companies_user ON companies(user_id);

CREATE TABLE IF NOT EXISTS work_entries (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  company_id TEXT NOT NULL REFERENCES companies(id) ON DELETE RESTRICT,
  date TEXT NOT NULL,
  hora_entrada TEXT,
  hora_salida TEXT,
  descanso_min INTEGER NOT NULL DEFAULT 0,
  horas_dia REAL NOT NULL DEFAULT 0,
  horas_noche REAL NOT NULL DEFAULT 0,
  bonus_cents INTEGER NOT NULL DEFAULT 0,
  pluses_cents INTEGER NOT NULL DEFAULT 0,
  anticipos_cents INTEGER NOT NULL DEFAULT 0,
  bruto_dia_cents INTEGER NOT NULL DEFAULT 0,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_work_entries_user_date ON work_entries(user_id, date);
CREATE INDEX IF NOT EXISTS idx_work_entries_company_date ON work_entries(company_id, date);

CREATE TABLE IF NOT EXISTS expenses (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  date TEXT NOT NULL,
  category TEXT NOT NULL,
  concept TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  currency TEXT NOT NULL,
  afecta_banco INTEGER NOT NULL DEFAULT 1,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_expenses_user_date ON expenses(user_id, date);
CREATE INDEX IF NOT EXISTS idx_expenses_user_category ON expenses(user_id, category);

CREATE TABLE IF NOT EXISTS month_closures (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  year INTEGER NOT NULL,
  month INTEGER NOT NULL,
  closed_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now')),
  UNIQUE(user_id, year, month)
);
CREATE INDEX IF NOT EXISTS idx_month_closures_user ON month_closures(user_id);

CREATE TABLE IF NOT EXISTS bank_movements (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  date TEXT NOT NULL,
  type TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  currency TEXT NOT NULL,
  note TEXT,
  month_closure_id TEXT REFERENCES month_closures(id) ON DELETE SET NULL,
  related_expense_id TEXT REFERENCES expenses(id) ON DELETE SET NULL,
  related_debt_payment_id TEXT,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_bank_movements_user_date ON bank_movements(user_id, date);
CREATE INDEX IF NOT EXISTS idx_bank_movements_user_currency ON bank_movements(user_id, currency);

CREATE TABLE IF NOT EXISTS debts (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  creditor TEXT NOT NULL,
  total_cents INTEGER NOT NULL,
  currency TEXT NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_debts_user ON debts(user_id);

CREATE TABLE IF NOT EXISTS debt_payments (
  id TEXT PRIMARY KEY,
  user_id TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
  debt_id TEXT NOT NULL REFERENCES debts(id) ON DELETE CASCADE,
  date TEXT NOT NULL,
  amount_cents INTEGER NOT NULL,
  created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
);
CREATE INDEX IF NOT EXISTS idx_debt_payments_debt_date ON debt_payments(debt_id, date);
"""


def _apply_migrations(conn: sqlite3.Connection) -> None:
    current = int(conn.execute("PRAGMA user_version;").fetchone()[0])
    migrations = [
        _migration_1_roles_and_soft_delete,
        _migration_2_audit_logs,
        _migration_3_firebase_auth,
    ]
    for idx, fn in enumerate(migrations, start=1):
        if current >= idx:
            continue
        fn(conn)
        conn.execute(f"PRAGMA user_version = {idx};")
        current = idx


def _migration_1_roles_and_soft_delete(conn: sqlite3.Connection) -> None:
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(users);").fetchall()}
    if "role" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN role TEXT;")
    if "is_active" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN is_active INTEGER;")
    if "deleted_at" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN deleted_at TEXT;")
    if "updated_at" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN updated_at TEXT;")

    conn.execute(
        """
        UPDATE users
        SET role = COALESCE(role, 'ROLE_FREE'),
            is_active = COALESCE(is_active, 1),
            updated_at = COALESCE(updated_at, created_at)
        """
    )
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_role ON users(role);")
    conn.execute("CREATE INDEX IF NOT EXISTS idx_users_active ON users(is_active);")


def _migration_2_audit_logs(conn: sqlite3.Connection) -> None:
    conn.executescript(
        """
        CREATE TABLE IF NOT EXISTS audit_logs (
          id TEXT PRIMARY KEY,
          actor_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
          actor_email TEXT,
          action TEXT NOT NULL,
          target_user_id TEXT REFERENCES users(id) ON DELETE SET NULL,
          target_email TEXT,
          changes_json TEXT,
          ip TEXT,
          user_agent TEXT,
          created_at TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        );
        CREATE INDEX IF NOT EXISTS idx_audit_logs_created_at ON audit_logs(created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_actor ON audit_logs(actor_user_id, created_at);
        CREATE INDEX IF NOT EXISTS idx_audit_logs_target ON audit_logs(target_user_id, created_at);
        """
    )


def _migration_3_firebase_auth(conn: sqlite3.Connection) -> None:
    cols = {row["name"] for row in conn.execute("PRAGMA table_info(users);").fetchall()}
    if "firebase_uid" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN firebase_uid TEXT;")
    if "auth_provider" not in cols:
        conn.execute("ALTER TABLE users ADD COLUMN auth_provider TEXT;")

    conn.execute("CREATE UNIQUE INDEX IF NOT EXISTS idx_users_firebase_uid ON users(firebase_uid);")
