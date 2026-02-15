import os
import sqlite3
from pathlib import Path

import pytest

from app.db import init_db
from app.services import (
    ROLE_ADMIN,
    ROLE_FREE,
    ROLE_OWNER,
    ROLE_PREMIUM,
    ROLE_SUPER_ADMIN,
    audit_log,
    authenticate,
    create_user,
    ensure_can_manage_user,
    get_user,
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


def test_new_user_defaults_to_active_free(conn: sqlite3.Connection) -> None:
    user_id = create_user(conn, email="test@example.com", password="123456").user_id
    user = get_user(conn, user_id=user_id)
    assert user.role == ROLE_FREE
    assert user.is_active is True
    assert user.deleted_at is None


def test_manage_user_requires_strictly_higher_role() -> None:
    with pytest.raises(ValueError):
        ensure_can_manage_user(actor_role=ROLE_ADMIN, target_role=ROLE_ADMIN)
    with pytest.raises(ValueError):
        ensure_can_manage_user(actor_role=ROLE_ADMIN, target_role=ROLE_SUPER_ADMIN)
    ensure_can_manage_user(actor_role=ROLE_ADMIN, target_role=ROLE_PREMIUM)
    ensure_can_manage_user(actor_role=ROLE_SUPER_ADMIN, target_role=ROLE_ADMIN)
    ensure_can_manage_user(actor_role=ROLE_OWNER, target_role=ROLE_SUPER_ADMIN)


def test_soft_delete_blocks_login(conn: sqlite3.Connection) -> None:
    create_user(conn, email="a@b.com", password="123456")
    ok = authenticate(conn, email="a@b.com", password="123456")
    assert ok is not None

    conn.execute(
        """
        UPDATE users
        SET is_active = 0, deleted_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        WHERE email = ?
        """,
        ("a@b.com",),
    )
    blocked = authenticate(conn, email="a@b.com", password="123456")
    assert blocked is None


def test_audit_log_writes_row(conn: sqlite3.Connection) -> None:
    actor_id = create_user(conn, email="actor@b.com", password="123456").user_id
    target_id = create_user(conn, email="target@b.com", password="123456").user_id
    log_id = audit_log(
        conn,
        actor_user_id=actor_id,
        action="admin.setPlan",
        target_user_id=target_id,
        changes={"fromRole": ROLE_FREE, "toRole": ROLE_PREMIUM},
        ip="127.0.0.1",
        user_agent="pytest",
    )
    row = conn.execute("SELECT id, action FROM audit_logs WHERE id = ?", (log_id,)).fetchone()
    assert row is not None
    assert row["action"] == "admin.setPlan"
