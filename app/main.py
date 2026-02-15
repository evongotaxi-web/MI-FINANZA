from __future__ import annotations

import csv
import html
import io
import json
import os
import secrets
import time
import urllib.parse
from base64 import urlsafe_b64decode
from datetime import datetime, timedelta, timezone
from typing import Any, Optional

import httpx
from fastapi import Depends, FastAPI, Form, HTTPException, Request, Response
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates

from app.db import get_db, init_db
from app.security import SessionData, decode_oauth, decode_session, encode_oauth, encode_session
from app.services import (
    ROLE_ADMIN,
    ROLE_FREE,
    ROLE_OWNER,
    ROLE_PREMIUM,
    ROLE_SUPER_ADMIN,
    audit_log,
    authenticate,
    bank_balance_by_currency,
    close_month,
    compute_bruto_dia_cents,
    create_user,
    create_user_firebase,
    ensure_can_manage_user,
    ensure_month_open,
    get_company,
    get_user,
    get_user_by_email,
    get_user_by_firebase_uid,
    is_month_closed,
    link_firebase_uid,
    month_expenses_by_currency,
    month_expenses_not_in_bank_by_currency,
    month_income_breakdown,
    month_income_net_by_currency,
    new_id,
    parse_date_or_raise,
    recalc_debt_remaining_cents,
    role_level,
)
from app.utils import SUPPORTED_CURRENCIES, cents_to_str, parse_money_to_cents

app = FastAPI(title="MIS FINANZAS")
templates = Jinja2Templates(directory="app/templates")
app.mount("/static", StaticFiles(directory="app/static"), name="static")


@app.on_event("startup")
def _startup() -> None:
    init_db()
    app.state.owner_bootstrap_token = os.environ.get("MIS_FINANZAS_OWNER_BOOTSTRAP_TOKEN", "")


def _current_user_id(request: Request) -> Optional[str]:
    cookie = request.cookies.get("mf_session")
    if not cookie:
        return None
    data = decode_session(cookie)
    return data.user_id if data else None


def _client_ip(request: Request) -> Optional[str]:
    return request.client.host if request.client else None


def _user_agent(request: Request) -> Optional[str]:
    raw = request.headers.get("user-agent")
    return raw if raw else None


def require_user_record(request: Request, conn=Depends(get_db)):
    user_id = _current_user_id(request)
    if not user_id:
        raise HTTPException(status_code=401, detail="No autenticado")
    user = get_user(conn, user_id=user_id)
    if (not user.is_active) or user.deleted_at:
        raise HTTPException(status_code=403, detail="Cuenta suspendida o eliminada")
    return user


def require_user_id(user=Depends(require_user_record)) -> str:
    return user.id


def require_page_user_record(request: Request, conn=Depends(get_db)):
    user_id = _current_user_id(request)
    if not user_id:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    user = get_user(conn, user_id=user_id)
    if (not user.is_active) or user.deleted_at:
        raise HTTPException(status_code=302, headers={"Location": "/login"})
    return user


def require_page_user_id(user=Depends(require_page_user_record)) -> str:
    return user.id


def require_admin_user(user=Depends(require_user_record)):
    if role_level(user.role) < role_level(ROLE_ADMIN):
        raise HTTPException(status_code=403, detail="No autorizado")
    return user


def require_super_admin_user(user=Depends(require_user_record)):
    if role_level(user.role) < role_level(ROLE_SUPER_ADMIN):
        raise HTTPException(status_code=403, detail="No autorizado")
    return user


def require_owner_user(user=Depends(require_user_record)):
    if user.role != ROLE_OWNER:
        raise HTTPException(status_code=403, detail="No autorizado")
    return user


def require_premium_user(user=Depends(require_user_record)):
    if role_level(user.role) < role_level(ROLE_PREMIUM):
        raise HTTPException(status_code=402, detail="Requiere Premium")
    return user


def _cookie_secure(request: Request) -> bool:
    proto = request.headers.get("x-forwarded-proto")
    if proto:
        return proto.lower() == "https"
    return request.url.scheme == "https"


def _set_session_cookie(response: Response, request: Request, user_id: str) -> None:
    token = encode_session(SessionData(user_id=user_id))
    response.set_cookie(
        "mf_session",
        token,
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(request),
        max_age=60 * 60 * 24 * 180,
    )


def _base_url(request: Request) -> str:
    proto = request.headers.get("x-forwarded-proto") or request.url.scheme
    host = (
        request.headers.get("x-forwarded-host")
        or request.headers.get("host")
        or request.url.netloc
    )
    return f"{proto}://{host}".rstrip("/")


@app.get("/", response_class=HTMLResponse)
def root(request: Request) -> Response:
    if _current_user_id(request):
        return RedirectResponse("/dashboard", status_code=302)
    return RedirectResponse("/login", status_code=302)


@app.get("/@vite/client")
def vite_client_placeholder() -> Response:
    return Response(content="", media_type="application/javascript")


@app.get("/login", response_class=HTMLResponse)
def login_page(request: Request) -> Response:
    error = request.query_params.get("error")
    firebase_config = _firebase_client_config()
    firebase_config_json = json.dumps(firebase_config) if firebase_config else None
    return templates.TemplateResponse(
        "auth_login.html",
        {
            "request": request,
            "error": error,
            "firebase_config": firebase_config,
            "firebase_config_json": firebase_config_json,
        },
    )


@app.post("/login", response_class=HTMLResponse)
def login(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    conn=Depends(get_db),
) -> Response:
    result = authenticate(conn, email=email, password=password)
    if not result:
        return templates.TemplateResponse(
            "auth_login.html",
            {"request": request, "error": "Credenciales inválidas"},
            status_code=400,
        )
    resp = RedirectResponse("/dashboard", status_code=302)
    _set_session_cookie(resp, request, result.user_id)
    return resp


@app.get("/register", response_class=HTMLResponse)
def register_page(request: Request) -> Response:
    return templates.TemplateResponse("auth_register.html", {"request": request})


@app.post("/register", response_class=HTMLResponse)
def register(
    request: Request,
    email: str = Form(...),
    password: str = Form(...),
    conn=Depends(get_db),
) -> Response:
    try:
        result = create_user(conn, email=email, password=password)
    except ValueError as e:
        return templates.TemplateResponse(
            "auth_register.html",
            {"request": request, "error": str(e)},
            status_code=400,
        )
    resp = RedirectResponse("/dashboard", status_code=302)
    _set_session_cookie(resp, request, result.user_id)
    return resp


def _firebase_client_config() -> Optional[dict[str, str]]:
    api_key = os.environ.get("FIREBASE_API_KEY", "").strip()
    auth_domain = os.environ.get("FIREBASE_AUTH_DOMAIN", "").strip()
    project_id = os.environ.get("FIREBASE_PROJECT_ID", "").strip()
    app_id = os.environ.get("FIREBASE_APP_ID", "").strip()
    messaging_sender_id = os.environ.get("FIREBASE_MESSAGING_SENDER_ID", "").strip()
    if not api_key or not auth_domain:
        return None
    cfg: dict[str, str] = {"apiKey": api_key, "authDomain": auth_domain}
    if project_id:
        cfg["projectId"] = project_id
    if app_id:
        cfg["appId"] = app_id
    if messaging_sender_id:
        cfg["messagingSenderId"] = messaging_sender_id
    return cfg


@app.post("/auth/firebase")
async def auth_firebase(
    request: Request,
    id_token: str = Form(...),
    conn=Depends(get_db),
) -> Response:
    api_key = os.environ.get("FIREBASE_API_KEY", "").strip()
    if not api_key:
        raise HTTPException(status_code=503, detail="Firebase no configurado")

    async with httpx.AsyncClient(timeout=12.0) as client:
        res = await client.post(
            "https://identitytoolkit.googleapis.com/v1/accounts:lookup",
            params={"key": api_key},
            json={"idToken": id_token},
        )
    if res.status_code != 200:
        return JSONResponse({"ok": False, "error": "Token inválido"}, status_code=400)
    raw = res.json()
    users = raw.get("users")
    if not isinstance(users, list) or not users:
        return JSONResponse({"ok": False, "error": "Token inválido"}, status_code=400)
    info = users[0] if isinstance(users[0], dict) else {}
    firebase_uid = str(info.get("localId") or "").strip()
    if not firebase_uid:
        return JSONResponse({"ok": False, "error": "Token inválido"}, status_code=400)

    email = str(info.get("email") or "").strip().lower()
    email_verified = bool(info.get("emailVerified") is True)
    provider = "firebase"
    provider_infos = info.get("providerUserInfo")
    if isinstance(provider_infos, list) and provider_infos:
        first = provider_infos[0] if isinstance(provider_infos[0], dict) else {}
        prov_id = str(first.get("providerId") or "").strip()
        if prov_id:
            provider = prov_id

    user = get_user_by_firebase_uid(conn, firebase_uid=firebase_uid)
    if not user and email:
        user = get_user_by_email(conn, email=email)
        if user:
            link_firebase_uid(
                conn,
                user_id=user.id,
                firebase_uid=firebase_uid,
                auth_provider=provider,
            )

    user_id: str
    if user:
        if (not user.is_active) or user.deleted_at:
            return JSONResponse({"ok": False, "error": "Cuenta suspendida"}, status_code=403)
        user_id = user.id
    else:
        if not email:
            email = f"firebase-{firebase_uid}@misfinanzas.local"
        if provider.endswith("password") and email and (not email_verified):
            return JSONResponse({"ok": False, "error": "Email no verificado"}, status_code=403)
        created = create_user_firebase(
            conn,
            email=email,
            password=secrets.token_urlsafe(32),
            firebase_uid=firebase_uid,
            auth_provider=provider,
        )
        user_id = created.user_id

    resp = JSONResponse({"ok": True, "redirect": "/dashboard"})
    _set_session_cookie(resp, request, user_id)
    return resp


def _jwt_payload(token: str) -> dict[str, object]:
    parts = token.split(".")
    if len(parts) < 2:
        return {}
    raw = parts[1]
    pad = "=" * (-len(raw) % 4)
    data = urlsafe_b64decode(raw + pad)
    val = json.loads(data.decode("utf-8"))
    return val if isinstance(val, dict) else {}


def _google_oauth_config(request: Request) -> dict[str, str]:
    client_id = os.environ.get("GOOGLE_CLIENT_ID", "").strip()
    client_secret = os.environ.get("GOOGLE_CLIENT_SECRET", "").strip()
    if not client_id or not client_secret:
        raise HTTPException(status_code=503, detail="Google OAuth no configurado")
    redirect_uri = os.environ.get("GOOGLE_REDIRECT_URI", "").strip()
    if not redirect_uri:
        redirect_uri = f"{_base_url(request)}/auth/google/callback"
    return {"client_id": client_id, "client_secret": client_secret, "redirect_uri": redirect_uri}


@app.get("/auth/google/start")
def auth_google_start(request: Request) -> Response:
    if _current_user_id(request):
        return RedirectResponse("/dashboard", status_code=302)
    try:
        cfg = _google_oauth_config(request)
    except HTTPException:
        return RedirectResponse("/login?error=Google%20no%20configurado", status_code=302)

    state = secrets.token_urlsafe(24)
    nonce = secrets.token_urlsafe(24)
    payload = encode_oauth({"state": state, "nonce": nonce, "ts": int(time.time())})

    params = {
        "client_id": cfg["client_id"],
        "redirect_uri": cfg["redirect_uri"],
        "response_type": "code",
        "scope": "openid email profile",
        "state": state,
        "nonce": nonce,
        "prompt": "select_account",
    }
    url = "https://accounts.google.com/o/oauth2/v2/auth?" + urllib.parse.urlencode(params)
    resp = RedirectResponse(url, status_code=302)
    resp.set_cookie(
        "mf_google_oauth",
        payload,
        httponly=True,
        samesite="lax",
        secure=_cookie_secure(request),
        max_age=60 * 10,
    )
    return resp


@app.get("/auth/google/callback", response_class=HTMLResponse)
async def auth_google_callback(request: Request, conn=Depends(get_db)) -> Response:
    if _current_user_id(request):
        return RedirectResponse("/dashboard", status_code=302)
    error = request.query_params.get("error")
    if error:
        return RedirectResponse("/login?error=Acceso%20con%20Google%20cancelado", status_code=302)

    code = request.query_params.get("code")
    state = request.query_params.get("state")
    if not code or not state:
        return RedirectResponse("/login?error=Google%20no%20válido", status_code=302)

    cookie = request.cookies.get("mf_google_oauth")
    data = decode_oauth(cookie) if cookie else None
    if not data or str(data.get("state") or "") != str(state):
        return RedirectResponse("/login?error=Sesión%20caducada", status_code=302)

    nonce_expected = str(data.get("nonce") or "")

    try:
        cfg = _google_oauth_config(request)
    except HTTPException:
        return RedirectResponse("/login?error=Google%20no%20configurado", status_code=302)

    async with httpx.AsyncClient(timeout=12.0) as client:
        token_res = await client.post(
            "https://oauth2.googleapis.com/token",
            data={
                "code": code,
                "client_id": cfg["client_id"],
                "client_secret": cfg["client_secret"],
                "redirect_uri": cfg["redirect_uri"],
                "grant_type": "authorization_code",
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        if token_res.status_code != 200:
            return RedirectResponse("/login?error=Google%20falló", status_code=302)
        token_json = token_res.json()
        id_token = str(token_json.get("id_token") or "")
        if not id_token:
            return RedirectResponse("/login?error=Google%20falló", status_code=302)

        info_res = await client.get(
            "https://oauth2.googleapis.com/tokeninfo",
            params={"id_token": id_token},
        )
        if info_res.status_code != 200:
            return RedirectResponse("/login?error=Google%20falló", status_code=302)
        info = info_res.json()
        if str(info.get("aud") or "") != cfg["client_id"]:
            return RedirectResponse("/login?error=Google%20no%20válido", status_code=302)
        if str(info.get("email_verified") or "").lower() not in ("true", "1", "yes"):
            return RedirectResponse("/login?error=Email%20no%20verificado", status_code=302)
        email = str(info.get("email") or "").strip().lower()
        if not email or "@" not in email:
            return RedirectResponse("/login?error=Google%20no%20válido", status_code=302)

    try:
        payload = _jwt_payload(id_token)
        if nonce_expected and str(payload.get("nonce") or "") != nonce_expected:
            return RedirectResponse("/login?error=Sesión%20caducada", status_code=302)
    except Exception:
        return RedirectResponse("/login?error=Google%20no%20válido", status_code=302)

    user = get_user_by_email(conn, email=email)
    if user:
        if (not user.is_active) or user.deleted_at:
            return RedirectResponse("/login?error=Cuenta%20suspendida", status_code=302)
        user_id = user.id
    else:
        try:
            created = create_user(conn, email=email, password=secrets.token_urlsafe(32))
            user_id = created.user_id
        except ValueError:
            user2 = get_user_by_email(conn, email=email)
            if not user2 or (not user2.is_active) or user2.deleted_at:
                return RedirectResponse("/login?error=No%20autorizado", status_code=302)
            user_id = user2.id

    resp = RedirectResponse("/dashboard", status_code=302)
    resp.delete_cookie("mf_google_oauth")
    _set_session_cookie(resp, request, user_id)
    return resp


@app.post("/logout")
def logout() -> Response:
    resp = RedirectResponse("/login", status_code=302)
    resp.delete_cookie("mf_session")
    return resp


@app.get("/dashboard", response_class=HTMLResponse)
def dashboard(request: Request, user_id: str = Depends(require_page_user_id)) -> Response:
    return templates.TemplateResponse("dashboard.html", {"request": request, "user_id": user_id})


@app.get("/ingresos", response_class=HTMLResponse)
def ingresos(request: Request, user_id: str = Depends(require_page_user_id)) -> Response:
    return templates.TemplateResponse("ingresos.html", {"request": request, "user_id": user_id})


@app.get("/gastos", response_class=HTMLResponse)
def gastos(request: Request, user_id: str = Depends(require_page_user_id)) -> Response:
    return templates.TemplateResponse("gastos.html", {"request": request, "user_id": user_id})


@app.get("/banco", response_class=HTMLResponse)
def banco(request: Request, user_id: str = Depends(require_page_user_id)) -> Response:
    return templates.TemplateResponse("banco.html", {"request": request, "user_id": user_id})


@app.get("/deudas", response_class=HTMLResponse)
def deudas(request: Request, user_id: str = Depends(require_page_user_id)) -> Response:
    return templates.TemplateResponse("deudas.html", {"request": request, "user_id": user_id})


@app.get("/reportes", response_class=HTMLResponse)
def reportes(request: Request, user_id: str = Depends(require_page_user_id)) -> Response:
    return templates.TemplateResponse("reportes.html", {"request": request, "user_id": user_id})


@app.get("/ajustes", response_class=HTMLResponse)
def ajustes(request: Request, user_id: str = Depends(require_page_user_id)) -> Response:
    return templates.TemplateResponse("ajustes.html", {"request": request, "user_id": user_id})


@app.get("/admin", response_class=HTMLResponse)
def admin_page(request: Request, user=Depends(require_page_user_record)) -> Response:
    if role_level(user.role) < role_level(ROLE_ADMIN):
        raise HTTPException(status_code=403, detail="No autorizado")
    return templates.TemplateResponse("admin.html", {"request": request, "user_id": user.id})


@app.get("/api/me")
def api_me(user=Depends(require_user_record)) -> Any:
    return {
        "ok": True,
        "user": {
            "id": user.id,
            "email": user.email,
            "role": user.role,
            "isActive": bool(user.is_active),
            "deletedAt": user.deleted_at,
        },
        "roles": [ROLE_FREE, ROLE_PREMIUM, ROLE_ADMIN, ROLE_SUPER_ADMIN, ROLE_OWNER],
    }


def _api_error(message: str, status_code: int = 400) -> JSONResponse:
    return JSONResponse({"ok": False, "error": message}, status_code=status_code)


def _format_cents_map(values: Any) -> Any:
    out = {}
    for k, v in dict(values).items():
        out[str(k)] = cents_to_str(int(v))
    return out


@app.get("/api/bootstrap")
def api_bootstrap(
    request: Request, user_id: str = Depends(require_user_id), conn=Depends(get_db)
) -> Any:
    company_count = conn.execute(
        "SELECT COUNT(*) as c FROM companies WHERE user_id = ?",
        (user_id,),
    ).fetchone()["c"]
    income_count = conn.execute(
        "SELECT COUNT(*) as c FROM work_entries WHERE user_id = ?",
        (user_id,),
    ).fetchone()["c"]
    expense_count = conn.execute(
        "SELECT COUNT(*) as c FROM expenses WHERE user_id = ?",
        (user_id,),
    ).fetchone()["c"]
    debt_count = conn.execute(
        "SELECT COUNT(*) as c FROM debts WHERE user_id = ?",
        (user_id,),
    ).fetchone()["c"]
    return {
        "ok": True,
        "counts": {
            "companies": int(company_count),
            "incomes": int(income_count),
            "expenses": int(expense_count),
            "debts": int(debt_count),
        },
        "bank": {
            "balanceByCurrency": bank_balance_by_currency(conn, user_id=user_id),
            "supportedCurrencies": sorted(SUPPORTED_CURRENCIES),
        },
    }


@app.get("/api/companies")
def api_list_companies(
    request: Request, user_id: str = Depends(require_user_id), conn=Depends(get_db)
) -> Any:
    rows = conn.execute(
        """
        SELECT id, name, currency, precio_hora_dia_cents, precio_hora_noche_cents,
               irpf_porcentaje, otros_descuentos_cents, pagas_prorrateadas
        FROM companies
        WHERE user_id = ?
        ORDER BY name ASC
        """,
        (user_id,),
    ).fetchall()
    return {
        "ok": True,
        "companies": [
            {
                "id": r["id"],
                "name": r["name"],
                "currency": r["currency"],
                "precioHoraDia": cents_to_str(r["precio_hora_dia_cents"]),
                "precioHoraNoche": cents_to_str(r["precio_hora_noche_cents"]),
                "irpfPorcentaje": r["irpf_porcentaje"],
                "otrosDescuentos": cents_to_str(r["otros_descuentos_cents"]),
                "pagasProrrateadas": bool(r["pagas_prorrateadas"]),
            }
            for r in rows
        ],
    }


@app.post("/api/companies")
async def api_create_company(
    request: Request, user_id: str = Depends(require_user_id), conn=Depends(get_db)
) -> Any:
    body = await request.json()
    try:
        name = str(body.get("name", "")).strip()
        if not name:
            raise ValueError("Nombre obligatorio")
        currency = str(body.get("currency", "EUR")).strip().upper()
        if currency not in SUPPORTED_CURRENCIES:
            raise ValueError("Moneda inválida")
        precio_hora_dia_cents = parse_money_to_cents(str(body.get("precioHoraDia", "")), currency)
        precio_hora_noche_cents = parse_money_to_cents(
            str(body.get("precioHoraNoche", "")), currency
        )
        irpf = float(body.get("irpfPorcentaje", 0))
        if irpf < 0 or irpf > 100:
            raise ValueError("IRPF inválido")
        otros_desc_cents = 0
        if str(body.get("otrosDescuentos", "")).strip():
            otros_desc_cents = parse_money_to_cents(str(body.get("otrosDescuentos")), currency)
        pagas = bool(body.get("pagasProrrateadas", False))
        company_id = new_id()
        conn.execute(
            """
            INSERT INTO companies
              (id, user_id, name, currency, precio_hora_dia_cents, precio_hora_noche_cents,
               irpf_porcentaje, otros_descuentos_cents, pagas_prorrateadas)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                company_id,
                user_id,
                name,
                currency,
                precio_hora_dia_cents,
                precio_hora_noche_cents,
                irpf,
                otros_desc_cents,
                1 if pagas else 0,
            ),
        )
        return {"ok": True, "id": company_id}
    except ValueError as e:
        return _api_error(str(e), 400)
    except Exception:
        return _api_error("No se pudo crear la empresa", 500)


@app.get("/api/expenses")
def api_list_expenses(
    request: Request, user_id: str = Depends(require_user_id), conn=Depends(get_db)
) -> Any:
    rows = conn.execute(
        """
        SELECT id, date, category, concept, amount_cents, currency, afecta_banco
        FROM expenses
        WHERE user_id = ?
        ORDER BY date DESC, created_at DESC
        LIMIT 500
        """,
        (user_id,),
    ).fetchall()
    return {
        "ok": True,
        "expenses": [
            {
                "id": r["id"],
                "date": r["date"],
                "category": r["category"],
                "concept": r["concept"],
                "amount": cents_to_str(r["amount_cents"]),
                "currency": r["currency"],
                "afectaBanco": bool(r["afecta_banco"]),
            }
            for r in rows
        ],
    }


@app.post("/api/expenses")
async def api_create_expense(
    request: Request, user_id: str = Depends(require_user_id), conn=Depends(get_db)
) -> Any:
    body = await request.json()
    try:
        d = parse_date_or_raise(str(body.get("date", "")))
        ensure_month_open(conn, user_id, d)
        category = str(body.get("category", "")).strip()
        concept = str(body.get("concept", "")).strip()
        if not category:
            raise ValueError("Categoría obligatoria")
        if not concept:
            raise ValueError("Concepto obligatorio")
        currency = str(body.get("currency", "EUR")).strip().upper()
        amount_cents = parse_money_to_cents(str(body.get("amount", "")), currency)
        afecta_banco = bool(body.get("afectaBanco", True))

        expense_id = new_id()
        conn.execute(
            """
            INSERT INTO expenses
              (id, user_id, date, category, concept, amount_cents, currency, afecta_banco)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                expense_id,
                user_id,
                d.isoformat(),
                category,
                concept,
                amount_cents,
                currency,
                1 if afecta_banco else 0,
            ),
        )
        if afecta_banco:
            conn.execute(
                """
                INSERT INTO bank_movements
                  (id, user_id, date, type, amount_cents, currency, note, related_expense_id)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                """,
                (
                    new_id(),
                    user_id,
                    d.isoformat(),
                    "gasto",
                    -int(amount_cents),
                    currency,
                    f"{category}: {concept}",
                    expense_id,
                ),
            )
        return {"ok": True, "id": expense_id}
    except ValueError as e:
        return _api_error(str(e), 400)
    except Exception:
        return _api_error("No se pudo crear el gasto", 500)


@app.get("/api/work-entries")
def api_list_work_entries(
    request: Request, user_id: str = Depends(require_user_id), conn=Depends(get_db)
) -> Any:
    rows = conn.execute(
        """
        SELECT w.id, w.company_id, w.date, w.hora_entrada, w.hora_salida, w.descanso_min,
               w.horas_dia, w.horas_noche, w.bonus_cents, w.pluses_cents, w.anticipos_cents,
               w.bruto_dia_cents,
               c.name as company_name, c.currency as currency
        FROM work_entries w
        JOIN companies c ON c.id = w.company_id
        WHERE w.user_id = ?
        ORDER BY w.date DESC, w.created_at DESC
        LIMIT 500
        """,
        (user_id,),
    ).fetchall()
    return {
        "ok": True,
        "entries": [
            {
                "id": r["id"],
                "companyId": r["company_id"],
                "companyName": r["company_name"],
                "date": r["date"],
                "horaEntrada": r["hora_entrada"],
                "horaSalida": r["hora_salida"],
                "descansoMin": r["descanso_min"],
                "horasDia": r["horas_dia"],
                "horasNoche": r["horas_noche"],
                "bonus": cents_to_str(r["bonus_cents"]),
                "pluses": cents_to_str(r["pluses_cents"]),
                "anticipos": cents_to_str(r["anticipos_cents"]),
                "brutoDia": cents_to_str(r["bruto_dia_cents"]),
                "currency": r["currency"],
            }
            for r in rows
        ],
    }


@app.post("/api/work-entries")
async def api_create_work_entry(
    request: Request, user_id: str = Depends(require_user_id), conn=Depends(get_db)
) -> Any:
    body = await request.json()
    try:
        company_id = str(body.get("companyId", "")).strip()
        company = get_company(conn, user_id=user_id, company_id=company_id)
        d = parse_date_or_raise(str(body.get("date", "")))
        ensure_month_open(conn, user_id, d)

        hora_entrada = str(body.get("horaEntrada") or "").strip() or None
        hora_salida = str(body.get("horaSalida") or "").strip() or None
        if hora_entrada and hora_salida and hora_entrada >= hora_salida:
            raise ValueError("Entrada debe ser menor que salida")

        descanso_min = int(body.get("descansoMin") or 0)
        if descanso_min < 0:
            raise ValueError("Descanso inválido")

        horas_dia = float(body.get("horasDia") or 0)
        horas_noche = float(body.get("horasNoche") or 0)
        if horas_dia < 0 or horas_noche < 0:
            raise ValueError("Horas inválidas")

        bonus_cents = 0
        if str(body.get("bonus", "")).strip():
            bonus_cents = parse_money_to_cents(str(body.get("bonus")), company["currency"])
        pluses_cents = 0
        if str(body.get("pluses", "")).strip():
            pluses_cents = parse_money_to_cents(str(body.get("pluses")), company["currency"])
        anticipos_cents = 0
        if str(body.get("anticipos", "")).strip():
            anticipos_cents = parse_money_to_cents(str(body.get("anticipos")), company["currency"])

        bruto_dia = (
            round(horas_dia * int(company["precio_hora_dia_cents"]))
            + round(horas_noche * int(company["precio_hora_noche_cents"]))
            + int(bonus_cents)
            + int(pluses_cents)
        )

        entry_id = new_id()
        conn.execute(
            """
            INSERT INTO work_entries
              (id, user_id, company_id, date, hora_entrada, hora_salida, descanso_min,
               horas_dia, horas_noche, bonus_cents, pluses_cents, anticipos_cents, bruto_dia_cents)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                entry_id,
                user_id,
                company_id,
                d.isoformat(),
                hora_entrada,
                hora_salida,
                descanso_min,
                horas_dia,
                horas_noche,
                bonus_cents,
                pluses_cents,
                anticipos_cents,
                int(bruto_dia),
            ),
        )
        return {"ok": True, "id": entry_id}
    except ValueError as e:
        return _api_error(str(e), 400)
    except Exception:
        return _api_error("No se pudo crear el ingreso", 500)


@app.get("/api/bank/summary")
def api_bank_summary(
    request: Request, user_id: str = Depends(require_user_id), conn=Depends(get_db)
) -> Any:
    balance = bank_balance_by_currency(conn, user_id=user_id)
    rows = conn.execute(
        """
        SELECT id, date, type, amount_cents, currency, note
        FROM bank_movements
        WHERE user_id = ?
        ORDER BY date DESC, created_at DESC
        LIMIT 200
        """,
        (user_id,),
    ).fetchall()
    return {
        "ok": True,
        "balanceByCurrency": balance,
        "movements": [
            {
                "id": r["id"],
                "date": r["date"],
                "type": r["type"],
                "amount": cents_to_str(r["amount_cents"]),
                "currency": r["currency"],
                "note": r["note"],
            }
            for r in rows
        ],
    }


@app.post("/api/months/close")
async def api_close_month(
    request: Request, user_id: str = Depends(require_user_id), conn=Depends(get_db)
) -> Any:
    body = await request.json()
    try:
        year = int(body.get("year"))
        month = int(body.get("month"))
        if year < 2000 or year > 2100 or month < 1 or month > 12:
            raise ValueError("Mes inválido")
        closure_id = close_month(conn, user_id=user_id, year=year, month=month)
        return {"ok": True, "closureId": closure_id}
    except ValueError as e:
        return _api_error(str(e), 400)
    except Exception:
        return _api_error("No se pudo cerrar el mes", 500)


@app.get("/api/reports/monthly")
def api_monthly_report(
    year: int,
    month: int,
    request: Request,
    user_id: str = Depends(require_user_id),
    conn=Depends(get_db),
) -> Any:
    try:
        if year < 2000 or year > 2100 or month < 1 or month > 12:
            raise ValueError("Mes inválido")
        income_by_company = month_income_breakdown(conn, user_id=user_id, year=year, month=month)
        income_net_by_currency = month_income_net_by_currency(
            conn, user_id=user_id, year=year, month=month
        )
        expenses_by_currency = month_expenses_by_currency(
            conn, user_id=user_id, year=year, month=month
        )
        expenses_no_bank_by_currency = month_expenses_not_in_bank_by_currency(
            conn, user_id=user_id, year=year, month=month
        )
        return {
            "ok": True,
            "year": year,
            "month": month,
            "isClosed": is_month_closed(conn, user_id=user_id, year=year, month=month),
            "incomeByCompany": {
                cid: {
                    "companyName": v["companyName"],
                    "currency": v["currency"],
                    "brutoMes": cents_to_str(v["brutoMesCents"]),
                    "irpf": cents_to_str(v["irpfCents"]),
                    "otrosDescuentos": cents_to_str(v["otrosDescuentosCents"]),
                    "netoEstimado": cents_to_str(v["netoEstimadoCents"]),
                    "anticipos": cents_to_str(v["anticiposCents"]),
                    "netoFinal": cents_to_str(v["netoFinalCents"]),
                }
                for cid, v in income_by_company.items()
            },
            "incomeNetByCurrency": _format_cents_map(income_net_by_currency),
            "expensesByCurrency": _format_cents_map(expenses_by_currency),
            "expensesNoBancoByCurrency": _format_cents_map(expenses_no_bank_by_currency),
            "bankBalanceByCurrency": _format_cents_map(
                bank_balance_by_currency(conn, user_id=user_id)
            ),
        }
    except ValueError as e:
        return _api_error(str(e), 400)
    except Exception:
        return _api_error("No se pudo generar el reporte", 500)


@app.get("/api/debts")
def api_list_debts(
    request: Request, user_id: str = Depends(require_user_id), conn=Depends(get_db)
) -> Any:
    debts = conn.execute(
        """
        SELECT id, creditor, total_cents, currency
        FROM debts
        WHERE user_id = ?
        ORDER BY created_at DESC
        """,
        (user_id,),
    ).fetchall()
    out = []
    for d in debts:
        total, remaining = recalc_debt_remaining_cents(conn, user_id=user_id, debt_id=d["id"])
        out.append(
            {
                "id": d["id"],
                "creditor": d["creditor"],
                "currency": d["currency"],
                "total": cents_to_str(total),
                "remaining": cents_to_str(remaining),
                "paid": remaining <= 0,
            }
        )
    return {"ok": True, "debts": out}


@app.post("/api/debts")
async def api_create_debt(
    request: Request, user_id: str = Depends(require_user_id), conn=Depends(get_db)
) -> Any:
    body = await request.json()
    try:
        creditor = str(body.get("creditor", "")).strip()
        if not creditor:
            raise ValueError("Acreedor obligatorio")
        currency = str(body.get("currency", "EUR")).strip().upper()
        if currency not in SUPPORTED_CURRENCIES:
            raise ValueError("Moneda inválida")
        total_cents = parse_money_to_cents(str(body.get("total", "")), currency)
        debt_id = new_id()
        conn.execute(
            """
            INSERT INTO debts (id, user_id, creditor, total_cents, currency)
            VALUES (?, ?, ?, ?, ?)
            """,
            (debt_id, user_id, creditor, total_cents, currency),
        )
        return {"ok": True, "id": debt_id}
    except ValueError as e:
        return _api_error(str(e), 400)
    except Exception:
        return _api_error("No se pudo crear la deuda", 500)


@app.get("/api/debts/{debt_id}/payments")
def api_list_debt_payments(
    debt_id: str, request: Request, user_id: str = Depends(require_user_id), conn=Depends(get_db)
) -> Any:
    rows = conn.execute(
        """
        SELECT id, date, amount_cents
        FROM debt_payments
        WHERE user_id = ? AND debt_id = ?
        ORDER BY date DESC, created_at DESC
        """,
        (user_id, debt_id),
    ).fetchall()
    return {
        "ok": True,
        "payments": [
            {"id": r["id"], "date": r["date"], "amount": cents_to_str(r["amount_cents"])}
            for r in rows
        ],
    }


@app.post("/api/debts/{debt_id}/payments")
async def api_create_debt_payment(
    debt_id: str, request: Request, user_id: str = Depends(require_user_id), conn=Depends(get_db)
) -> Any:
    body = await request.json()
    try:
        d = parse_date_or_raise(str(body.get("date", "")))
        ensure_month_open(conn, user_id, d)
        debt = conn.execute(
            "SELECT id, currency FROM debts WHERE id = ? AND user_id = ?",
            (debt_id, user_id),
        ).fetchone()
        if not debt:
            raise ValueError("Deuda no encontrada")
        currency = debt["currency"]
        amount_cents = parse_money_to_cents(str(body.get("amount", "")), currency)
        payment_id = new_id()
        conn.execute(
            """
            INSERT INTO debt_payments (id, user_id, debt_id, date, amount_cents)
            VALUES (?, ?, ?, ?, ?)
            """,
            (payment_id, user_id, debt_id, d.isoformat(), amount_cents),
        )
        conn.execute(
            """
            INSERT INTO bank_movements
              (id, user_id, date, type, amount_cents, currency, note, related_debt_payment_id)
            VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                new_id(),
                user_id,
                d.isoformat(),
                "pagoDeuda",
                -int(amount_cents),
                currency,
                f"Pago deuda {debt_id}",
                payment_id,
            ),
        )
        return {"ok": True, "id": payment_id}
    except ValueError as e:
        return _api_error(str(e), 400)
    except Exception:
        return _api_error("No se pudo añadir el pago", 500)


@app.get("/api/admin/users")
def api_admin_list_users(
    request: Request, admin=Depends(require_admin_user), conn=Depends(get_db)
) -> Any:
    rows = conn.execute(
        """
        SELECT id, email, role, is_active, deleted_at, created_at
        FROM users
        ORDER BY created_at DESC
        LIMIT 500
        """
    ).fetchall()
    return {
        "ok": True,
        "users": [
            {
                "id": r["id"],
                "email": r["email"],
                "role": r["role"],
                "isActive": bool(r["is_active"]),
                "deletedAt": r["deleted_at"],
                "createdAt": r["created_at"],
            }
            for r in rows
        ],
    }


@app.post("/api/admin/users/{target_user_id}/set-plan")
async def api_admin_set_plan(
    target_user_id: str,
    request: Request,
    admin=Depends(require_admin_user),
    conn=Depends(get_db),
) -> Any:
    body = await request.json()
    desired = str(body.get("role", "")).strip()
    if desired not in (ROLE_FREE, ROLE_PREMIUM):
        return _api_error("Rol inválido para plan", 400)
    if admin.id == target_user_id:
        return _api_error("No puedes cambiar tu propio plan", 400)
    target = get_user(conn, user_id=target_user_id)
    if target.role not in (ROLE_FREE, ROLE_PREMIUM):
        return _api_error("Solo se puede cambiar plan de FREE/PREMIUM", 400)
    ensure_can_manage_user(actor_role=admin.role, target_role=target.role)
    conn.execute(
        """
        UPDATE users
        SET role = ?, updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        WHERE id = ?
        """,
        (desired, target_user_id),
    )
    audit_log(
        conn,
        actor_user_id=admin.id,
        action="admin.setPlan",
        target_user_id=target_user_id,
        changes={"fromRole": target.role, "toRole": desired},
        ip=_client_ip(request),
        user_agent=_user_agent(request),
    )
    return {"ok": True}


@app.post("/api/admin/users/{target_user_id}/suspend")
async def api_admin_suspend_user(
    target_user_id: str,
    request: Request,
    admin=Depends(require_admin_user),
    conn=Depends(get_db),
) -> Any:
    body = await request.json()
    is_active = bool(body.get("isActive", False))
    if admin.id == target_user_id:
        return _api_error("No puedes suspender tu propia cuenta", 400)
    target = get_user(conn, user_id=target_user_id)
    ensure_can_manage_user(actor_role=admin.role, target_role=target.role)
    if target.role == ROLE_OWNER:
        return _api_error("No se puede suspender OWNER desde UI", 400)
    conn.execute(
        """
        UPDATE users
        SET is_active = ?, updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        WHERE id = ?
        """,
        (1 if is_active else 0, target_user_id),
    )
    audit_log(
        conn,
        actor_user_id=admin.id,
        action="admin.setActive",
        target_user_id=target_user_id,
        changes={"fromActive": target.is_active, "toActive": is_active},
        ip=_client_ip(request),
        user_agent=_user_agent(request),
    )
    return {"ok": True}


@app.post("/api/admin/users/{target_user_id}/soft-delete")
async def api_super_admin_soft_delete_user(
    target_user_id: str,
    request: Request,
    super_admin=Depends(require_super_admin_user),
    conn=Depends(get_db),
) -> Any:
    if super_admin.id == target_user_id:
        return _api_error("No puedes eliminar tu propia cuenta", 400)
    target = get_user(conn, user_id=target_user_id)
    if target.role in (ROLE_SUPER_ADMIN, ROLE_OWNER):
        return _api_error("No se puede eliminar SUPER_ADMIN u OWNER", 400)
    ensure_can_manage_user(actor_role=super_admin.role, target_role=target.role)
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    conn.execute(
        """
        UPDATE users
        SET is_active = 0, deleted_at = ?, updated_at = ?
        WHERE id = ?
        """,
        (now, now, target_user_id),
    )
    audit_log(
        conn,
        actor_user_id=super_admin.id,
        action="admin.softDelete",
        target_user_id=target_user_id,
        changes={
            "fromDeletedAt": target.deleted_at,
            "toDeletedAt": now,
            "fromActive": target.is_active,
        },
        ip=_client_ip(request),
        user_agent=_user_agent(request),
    )
    return {"ok": True}


@app.post("/api/admin/users/{target_user_id}/recover")
async def api_super_admin_recover_user(
    target_user_id: str,
    request: Request,
    super_admin=Depends(require_super_admin_user),
    conn=Depends(get_db),
) -> Any:
    target = get_user(conn, user_id=target_user_id)
    ensure_can_manage_user(actor_role=super_admin.role, target_role=target.role)
    conn.execute(
        """
        UPDATE users
        SET is_active = 1, deleted_at = NULL, updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        WHERE id = ?
        """,
        (target_user_id,),
    )
    audit_log(
        conn,
        actor_user_id=super_admin.id,
        action="admin.recover",
        target_user_id=target_user_id,
        changes={"fromDeletedAt": target.deleted_at, "toDeletedAt": None, "toActive": True},
        ip=_client_ip(request),
        user_agent=_user_agent(request),
    )
    return {"ok": True}


@app.post("/api/admin/users/{target_user_id}/set-role")
async def api_admin_set_role(
    target_user_id: str,
    request: Request,
    admin_user=Depends(require_super_admin_user),
    conn=Depends(get_db),
) -> Any:
    body = await request.json()
    desired = str(body.get("role", "")).strip()
    if desired not in (ROLE_FREE, ROLE_PREMIUM, ROLE_ADMIN, ROLE_SUPER_ADMIN, ROLE_OWNER):
        return _api_error("Rol inválido", 400)
    if admin_user.id == target_user_id:
        return _api_error("No puedes cambiar tu propio rol", 400)
    target = get_user(conn, user_id=target_user_id)
    if target.role == ROLE_OWNER:
        return _api_error("No se puede modificar OWNER desde UI", 400)
    if target.role == ROLE_SUPER_ADMIN and admin_user.role != ROLE_OWNER:
        return _api_error("Solo OWNER puede modificar SUPER_ADMIN", 400)
    ensure_can_manage_user(actor_role=admin_user.role, target_role=target.role)
    if admin_user.role == ROLE_SUPER_ADMIN:
        if desired not in (ROLE_FREE, ROLE_PREMIUM, ROLE_ADMIN):
            return _api_error("SUPER_ADMIN no puede asignar SUPER_ADMIN/OWNER", 400)
    if desired == ROLE_OWNER:
        return _api_error("ROLE_OWNER no se asigna desde UI", 400)
    if desired == ROLE_SUPER_ADMIN and admin_user.role != ROLE_OWNER:
        return _api_error("ROLE_SUPER_ADMIN solo lo asigna OWNER", 400)
    conn.execute(
        """
        UPDATE users
        SET role = ?, updated_at = (strftime('%Y-%m-%dT%H:%M:%fZ','now'))
        WHERE id = ?
        """,
        (desired, target_user_id),
    )
    audit_log(
        conn,
        actor_user_id=admin_user.id,
        action="admin.setRole",
        target_user_id=target_user_id,
        changes={"fromRole": target.role, "toRole": desired},
        ip=_client_ip(request),
        user_agent=_user_agent(request),
    )
    return {"ok": True}


@app.post("/api/admin/bootstrap/claim-owner")
async def api_claim_owner(
    request: Request, user=Depends(require_user_record), conn=Depends(get_db)
) -> Any:
    body = await request.json()
    token = str(body.get("token", "")).strip()
    expected = (request.app.state.owner_bootstrap_token or "").strip()
    if (not expected) or token != expected:
        return _api_error("Token inválido", 403)
    owner_count = int(
        conn.execute(
            "SELECT COUNT(*) as c FROM users WHERE role = ?",
            (ROLE_OWNER,),
        ).fetchone()["c"]
    )
    if owner_count >= 2:
        return _api_error("Límite de OWNER alcanzado", 400)
    if user.role == ROLE_OWNER:
        return {"ok": True}
    now = datetime.now(timezone.utc).isoformat().replace("+00:00", "Z")
    conn.execute(
        """
        UPDATE users
        SET role = ?, updated_at = ?
        WHERE id = ?
        """,
        (ROLE_OWNER, now, user.id),
    )
    audit_log(
        conn,
        actor_user_id=user.id,
        action="bootstrap.claimOwner",
        target_user_id=user.id,
        changes={"fromRole": user.role, "toRole": ROLE_OWNER},
        ip=_client_ip(request),
        user_agent=_user_agent(request),
    )
    return {"ok": True}


@app.get("/api/admin/audit")
def api_admin_audit(
    request: Request, super_admin=Depends(require_super_admin_user), conn=Depends(get_db)
) -> Any:
    rows = conn.execute(
        """
        SELECT id, actor_user_id, actor_email, action, target_user_id, target_email,
               changes_json, ip, user_agent, created_at
        FROM audit_logs
        ORDER BY created_at DESC
        LIMIT 500
        """
    ).fetchall()
    return {
        "ok": True,
        "logs": [
            {
                "id": r["id"],
                "actorUserId": r["actor_user_id"],
                "actorEmail": r["actor_email"],
                "action": r["action"],
                "targetUserId": r["target_user_id"],
                "targetEmail": r["target_email"],
                "changesJson": r["changes_json"],
                "ip": r["ip"],
                "userAgent": r["user_agent"],
                "createdAt": r["created_at"],
            }
            for r in rows
        ],
    }


@app.get("/api/premium/projection/annual")
def api_premium_annual_projection(
    year: int, request: Request, premium=Depends(require_premium_user), conn=Depends(get_db)
) -> Any:
    if year < 2000 or year > 2100:
        return _api_error("Año inválido", 400)
    months = []
    total_income: dict[str, int] = {}
    total_expenses: dict[str, int] = {}
    for month in range(1, 13):
        income = month_income_net_by_currency(conn, user_id=premium.id, year=year, month=month)
        expenses = month_expenses_by_currency(conn, user_id=premium.id, year=year, month=month)
        for k, v in income.items():
            total_income[k] = int(total_income.get(k, 0)) + int(v)
        for k, v in expenses.items():
            total_expenses[k] = int(total_expenses.get(k, 0)) + int(v)
        savings = {
            k: int(income.get(k, 0)) - int(expenses.get(k, 0))
            for k in set(income) | set(expenses)
        }
        months.append(
            {
                "month": month,
                "incomeNetByCurrency": _format_cents_map(income),
                "expensesByCurrency": _format_cents_map(expenses),
                "savingsByCurrency": _format_cents_map(savings),
            }
        )
    total_savings = {
        k: int(total_income.get(k, 0)) - int(total_expenses.get(k, 0))
        for k in set(total_income) | set(total_expenses)
    }
    return {
        "ok": True,
        "year": year,
        "months": months,
        "totals": {
            "incomeNetByCurrency": _format_cents_map(total_income),
            "expensesByCurrency": _format_cents_map(total_expenses),
            "savingsByCurrency": _format_cents_map(total_savings),
        },
    }


@app.post("/api/premium/simulate-salary")
async def api_premium_simulate_salary(
    request: Request, premium=Depends(require_premium_user), conn=Depends(get_db)
) -> Any:
    body = await request.json()
    try:
        company_id = str(body.get("companyId", "")).strip()
        company = get_company(conn, user_id=premium.id, company_id=company_id)
        horas_dia = float(body.get("horasDia") or 0)
        horas_noche = float(body.get("horasNoche") or 0)
        if horas_dia < 0 or horas_noche < 0:
            raise ValueError("Horas inválidas")
        currency = str(company["currency"])
        bonus_cents = (
            parse_money_to_cents(str(body.get("bonus", "")), currency)
            if str(body.get("bonus", "")).strip()
            else 0
        )
        pluses_cents = (
            parse_money_to_cents(str(body.get("pluses", "")), currency)
            if str(body.get("pluses", "")).strip()
            else 0
        )
        anticipos_cents = (
            parse_money_to_cents(str(body.get("anticipos", "")), currency)
            if str(body.get("anticipos", "")).strip()
            else 0
        )
        bruto_cents = compute_bruto_dia_cents(
            horas_dia=horas_dia,
            horas_noche=horas_noche,
            precio_hora_dia_cents=int(company["precio_hora_dia_cents"]),
            precio_hora_noche_cents=int(company["precio_hora_noche_cents"]),
            bonus_cents=bonus_cents,
            pluses_cents=pluses_cents,
        )
        irpf_pct = float(company["irpf_porcentaje"] or 0)
        irpf_cents = int(round(bruto_cents * (irpf_pct / 100.0)))
        otros_desc = int(company["otros_descuentos_cents"] or 0)
        neto_estimado = bruto_cents - irpf_cents - otros_desc
        neto_final = neto_estimado - anticipos_cents
        return {
            "ok": True,
            "currency": currency,
            "bruto": cents_to_str(bruto_cents),
            "irpf": cents_to_str(irpf_cents),
            "otrosDescuentos": cents_to_str(otros_desc),
            "anticipos": cents_to_str(anticipos_cents),
            "netoEstimado": cents_to_str(neto_estimado),
            "netoFinal": cents_to_str(neto_final),
        }
    except ValueError as e:
        return _api_error(str(e), 400)
    except Exception:
        return _api_error("No se pudo simular", 500)


@app.get("/api/premium/export/csv")
def api_premium_export_csv(
    request: Request, premium=Depends(require_premium_user), conn=Depends(get_db)
) -> Response:
    today = datetime.now(timezone.utc).date()
    start_raw = request.query_params.get("from")
    end_raw = request.query_params.get("to")
    start = parse_date_or_raise(start_raw) if start_raw else (today - timedelta(days=365))
    end = parse_date_or_raise(end_raw) if end_raw else today
    end_exclusive = (end + timedelta(days=1)).isoformat()

    out = io.StringIO()
    w = csv.writer(out)
    w.writerow(["kind", "date", "currency", "amount", "company", "category", "concept", "note"])

    work_rows = conn.execute(
        """
        SELECT w.date, c.currency, c.name as company_name, w.bruto_dia_cents
        FROM work_entries w
        JOIN companies c ON c.id = w.company_id
        WHERE w.user_id = ? AND w.date >= ? AND w.date < ?
        ORDER BY w.date ASC
        """,
        (premium.id, start.isoformat(), end_exclusive),
    ).fetchall()
    for r in work_rows:
        w.writerow(
            [
                "income_entry",
                r["date"],
                r["currency"],
                cents_to_str(r["bruto_dia_cents"]),
                r["company_name"],
                "",
                "",
                "Bruto día",
            ]
        )

    expense_rows = conn.execute(
        """
        SELECT date, currency, amount_cents, category, concept, afecta_banco
        FROM expenses
        WHERE user_id = ? AND date >= ? AND date < ?
        ORDER BY date ASC
        """,
        (premium.id, start.isoformat(), end_exclusive),
    ).fetchall()
    for r in expense_rows:
        w.writerow(
            [
                "expense",
                r["date"],
                r["currency"],
                cents_to_str(r["amount_cents"]),
                "",
                r["category"],
                r["concept"],
                "Afecta banco" if bool(r["afecta_banco"]) else "No afecta banco",
            ]
        )

    filename = f"mis-finanzas-{start.isoformat()}_{end.isoformat()}.csv"
    return Response(
        content=out.getvalue(),
        media_type="text/csv; charset=utf-8",
        headers={"Content-Disposition": f'attachment; filename="{filename}"'},
    )


@app.get("/api/premium/export/pdf", response_class=HTMLResponse)
def api_premium_export_pdf(
    year: int,
    month: int,
    request: Request,
    premium=Depends(require_premium_user),
    conn=Depends(get_db),
) -> Response:
    if year < 2000 or year > 2100 or month < 1 or month > 12:
        return HTMLResponse(content="Mes inválido", status_code=400)

    income_by_company = month_income_breakdown(conn, user_id=premium.id, year=year, month=month)
    income_net_by_currency = month_income_net_by_currency(
        conn, user_id=premium.id, year=year, month=month
    )
    expenses_by_currency = month_expenses_by_currency(
        conn, user_id=premium.id, year=year, month=month
    )
    expenses_no_bank_by_currency = month_expenses_not_in_bank_by_currency(
        conn, user_id=premium.id, year=year, month=month
    )

    summary_rows = []
    currencies = sorted(
        set(income_net_by_currency) | set(expenses_by_currency) | set(expenses_no_bank_by_currency)
    )
    for cur in currencies:
        summary_rows.append(
            (
                cur,
                cents_to_str(int(income_net_by_currency.get(cur, 0))),
                cents_to_str(int(expenses_by_currency.get(cur, 0))),
                cents_to_str(int(expenses_no_bank_by_currency.get(cur, 0))),
            )
        )

    company_rows = []
    for v in income_by_company.values():
        company_rows.append(
            (
                str(v["companyName"]),
                str(v["currency"]),
                cents_to_str(int(v["brutoMesCents"])),
                cents_to_str(int(v["irpfCents"])),
                cents_to_str(int(v["otrosDescuentosCents"])),
                cents_to_str(int(v["anticiposCents"])),
                cents_to_str(int(v["netoFinalCents"])),
            )
        )

    title = f"MIS FINANZAS — Reporte {year:04d}-{month:02d}"
    generated_at = datetime.now(timezone.utc).isoformat()
    summary_tbody = "".join(
        (
            "<tr>"
            f"<td>{html.escape(cur)}</td>"
            f"<td>{html.escape(i)}</td>"
            f"<td>{html.escape(e)}</td>"
            f"<td>{html.escape(enb)}</td>"
            "</tr>"
        )
        for (cur, i, e, enb) in summary_rows
    )
    company_tbody = "".join(
        (
            "<tr>"
            f"<td>{html.escape(name)}</td>"
            f"<td>{html.escape(cur)}</td>"
            f"<td>{html.escape(b)}</td>"
            f"<td>{html.escape(irpf)}</td>"
            f"<td>{html.escape(od)}</td>"
            f"<td>{html.escape(a)}</td>"
            f"<td>{html.escape(nf)}</td>"
            "</tr>"
        )
        for (name, cur, b, irpf, od, a, nf) in company_rows
    )
    html_out = f"""
    <!doctype html>
    <html lang="es">
      <head>
        <meta charset="utf-8" />
        <meta name="viewport" content="width=device-width,initial-scale=1" />
        <title>{html.escape(title)}</title>
        <style>
          body {{ font-family: system-ui, -apple-system, Segoe UI, Roboto, Arial, sans-serif; }}
          body {{ padding: 24px; }}
          h1 {{ margin: 0 0 8px; font-size: 20px; }}
          .muted {{ color: #666; font-size: 12px; }}
          table {{ width: 100%; border-collapse: collapse; margin-top: 12px; }}
          th, td {{ border: 1px solid #ddd; padding: 8px; font-size: 12px; text-align: left; }}
          th {{ background: #f6f6f6; }}
          .section {{ margin-top: 18px; }}
        </style>
      </head>
      <body>
        <h1>{html.escape(title)}</h1>
        <div class="muted">
          Usuario: {html.escape(premium.email)} · Generado: {html.escape(generated_at)}
        </div>

        <div class="section">
          <h2 style="font-size:14px;margin:0;">Resumen por moneda</h2>
          <table>
            <thead>
              <tr>
                <th>Moneda</th>
                <th>Ingresos (neto)</th>
                <th>Gastos (total)</th>
                <th>Gastos (no banco)</th>
              </tr>
            </thead>
            <tbody>
              {summary_tbody}
            </tbody>
          </table>
        </div>

        <div class="section">
          <h2 style="font-size:14px;margin:0;">Ingresos por empresa</h2>
          <table>
            <thead>
              <tr>
                <th>Empresa</th>
                <th>Moneda</th>
                <th>Bruto mes</th>
                <th>IRPF</th>
                <th>Otros desc.</th>
                <th>Anticipos</th>
                <th>Neto final</th>
              </tr>
            </thead>
            <tbody>
              {company_tbody}
            </tbody>
          </table>
        </div>
      </body>
    </html>
    """
    return HTMLResponse(content=html_out)
