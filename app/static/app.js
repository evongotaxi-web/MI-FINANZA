const DB_NAME = "mis_finanzas_cache";
const DB_VERSION = 1;
const STORE = "cache";

function openCacheDb() {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(DB_NAME, DB_VERSION);
    req.onupgradeneeded = () => {
      const db = req.result;
      if (!db.objectStoreNames.contains(STORE)) {
        db.createObjectStore(STORE, { keyPath: "key" });
      }
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function cacheGet(key) {
  try {
    const db = await openCacheDb();
    return await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readonly");
      const store = tx.objectStore(STORE);
      const req = store.get(key);
      req.onsuccess = () => resolve(req.result?.data ?? null);
      req.onerror = () => reject(req.error);
    });
  } catch {
    return null;
  }
}

async function cacheSet(key, data) {
  try {
    const db = await openCacheDb();
    await new Promise((resolve, reject) => {
      const tx = db.transaction(STORE, "readwrite");
      const store = tx.objectStore(STORE);
      store.put({ key, data, updatedAt: Date.now() });
      tx.oncomplete = () => resolve(null);
      tx.onerror = () => reject(tx.error);
    });
  } catch {}
}

function $(sel) {
  return document.querySelector(sel);
}

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [k, v] of Object.entries(attrs)) {
    if (k === "class") node.className = v;
    else if (k.startsWith("on") && typeof v === "function") node.addEventListener(k.slice(2), v);
    else if (v === false || v === null || v === undefined) continue;
    else node.setAttribute(k, String(v));
  }
  for (const c of children) {
    if (c === null || c === undefined) continue;
    node.appendChild(typeof c === "string" ? document.createTextNode(c) : c);
  }
  return node;
}

function render(root, children) {
  root.innerHTML = "";
  for (const c of children) root.appendChild(c);
}

function formatMoney(amountStr, currency) {
  const n = Number(String(amountStr || "0").replace(",", "."));
  const value = Number.isFinite(n) ? n : 0;
  try {
    return new Intl.NumberFormat("es-ES", {
      style: "currency",
      currency: String(currency || "EUR"),
      maximumFractionDigits: 2,
    }).format(value);
  } catch {
    return `${amountStr} ${currency}`;
  }
}

function formatCentsNumber(cents) {
  return (Number(cents) / 100).toFixed(2);
}

const ROLE_LEVEL = {
  ROLE_FREE: 10,
  ROLE_PREMIUM: 20,
  ROLE_ADMIN: 30,
  ROLE_SUPER_ADMIN: 40,
  ROLE_OWNER: 50,
};

let CURRENT_USER = null;

function roleLevel(role) {
  return ROLE_LEVEL[String(role || "")] || 0;
}

function updateNavVisibility() {
  const adminLinks = document.querySelectorAll('[data-nav="admin"]');
  adminLinks.forEach((a) => {
    a.style.display = roleLevel(CURRENT_USER?.role) >= ROLE_LEVEL.ROLE_ADMIN ? "" : "none";
  });
}

async function fetchJson(url, opts = {}) {
  const ctrl = new AbortController();
  const timeout = setTimeout(() => ctrl.abort(), 12000);
  try {
    const res = await fetch(url, {
      ...opts,
      headers: { "Content-Type": "application/json", ...(opts.headers || {}) },
      signal: ctrl.signal,
    });
    const json = await res.json().catch(() => null);
    if (!res.ok) {
      const msg = json?.error || `Error ${res.status}`;
      throw new Error(msg);
    }
    if (json && json.ok === false) throw new Error(json.error || "Error");
    return json;
  } finally {
    clearTimeout(timeout);
  }
}

async function initMe() {
  try {
    const me = await fetchJson("/api/me");
    CURRENT_USER = me.user || null;
  } catch {
    CURRENT_USER = null;
  }
  updateNavVisibility();
}

function setActiveNav() {
  const path = window.location.pathname.replace("/", "") || "dashboard";
  document.querySelectorAll(".nav-item").forEach((a) => {
    a.classList.toggle("active", a.dataset.nav === path);
  });
}

function alertNode(message, kind = "error") {
  const cls = kind === "error" ? "alert alert-error" : "alert";
  return el("div", { class: cls }, [message]);
}

function emptyStateNode() {
  return el("div", { class: "card" }, [
    el("div", { class: "card-title" }, ["Aún no tienes datos"]),
    el("div", { class: "muted" }, [
      "Añade tu primer ingreso o gasto para comenzar.",
    ]),
    el("div", { class: "btn-row", style: "margin-top:12px" }, [
      el(
        "a",
        { class: "btn", href: "/ingresos?action=first-income" },
        ["Añadir primer ingreso"]
      ),
      el(
        "a",
        { class: "btn btn-ghost", href: "/gastos?action=first-expense" },
        ["Añadir primer gasto"]
      ),
      el(
        "a",
        { class: "btn btn-ghost", href: "/ingresos?action=create-company" },
        ["Crear empresa"]
      ),
    ]),
  ]);
}

async function initDashboard() {
  const root = $("#dashboard-root");
  if (!root) return;

  const { year, month } = currentYearMonth();
  const cacheKey = `dashboard:${year}-${month}`;
  const cached = await cacheGet(cacheKey);
  if (cached?.bootstrap) renderDashboard(root, cached);
  else render(root, [el("div", { class: "muted" }, ["Cargando…"])]);

  try {
    const [bootstrap, report] = await Promise.all([
      fetchJson("/api/bootstrap"),
      fetchJson(`/api/reports/monthly?year=${year}&month=${month}`),
    ]);
    const fresh = { bootstrap, report };
    await cacheSet("bootstrap", bootstrap);
    await cacheSet(cacheKey, fresh);
    renderDashboard(root, fresh);
  } catch (e) {
    if (!cached) render(root, [alertNode(e.message)]);
  }
}

function doubleConfirm(message) {
  if (!confirm(message)) return false;
  return confirm("Confirmación final: ¿seguro?");
}

async function initAdmin() {
  const root = $("#admin-root");
  if (!root) return;

  render(root, [el("div", { class: "muted" }, ["Cargando…"])]);
  try {
    const me = CURRENT_USER ? { user: CURRENT_USER } : await fetchJson("/api/me");
    CURRENT_USER = me.user || CURRENT_USER;
    updateNavVisibility();
  } catch {}

  async function refresh() {
    const usersRes = await fetchJson("/api/admin/users");
    let logsRes = null;
    if (roleLevel(CURRENT_USER?.role) >= ROLE_LEVEL.ROLE_SUPER_ADMIN) {
      logsRes = await fetchJson("/api/admin/audit");
    }
    renderAdmin(root, usersRes.users || [], logsRes?.logs || []);
  }

  function renderAdmin(root, users, logs) {
    const role = String(CURRENT_USER?.role || "");
    const canSetRole = roleLevel(role) >= ROLE_LEVEL.ROLE_SUPER_ADMIN;
    const isOwner = role === "ROLE_OWNER";

    const rows = users.map((u) => {
      const isSelf = u.id === CURRENT_USER?.id;
      const roleCell = el("div", { class: "muted" }, [u.role]);
      const planSelect = el(
        "select",
        { class: "select", disabled: isSelf || !["ROLE_FREE", "ROLE_PREMIUM"].includes(u.role) },
        [
          el("option", { value: "ROLE_FREE", selected: u.role === "ROLE_FREE" }, ["ROLE_FREE"]),
          el("option", { value: "ROLE_PREMIUM", selected: u.role === "ROLE_PREMIUM" }, ["ROLE_PREMIUM"]),
        ]
      );
      planSelect.addEventListener("change", async () => {
        if (!doubleConfirm(`Cambiar plan de ${u.email} a ${planSelect.value}?`)) {
          planSelect.value = u.role;
          return;
        }
        await fetchJson(`/api/admin/users/${u.id}/set-plan`, {
          method: "POST",
          body: JSON.stringify({ role: planSelect.value }),
        });
        await refresh();
      });

      const activeToggle = el("input", { type: "checkbox" });
      activeToggle.checked = Boolean(u.isActive);
      activeToggle.disabled = isSelf || u.role === "ROLE_OWNER" || Boolean(u.deletedAt);
      activeToggle.addEventListener("change", async () => {
        if (!doubleConfirm(`${activeToggle.checked ? "Activar" : "Suspender"} a ${u.email}?`)) {
          activeToggle.checked = !activeToggle.checked;
          return;
        }
        await fetchJson(`/api/admin/users/${u.id}/suspend`, {
          method: "POST",
          body: JSON.stringify({ isActive: activeToggle.checked }),
        });
        await refresh();
      });

      const roleSelect = el(
        "select",
        { class: "select", disabled: !canSetRole || isSelf || u.role === "ROLE_OWNER" },
        [
          el("option", { value: "ROLE_FREE", selected: u.role === "ROLE_FREE" }, ["ROLE_FREE"]),
          el("option", { value: "ROLE_PREMIUM", selected: u.role === "ROLE_PREMIUM" }, ["ROLE_PREMIUM"]),
          el("option", { value: "ROLE_ADMIN", selected: u.role === "ROLE_ADMIN" }, ["ROLE_ADMIN"]),
          ...(isOwner
            ? [el("option", { value: "ROLE_SUPER_ADMIN", selected: u.role === "ROLE_SUPER_ADMIN" }, ["ROLE_SUPER_ADMIN"])]
            : []),
        ]
      );
      roleSelect.addEventListener("change", async () => {
        if (!doubleConfirm(`Cambiar rol de ${u.email} a ${roleSelect.value}?`)) {
          roleSelect.value = u.role;
          return;
        }
        await fetchJson(`/api/admin/users/${u.id}/set-role`, {
          method: "POST",
          body: JSON.stringify({ role: roleSelect.value }),
        });
        await refresh();
      });

      const deleteBtn = el(
        "button",
        { class: "btn btn-ghost", type: "button", disabled: !canSetRole || isSelf || u.role === "ROLE_OWNER" },
        ["Soft delete"]
      );
      deleteBtn.addEventListener("click", async () => {
        if (!doubleConfirm(`Soft delete de ${u.email}? Mantiene datos y bloquea login.`)) return;
        await fetchJson(`/api/admin/users/${u.id}/soft-delete`, { method: "POST", body: "{}" });
        await refresh();
      });

      const recoverBtn = el(
        "button",
        { class: "btn btn-ghost", type: "button", disabled: !canSetRole || u.role === "ROLE_OWNER" },
        ["Recuperar"]
      );
      recoverBtn.addEventListener("click", async () => {
        if (!doubleConfirm(`Recuperar cuenta ${u.email}?`)) return;
        await fetchJson(`/api/admin/users/${u.id}/recover`, { method: "POST", body: "{}" });
        await refresh();
      });

      return el("tr", {}, [
        el("td", {}, [u.email]),
        el("td", {}, [roleCell]),
        el("td", {}, [planSelect]),
        el("td", {}, [activeToggle]),
        el("td", {}, [String(u.deletedAt || "")]),
        el("td", {}, [roleSelect]),
        el("td", {}, [el("div", { class: "btn-row" }, [deleteBtn, recoverBtn])]),
      ]);
    });

    const usersTable = el("table", { class: "table" }, [
      el("thead", {}, [
        el("tr", {}, [
          el("th", {}, ["Email"]),
          el("th", {}, ["Rol"]),
          el("th", {}, ["Plan"]),
          el("th", {}, ["Activo"]),
          el("th", {}, ["DeletedAt"]),
          el("th", {}, ["Asignar rol"]),
          el("th", {}, ["Acciones"]),
        ]),
      ]),
      el("tbody", {}, rows),
    ]);

    const claimOwnerCard = el("div", { class: "card" }, [
      el("div", { class: "card-title" }, ["Bootstrap OWNER"]),
      el("div", { class: "muted" }, ["Solo si tienes el token de arranque."]),
      el("div", { class: "btn-row", style: "margin-top:12px" }, [
        el("input", { class: "input", placeholder: "TOKEN", id: "owner-token" }),
        el(
          "button",
          {
            class: "btn",
            type: "button",
            onclick: async () => {
              const token = $("#owner-token")?.value || "";
              if (!doubleConfirm("Convertir esta cuenta en OWNER?")) return;
              await fetchJson("/api/admin/bootstrap/claim-owner", {
                method: "POST",
                body: JSON.stringify({ token }),
              });
              window.location.reload();
            },
          },
          ["Claim"]
        ),
      ]),
    ]);

    const cards = [el("section", { class: "card" }, [el("div", { class: "card-title" }, ["Usuarios"]), usersTable])];
    if (roleLevel(role) >= ROLE_LEVEL.ROLE_SUPER_ADMIN) {
      const logRows = logs.map((l) =>
        el("tr", {}, [
          el("td", {}, [l.createdAt]),
          el("td", {}, [l.actorEmail || ""]),
          el("td", {}, [l.action]),
          el("td", {}, [l.targetEmail || ""]),
          el("td", {}, [String(l.changesJson || "")]),
        ])
      );
      cards.push(
        el("section", { class: "card" }, [
          el("div", { class: "card-title" }, ["Auditoría"]),
          el("table", { class: "table" }, [
            el("thead", {}, [el("tr", {}, [el("th", {}, ["Fecha"]), el("th", {}, ["Actor"]), el("th", {}, ["Acción"]), el("th", {}, ["Objetivo"]), el("th", {}, ["Cambios"])])]),
            el("tbody", {}, logRows),
          ]),
        ])
      );
    }
    render(root, [claimOwnerCard, ...cards]);
  }

  await refresh();
}

function monthLabelEs(year, month) {
  const months = ["Ene", "Feb", "Mar", "Abr", "May", "Jun", "Jul", "Ago", "Sep", "Oct", "Nov", "Dic"];
  const m = months[Math.max(1, Math.min(12, Number(month))) - 1] || "";
  return `${m} ${year}`;
}

function amountStrToCents(amountStr) {
  const n = Number(String(amountStr || "0").replace(",", "."));
  if (!Number.isFinite(n)) return 0;
  return Math.round(n * 100);
}

function centsToAmountStr(cents) {
  return (Number(cents || 0) / 100).toFixed(2);
}

function pickCurrency(maps) {
  for (const m of maps) {
    if (m && typeof m === "object" && m.EUR !== undefined) return "EUR";
  }
  for (const m of maps) {
    if (m && typeof m === "object") {
      const keys = Object.keys(m);
      if (keys.length) return keys[0];
    }
  }
  return "EUR";
}

async function closeCurrentMonthAndRefresh(root) {
  const { year, month } = currentYearMonth();
  if (!doubleConfirm(`¿Cerrar el mes ${monthLabelEs(year, month)}?`)) return;
  await fetchJson("/api/months/close", { method: "POST", body: JSON.stringify({ year, month }) });
  const [bootstrap, report] = await Promise.all([
    fetchJson("/api/bootstrap"),
    fetchJson(`/api/reports/monthly?year=${year}&month=${month}`),
  ]);
  const fresh = { bootstrap, report };
  await cacheSet("bootstrap", bootstrap);
  await cacheSet(`dashboard:${year}-${month}`, fresh);
  await cacheSet("bankSummary", await fetchJson("/api/bank/summary"));
  renderDashboard(root, fresh);
}

function renderDashboard(root, data) {
  const bootstrap = data.bootstrap || data || {};
  const report = data.report || null;
  const c = bootstrap.counts || {};
  const isEmpty =
    (c.companies || 0) === 0 && (c.incomes || 0) === 0 && (c.expenses || 0) === 0 && (c.debts || 0) === 0;

  const { year, month } = currentYearMonth();
  const bankMap = report?.bankBalanceByCurrency || bootstrap.bank?.balanceByCurrency || {};
  const incomeMap = report?.incomeNetByCurrency || {};
  const expensesMap = report?.expensesByCurrency || {};
  const currency = pickCurrency([bankMap, incomeMap, expensesMap]);

  const bankCents =
    typeof bankMap?.[currency] === "string" ? amountStrToCents(bankMap[currency]) : Number(bankMap?.[currency] || 0);
  const incomeCents = amountStrToCents(incomeMap?.[currency] || "0");
  const expensesCents = amountStrToCents(expensesMap?.[currency] || "0");
  const beneficioCents = incomeCents - expensesCents;

  const progressPct = incomeCents > 0 ? Math.max(0, Math.min(100, Math.round((expensesCents / incomeCents) * 100))) : 0;

  const cardBanco = el("section", { class: "card" }, [
    el("div", { class: "metric-title" }, [
      "En Banco",
      el("span", { class: "chip" }, [monthLabelEs(year, month)]),
    ]),
    el("div", { class: "metric-value" }, [formatMoney(centsToAmountStr(bankCents), currency)]),
    el("div", { class: "progress" }, [el("div", { style: `width:${progressPct}%` }, [])]),
  ]);

  const beneficioChipClass = beneficioCents >= 0 ? "chip chip-pos" : "chip chip-neg";
  const beneficioSign = beneficioCents >= 0 ? "+" : "";
  const cardBeneficio = el("section", { class: "card" }, [
    el("div", { class: "metric-title" }, ["Beneficio Mes Actual", el("span", { class: beneficioChipClass }, [`${beneficioSign}${formatMoney(centsToAmountStr(beneficioCents), currency)}`])]),
    el("div", { class: "metric-value" }, [formatMoney(centsToAmountStr(beneficioCents), currency)]),
  ]);

  const cardGastos = el("section", { class: "card" }, [
    el("div", { class: "metric-title" }, [
      "Gastos del Mes",
      el("span", { class: "chip chip-neg" }, [`-${formatMoney(centsToAmountStr(expensesCents), currency)}`]),
    ]),
    el("div", { class: "metric-value" }, [formatMoney(centsToAmountStr(expensesCents), currency)]),
  ]);

  const isClosed = Boolean(report?.isClosed);
  const closeBtn = el(
    "button",
    { class: "btn btn-primary btn-lg close-card-btn", type: "button", disabled: isClosed },
    [el("span", { class: "icon", "data-icon": "logout", style: "transform: rotate(180deg)" }, []), isClosed ? "Mes Cerrado" : "Cerrar Mes"]
  );
  closeBtn.addEventListener("click", async () => {
    try {
      closeBtn.disabled = true;
      await closeCurrentMonthAndRefresh(root);
    } catch (e) {
      closeBtn.disabled = false;
      alert(e.message);
    }
  });

  const cardCerrar = el("section", { class: "card" }, [
    el("div", { class: "metric-title" }, ["Cerrar Mes", el("span", { class: "chip" }, [isClosed ? "Cerrado" : "Abierto"])]),
    closeBtn,
  ]);

  const cards = [cardBanco, cardBeneficio, cardGastos, cardCerrar];
  if (isEmpty) cards.push(el("section", { class: "card" }, [emptyStateNode()]));
  render(root, [el("div", { class: "dashboard-grid" }, cards)]);
}

function todayIso() {
  const d = new Date();
  const pad = (n) => String(n).padStart(2, "0");
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function currentYearMonth() {
  const d = new Date();
  return { year: d.getFullYear(), month: d.getMonth() + 1 };
}

function initMonthPill() {
  const pill = $("#month-pill");
  if (!pill) return;
  const { year, month } = currentYearMonth();
  pill.textContent = monthLabelEs(year, month);
}

async function initCompaniesAndWorkEntries() {
  const companiesRoot = $("#companies-root");
  const entriesRoot = $("#work-entries-root");
  if (!companiesRoot || !entriesRoot) return;

  const cachedCompanies = await cacheGet("companies");
  if (cachedCompanies?.companies) renderCompanies(companiesRoot, cachedCompanies.companies);

  const cachedEntries = await cacheGet("workEntries");
  if (cachedEntries?.entries) renderWorkEntries(entriesRoot, cachedEntries.entries, cachedCompanies?.companies || []);

  try {
    const companies = await fetchJson("/api/companies");
    await cacheSet("companies", companies);
    renderCompanies(companiesRoot, companies.companies);

    const entries = await fetchJson("/api/work-entries");
    await cacheSet("workEntries", entries);
    renderWorkEntries(entriesRoot, entries.entries, companies.companies);
  } catch (e) {
    if (!cachedCompanies) render(companiesRoot, [alertNode(e.message)]);
    if (!cachedEntries) render(entriesRoot, [alertNode(e.message)]);
  }
}

function renderCompanies(root, companies) {
  const currencyOptions = ["EUR", "XAF"];

  const form = el("form", { class: "form" }, [
    el("div", { class: "row" }, [
      el("label", { class: "label col-12" }, [
        "Nombre",
        el("input", { class: "input", name: "name", required: true }),
      ]),
      el("label", { class: "label col-4" }, [
        "Moneda",
        el(
          "select",
          { class: "select", name: "currency" },
          currencyOptions.map((c) => el("option", { value: c }, [c]))
        ),
      ]),
      el("label", { class: "label col-4" }, [
        "Precio hora día",
        el("input", { class: "input", name: "precioHoraDia", inputmode: "decimal", required: true, placeholder: "0.00" }),
      ]),
      el("label", { class: "label col-4" }, [
        "Precio hora noche",
        el("input", { class: "input", name: "precioHoraNoche", inputmode: "decimal", required: true, placeholder: "0.00" }),
      ]),
      el("label", { class: "label col-4" }, [
        "IRPF %",
        el("input", { class: "input", name: "irpfPorcentaje", inputmode: "decimal", value: "0" }),
      ]),
      el("label", { class: "label col-4" }, [
        "Otros descuentos",
        el("input", { class: "input", name: "otrosDescuentos", inputmode: "decimal", placeholder: "0.00" }),
      ]),
      el("label", { class: "label col-4" }, [
        el("span", {}, ["Pagas prorrateadas"]),
        el("select", { class: "select", name: "pagasProrrateadas" }, [
          el("option", { value: "false" }, ["No"]),
          el("option", { value: "true" }, ["Sí"]),
        ]),
      ]),
    ]),
    el("button", { class: "btn", type: "submit" }, ["Crear empresa"]),
  ]);

  const status = el("div", { class: "muted" }, []);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    status.textContent = "";
    const fd = new FormData(form);
    const payload = Object.fromEntries(fd.entries());
    payload.pagasProrrateadas = payload.pagasProrrateadas === "true";
    try {
      await fetchJson("/api/companies", { method: "POST", body: JSON.stringify(payload) });
      const companiesRes = await fetchJson("/api/companies");
      await cacheSet("companies", companiesRes);
      renderCompanies(root, companiesRes.companies);
      const entriesRes = await fetchJson("/api/work-entries");
      await cacheSet("workEntries", entriesRes);
      const entriesRoot = $("#work-entries-root");
      if (entriesRoot) renderWorkEntries(entriesRoot, entriesRes.entries, companiesRes.companies);
    } catch (e) {
      status.textContent = e.message;
    }
  });

  const table = el("table", { class: "table" }, [
    el("thead", {}, [
      el("tr", {}, [
        el("th", {}, ["Empresa"]),
        el("th", {}, ["Moneda"]),
        el("th", {}, ["Día"]),
        el("th", {}, ["Noche"]),
        el("th", {}, ["IRPF %"]),
      ]),
    ]),
    el("tbody", {}, companies.map((c) =>
      el("tr", {}, [
        el("td", {}, [c.name]),
        el("td", {}, [c.currency]),
        el("td", {}, [c.precioHoraDia]),
        el("td", {}, [c.precioHoraNoche]),
        el("td", {}, [String(c.irpfPorcentaje)]),
      ])
    )),
  ]);

  render(root, [form, status, el("div", { style: "height:10px" }, []), table]);
}

function renderWorkEntries(root, entries, companies) {
  const companyOptions = companies.map((c) => el("option", { value: c.id }, [c.name]));

  const form = el("form", { class: "form" }, [
    el("div", { class: "row" }, [
      el("label", { class: "label col-4" }, [
        "Empresa",
        el("select", { class: "select", name: "companyId", required: true }, companyOptions),
      ]),
      el("label", { class: "label col-4" }, [
        "Fecha",
        el("input", { class: "input", name: "date", type: "date", value: todayIso(), required: true }),
      ]),
      el("label", { class: "label col-4" }, [
        "Descanso (min)",
        el("input", { class: "input", name: "descansoMin", type: "number", min: "0", value: "0" }),
      ]),
      el("label", { class: "label col-3" }, [
        "Entrada",
        el("input", { class: "input", name: "horaEntrada", type: "time" }),
      ]),
      el("label", { class: "label col-3" }, [
        "Salida",
        el("input", { class: "input", name: "horaSalida", type: "time" }),
      ]),
      el("label", { class: "label col-3" }, [
        "Horas día",
        el("input", { class: "input", name: "horasDia", inputmode: "decimal", value: "0" }),
      ]),
      el("label", { class: "label col-3" }, [
        "Horas noche",
        el("input", { class: "input", name: "horasNoche", inputmode: "decimal", value: "0" }),
      ]),
      el("label", { class: "label col-4" }, [
        "Bonus",
        el("input", { class: "input", name: "bonus", inputmode: "decimal", placeholder: "0.00" }),
      ]),
      el("label", { class: "label col-4" }, [
        "Pluses",
        el("input", { class: "input", name: "pluses", inputmode: "decimal", placeholder: "0.00" }),
      ]),
      el("label", { class: "label col-4" }, [
        "Anticipos",
        el("input", { class: "input", name: "anticipos", inputmode: "decimal", placeholder: "0.00" }),
      ]),
    ]),
    el("button", { class: "btn", type: "submit", disabled: companies.length === 0 }, [
      companies.length === 0 ? "Crea una empresa primero" : "Añadir ingreso",
    ]),
  ]);

  const status = el("div", { class: "muted" }, []);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    status.textContent = "";
    const fd = new FormData(form);
    const payload = Object.fromEntries(fd.entries());
    try {
      await fetchJson("/api/work-entries", { method: "POST", body: JSON.stringify(payload) });
      const entriesRes = await fetchJson("/api/work-entries");
      await cacheSet("workEntries", entriesRes);
      renderWorkEntries(root, entriesRes.entries, companies);
    } catch (e) {
      status.textContent = e.message;
    }
  });

  const table = el("table", { class: "table" }, [
    el("thead", {}, [
      el("tr", {}, [
        el("th", {}, ["Fecha"]),
        el("th", {}, ["Empresa"]),
        el("th", {}, ["Bruto día"]),
        el("th", {}, ["Horas (D/N)"]),
        el("th", {}, ["Bonus"]),
        el("th", {}, ["Pluses"]),
        el("th", {}, ["Anticipos"]),
      ]),
    ]),
    el("tbody", {}, entries.map((it) =>
      el("tr", {}, [
        el("td", {}, [it.date]),
        el("td", {}, [it.companyName]),
        el("td", {}, [formatMoney(it.brutoDia, it.currency)]),
        el("td", {}, [`${it.horasDia} / ${it.horasNoche}`]),
        el("td", {}, [formatMoney(it.bonus, it.currency)]),
        el("td", {}, [formatMoney(it.pluses, it.currency)]),
        el("td", {}, [formatMoney(it.anticipos, it.currency)]),
      ])
    )),
  ]);

  render(root, [form, status, el("div", { style: "height:10px" }, []), table]);
}

async function initExpenses() {
  const formRoot = $("#expense-form-root");
  const listRoot = $("#expenses-root");
  if (!formRoot || !listRoot) return;

  const cached = await cacheGet("expenses");
  if (cached?.expenses) renderExpenses(listRoot, cached.expenses);

  renderExpenseForm(formRoot, async () => {
    const fresh = await fetchJson("/api/expenses");
    await cacheSet("expenses", fresh);
    renderExpenses(listRoot, fresh.expenses);
  });

  try {
    const fresh = await fetchJson("/api/expenses");
    await cacheSet("expenses", fresh);
    renderExpenses(listRoot, fresh.expenses);
  } catch (e) {
    if (!cached) render(listRoot, [alertNode(e.message)]);
  }
}

function renderExpenseForm(root, onCreated) {
  const form = el("form", { class: "form" }, [
    el("div", { class: "row" }, [
      el("label", { class: "label col-4" }, [
        "Fecha",
        el("input", { class: "input", name: "date", type: "date", value: todayIso(), required: true }),
      ]),
      el("label", { class: "label col-4" }, [
        "Moneda",
        el("select", { class: "select", name: "currency" }, [
          el("option", { value: "EUR" }, ["EUR"]),
          el("option", { value: "XAF" }, ["XAF"]),
        ]),
      ]),
      el("label", { class: "label col-4" }, [
        "Importe",
        el("input", { class: "input", name: "amount", inputmode: "decimal", required: true, placeholder: "0.00" }),
      ]),
      el("label", { class: "label col-6" }, [
        "Categoría",
        el("input", { class: "input", name: "category", required: true }),
      ]),
      el("label", { class: "label col-6" }, [
        "Concepto",
        el("input", { class: "input", name: "concept", required: true }),
      ]),
      el("label", { class: "label col-12" }, [
        "Afecta banco",
        el("select", { class: "select", name: "afectaBanco" }, [
          el("option", { value: "true" }, ["Sí (resta del saldo)"]),
          el("option", { value: "false" }, ["No"]),
        ]),
      ]),
    ]),
    el("button", { class: "btn", type: "submit" }, ["Añadir gasto"]),
  ]);

  const status = el("div", { class: "muted" }, []);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    status.textContent = "";
    const fd = new FormData(form);
    const payload = Object.fromEntries(fd.entries());
    payload.afectaBanco = payload.afectaBanco === "true";
    try {
      await fetchJson("/api/expenses", { method: "POST", body: JSON.stringify(payload) });
      await onCreated();
      const bank = await fetchJson("/api/bank/summary");
      await cacheSet("bankSummary", bank);
      const balanceRoot = $("#bank-balance-root");
      const movementsRoot = $("#bank-movements-root");
      if (balanceRoot && movementsRoot) {
        renderBankBalance(balanceRoot, bank.balanceByCurrency);
        renderBankMovements(movementsRoot, bank.movements);
      }
      form.reset();
      form.querySelector('[name="date"]').value = todayIso();
      form.querySelector('[name="afectaBanco"]').value = "true";
      form.querySelector('[name="currency"]').value = "EUR";
    } catch (e) {
      status.textContent = e.message;
    }
  });

  render(root, [form, status]);
}

function renderExpenses(root, expenses) {
  const table = el("table", { class: "table" }, [
    el("thead", {}, [
      el("tr", {}, [
        el("th", {}, ["Fecha"]),
        el("th", {}, ["Categoría"]),
        el("th", {}, ["Concepto"]),
        el("th", {}, ["Importe"]),
        el("th", {}, ["Banco"]),
      ]),
    ]),
    el("tbody", {}, expenses.map((g) =>
      el("tr", {}, [
        el("td", {}, [g.date]),
        el("td", {}, [g.category]),
        el("td", {}, [g.concept]),
        el("td", {}, [formatMoney(g.amount, g.currency)]),
        el("td", {}, [g.afectaBanco ? "Sí" : "No"]),
      ])
    )),
  ]);
  render(root, [table]);
}

async function initBank() {
  const balanceRoot = $("#bank-balance-root");
  const movementsRoot = $("#bank-movements-root");
  const closeRoot = $("#month-close-root");
  if (!balanceRoot || !movementsRoot || !closeRoot) return;

  const cached = await cacheGet("bankSummary");
  if (cached?.balanceByCurrency) {
    renderBankBalance(balanceRoot, cached.balanceByCurrency);
    renderBankMovements(movementsRoot, cached.movements || []);
  } else {
    render(balanceRoot, [el("div", { class: "muted" }, ["Cargando…"])]);
  }

  renderMonthClose(closeRoot);

  try {
    const fresh = await fetchJson("/api/bank/summary");
    await cacheSet("bankSummary", fresh);
    renderBankBalance(balanceRoot, fresh.balanceByCurrency);
    renderBankMovements(movementsRoot, fresh.movements || []);
  } catch (e) {
    if (!cached) render(balanceRoot, [alertNode(e.message)]);
  }
}

function renderBankBalance(root, balanceByCurrency) {
  const tags = Object.entries(balanceByCurrency || {}).map(([cur, cents]) =>
    el("div", { class: "tag" }, [`${formatCentsNumber(cents)} ${cur}`])
  );
  render(root, tags.length ? tags : [el("div", { class: "muted" }, ["0"])]);
}

function renderBankMovements(root, movements) {
  const table = el("table", { class: "table" }, [
    el("thead", {}, [
      el("tr", {}, [
        el("th", {}, ["Fecha"]),
        el("th", {}, ["Tipo"]),
        el("th", {}, ["Importe"]),
        el("th", {}, ["Nota"]),
      ]),
    ]),
    el("tbody", {}, movements.map((m) =>
      el("tr", {}, [
        el("td", {}, [m.date]),
        el("td", {}, [m.type]),
        el("td", {}, [formatMoney(m.amount, m.currency)]),
        el("td", {}, [m.note || ""]),
      ])
    )),
  ]);
  render(root, [table]);
}

function renderMonthClose(root) {
  const { year, month } = currentYearMonth();
  const form = el("form", { class: "form" }, [
    el("div", { class: "row" }, [
      el("label", { class: "label col-6" }, [
        "Año",
        el("input", { class: "input", name: "year", type: "number", min: "2000", max: "2100", value: String(year) }),
      ]),
      el("label", { class: "label col-6" }, [
        "Mes",
        el("input", { class: "input", name: "month", type: "number", min: "1", max: "12", value: String(month) }),
      ]),
    ]),
    el("button", { class: "btn", type: "submit" }, ["Cerrar mes"]),
    el("div", { class: "muted" }, [
      "Cierra el mes para registrar el ingreso del mes en el banco y bloquear ese mes.",
    ]),
  ]);
  const status = el("div", { class: "muted" }, []);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    status.textContent = "";
    const fd = new FormData(form);
    const payload = {
      year: Number(fd.get("year")),
      month: Number(fd.get("month")),
    };
    try {
      await fetchJson("/api/months/close", { method: "POST", body: JSON.stringify(payload) });
      const bank = await fetchJson("/api/bank/summary");
      await cacheSet("bankSummary", bank);
      const balanceRoot = $("#bank-balance-root");
      const movementsRoot = $("#bank-movements-root");
      if (balanceRoot && movementsRoot) {
        renderBankBalance(balanceRoot, bank.balanceByCurrency);
        renderBankMovements(movementsRoot, bank.movements);
      }
      status.textContent = "Mes cerrado";
    } catch (e) {
      status.textContent = e.message;
    }
  });
  render(root, [form, status]);
}

async function initDebts() {
  const formRoot = $("#debt-form-root");
  const listRoot = $("#debts-root");
  if (!formRoot || !listRoot) return;

  renderDebtForm(formRoot, async () => {
    const fresh = await fetchJson("/api/debts");
    await cacheSet("debts", fresh);
    await renderDebts(listRoot, fresh.debts);
  });

  const cached = await cacheGet("debts");
  if (cached?.debts) await renderDebts(listRoot, cached.debts);

  try {
    const fresh = await fetchJson("/api/debts");
    await cacheSet("debts", fresh);
    await renderDebts(listRoot, fresh.debts);
  } catch (e) {
    if (!cached) render(listRoot, [alertNode(e.message)]);
  }
}

function renderDebtForm(root, onCreated) {
  const form = el("form", { class: "form" }, [
    el("div", { class: "row" }, [
      el("label", { class: "label col-6" }, [
        "Acreedor",
        el("input", { class: "input", name: "creditor", required: true }),
      ]),
      el("label", { class: "label col-3" }, [
        "Moneda",
        el("select", { class: "select", name: "currency" }, [
          el("option", { value: "EUR" }, ["EUR"]),
          el("option", { value: "XAF" }, ["XAF"]),
        ]),
      ]),
      el("label", { class: "label col-3" }, [
        "Total",
        el("input", { class: "input", name: "total", inputmode: "decimal", required: true, placeholder: "0.00" }),
      ]),
    ]),
    el("button", { class: "btn", type: "submit" }, ["Crear deuda"]),
  ]);
  const status = el("div", { class: "muted" }, []);
  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    status.textContent = "";
    const fd = new FormData(form);
    const payload = Object.fromEntries(fd.entries());
    try {
      await fetchJson("/api/debts", { method: "POST", body: JSON.stringify(payload) });
      await onCreated();
      form.reset();
      form.querySelector('[name="currency"]').value = "EUR";
    } catch (e) {
      status.textContent = e.message;
    }
  });
  render(root, [form, status]);
}

async function renderDebts(root, debts) {
  const rows = debts.map((d) => {
    const statusTag = d.paid ? el("span", { class: "tag tag-paid" }, ["PAGADO"]) : el("span", { class: "tag" }, ["ACTIVO"]);
    const paymentForm = el("form", { class: "form", style: "margin-top:10px; display:none" }, [
      el("div", { class: "row" }, [
        el("label", { class: "label col-6" }, [
          "Fecha",
          el("input", { class: "input", name: "date", type: "date", value: todayIso(), required: true }),
        ]),
        el("label", { class: "label col-6" }, [
          "Importe",
          el("input", { class: "input", name: "amount", inputmode: "decimal", required: true, placeholder: "0.00" }),
        ]),
      ]),
      el("button", { class: "btn", type: "submit" }, ["Añadir pago"]),
    ]);

    const paymentsBox = el("div", { class: "muted", style: "margin-top:10px" }, [""]);

    async function refreshPayments() {
      try {
        const res = await fetchJson(`/api/debts/${d.id}/payments`);
        const list = el("table", { class: "table" }, [
          el("thead", {}, [el("tr", {}, [el("th", {}, ["Fecha"]), el("th", {}, ["Importe"])])]),
          el("tbody", {}, (res.payments || []).map((p) =>
            el("tr", {}, [el("td", {}, [p.date]), el("td", {}, [formatMoney(p.amount, d.currency)])])
          )),
        ]);
        paymentsBox.innerHTML = "";
        paymentsBox.appendChild(list);
      } catch (e) {
        paymentsBox.textContent = e.message;
      }
    }

    paymentForm.addEventListener("submit", async (ev) => {
      ev.preventDefault();
      const fd = new FormData(paymentForm);
      const payload = Object.fromEntries(fd.entries());
      try {
        await fetchJson(`/api/debts/${d.id}/payments`, { method: "POST", body: JSON.stringify(payload) });
        const debtsRes = await fetchJson("/api/debts");
        await cacheSet("debts", debtsRes);
        await renderDebts(root, debtsRes.debts);
        const bank = await fetchJson("/api/bank/summary");
        await cacheSet("bankSummary", bank);
      } catch (e) {
        paymentsBox.textContent = e.message;
      }
    });

    const toggleBtn = el(
      "button",
      {
        class: "btn btn-ghost",
        type: "button",
        onclick: async () => {
          const show = paymentForm.style.display === "none";
          paymentForm.style.display = show ? "block" : "none";
          if (show) await refreshPayments();
        },
      },
      ["Pagos"]
    );

    return el("tr", {}, [
      el("td", {}, [d.creditor]),
      el("td", {}, [formatMoney(d.total, d.currency)]),
      el("td", {}, [formatMoney(d.remaining, d.currency)]),
      el("td", {}, [statusTag]),
      el("td", {}, [toggleBtn]),
      el("td", {}, [el("div", {}, [paymentForm, paymentsBox])]),
    ]);
  });

  const table = el("table", { class: "table" }, [
    el("thead", {}, [
      el("tr", {}, [
        el("th", {}, ["Acreedor"]),
        el("th", {}, ["Total"]),
        el("th", {}, ["Restante"]),
        el("th", {}, ["Estado"]),
        el("th", {}, ["Acciones"]),
        el("th", {}, ["Detalle"]),
      ]),
    ]),
    el("tbody", {}, rows),
  ]);

  render(root, [table]);
}

async function initReports() {
  const root = $("#reports-root");
  if (!root) return;

  if (!CURRENT_USER) {
    try {
      const me = await fetchJson("/api/me");
      CURRENT_USER = me.user || null;
      updateNavVisibility();
    } catch {}
  }

  const { year, month } = currentYearMonth();
  const isPremium = roleLevel(CURRENT_USER?.role) >= ROLE_LEVEL.ROLE_PREMIUM;

  const premiumContent = el("div", { style: "margin-top:12px" }, []);
  const premiumCard = el("section", { class: "card" }, [
    el("div", { class: "card-title" }, ["Funciones Premium"]),
    isPremium
      ? el("div", { class: "btn-row", style: "margin-top:12px" }, [
          el(
            "a",
            {
              class: "btn btn-ghost",
              href: `/api/premium/export/csv?from=${encodeURIComponent(`${year}-01-01`)}&to=${encodeURIComponent(`${year}-12-31`)}`,
            },
            ["Exportar CSV (año)"]
          ),
          el(
            "button",
            {
              class: "btn btn-ghost",
              type: "button",
              onclick: async () => {
                const y = Number(new FormData(form).get("year"));
                const m = Number(new FormData(form).get("month"));
                window.open(
                  `/api/premium/export/pdf?year=${encodeURIComponent(y)}&month=${encodeURIComponent(m)}`,
                  "_blank"
                );
              },
            },
            ["Exportar PDF"]
          ),
          el(
            "button",
            {
              class: "btn btn-ghost",
              type: "button",
              onclick: async () => {
                const y = Number(new FormData(form).get("year"));
                const proj = await fetchJson(`/api/premium/projection/annual?year=${encodeURIComponent(y)}`);
                renderPremiumProjection(premiumContent, proj);
              },
            },
            ["Proyección anual"]
          ),
        ])
      : el("div", { class: "muted" }, ["Requiere Premium: proyecciones y exportación"]),
    premiumContent,
  ]);

  const form = el("form", { class: "form" }, [
    el("div", { class: "row" }, [
      el("label", { class: "label col-6" }, [
        "Año",
        el("input", { class: "input", name: "year", type: "number", min: "2000", max: "2100", value: String(year) }),
      ]),
      el("label", { class: "label col-6" }, [
        "Mes",
        el("input", { class: "input", name: "month", type: "number", min: "1", max: "12", value: String(month) }),
      ]),
    ]),
    el("button", { class: "btn", type: "submit" }, ["Ver reporte"]),
  ]);

  const status = el("div", { class: "muted" }, []);
  const content = el("div", { style: "margin-top:12px" }, []);

  async function loadReport(y, m) {
    const key = `report:${y}-${String(m).padStart(2, "0")}`;
    const cached = await cacheGet(key);
    if (cached?.ok) renderMonthlyReport(content, cached);
    else render(content, [el("div", { class: "muted" }, ["Cargando…"])]);
    try {
      const fresh = await fetchJson(`/api/reports/monthly?year=${encodeURIComponent(y)}&month=${encodeURIComponent(m)}`);
      await cacheSet(key, fresh);
      renderMonthlyReport(content, fresh);
      status.textContent = fresh.isClosed ? "Mes cerrado" : "Mes abierto";
    } catch (e) {
      status.textContent = e.message;
      if (!cached) render(content, [alertNode(e.message)]);
    }
  }

  form.addEventListener("submit", async (ev) => {
    ev.preventDefault();
    status.textContent = "";
    const fd = new FormData(form);
    await loadReport(Number(fd.get("year")), Number(fd.get("month")));
  });

  render(root, [premiumCard, form, status, content]);
  await loadReport(year, month);
}

function renderPremiumProjection(root, proj) {
  const rows = (proj.months || []).map((m) => {
    const keys = Object.keys(m.savingsByCurrency || {});
    const text = keys.length
      ? keys.map((cur) => `${m.savingsByCurrency[cur]} ${cur}`).join(" | ")
      : "0.00";
    return el("tr", {}, [el("td", {}, [String(m.month)]), el("td", {}, [text])]);
  });
  render(root, [
    el("div", { class: "muted", style: "margin-top:12px" }, [`Año ${proj.year}`]),
    el("table", { class: "table", style: "margin-top:8px" }, [
      el("thead", {}, [el("tr", {}, [el("th", {}, ["Mes"]), el("th", {}, ["Ahorro (ingresos - gastos)"])])]),
      el("tbody", {}, rows),
    ]),
  ]);
}

function renderMonthlyReport(root, report) {
  const income = report.incomeNetByCurrency || {};
  const expenses = report.expensesByCurrency || {};
  const expensesNoBanco = report.expensesNoBancoByCurrency || {};

  const summaryRows = Array.from(new Set([...Object.keys(income), ...Object.keys(expenses), ...Object.keys(expensesNoBanco)])).map((cur) =>
    el("tr", {}, [
      el("td", {}, [cur]),
      el("td", {}, [formatMoney(income[cur] || "0.00", cur)]),
      el("td", {}, [formatMoney(expenses[cur] || "0.00", cur)]),
      el("td", {}, [formatMoney(expensesNoBanco[cur] || "0.00", cur)]),
    ])
  );

  const companyItems = Object.entries(report.incomeByCompany || {});
  const companyRows = companyItems.map(([id, v]) =>
    el("tr", {}, [
      el("td", {}, [v.companyName]),
      el("td", {}, [v.currency]),
      el("td", {}, [formatMoney(v.brutoMes, v.currency)]),
      el("td", {}, [formatMoney(v.irpf, v.currency)]),
      el("td", {}, [formatMoney(v.otrosDescuentos, v.currency)]),
      el("td", {}, [formatMoney(v.anticipos, v.currency)]),
      el("td", {}, [formatMoney(v.netoFinal, v.currency)]),
    ])
  );

  const summaryTable = el("table", { class: "table" }, [
    el("thead", {}, [
      el("tr", {}, [
        el("th", {}, ["Moneda"]),
        el("th", {}, ["Ingresos (neto)"]),
        el("th", {}, ["Gastos (total)"]),
        el("th", {}, ["Gastos (no banco)"]),
      ]),
    ]),
    el("tbody", {}, summaryRows),
  ]);

  const companyTable = el("table", { class: "table" }, [
    el("thead", {}, [
      el("tr", {}, [
        el("th", {}, ["Empresa"]),
        el("th", {}, ["Moneda"]),
        el("th", {}, ["Bruto mes"]),
        el("th", {}, ["IRPF"]),
        el("th", {}, ["Otros desc."]),
        el("th", {}, ["Anticipos"]),
        el("th", {}, ["Neto final"]),
      ]),
    ]),
    el("tbody", {}, companyRows),
  ]);

  render(root, [
    el("div", { class: "grid" }, [
      el("section", { class: "card" }, [el("div", { class: "card-title" }, ["Resumen"]), summaryTable]),
      el("section", { class: "card" }, [
        el("div", { class: "card-title" }, ["Ingresos por empresa"]),
        companyItems.length ? companyTable : el("div", { class: "muted" }, ["Sin ingresos en este mes"]),
      ]),
    ]),
  ]);
}

setActiveNav();
initMe();
initMonthPill();
initDashboard();
initCompaniesAndWorkEntries();
initExpenses();
initBank();
initDebts();
initReports();
initAdmin();
