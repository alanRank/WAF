const state = {
  token: localStorage.getItem("waf_token") || "",
  activeTab: "overview",
  config: null,
  rules: [],
  policies: null,
  logs: [],
  ipEntries: [],
  users: [],
  charts: {
    distribution: null,
    timeline: null
  }
};

const authView = document.getElementById("auth-view");
const dashboardView = document.getElementById("dashboard-view");
const loginError = document.getElementById("login-error");
const globalStatus = document.getElementById("global-status");

document.getElementById("login-form").addEventListener("submit", onLogin);
document.getElementById("refresh-btn").addEventListener("click", refreshAll);
document.getElementById("logout-btn").addEventListener("click", logout);
document.getElementById("config-form").addEventListener("submit", saveConfig);
document.getElementById("ip-form").addEventListener("submit", upsertIpEntry);
document.getElementById("user-form").addEventListener("submit", createUser);
document.getElementById("load-config-btn").addEventListener("click", reloadConfig);
document.getElementById("load-rules-btn").addEventListener("click", reloadRules);
document.getElementById("load-policies-btn").addEventListener("click", reloadPolicies);
document.getElementById("save-rules-btn").addEventListener("click", saveRules);
document.getElementById("save-policies-btn").addEventListener("click", savePolicies);
document.getElementById("logs-clear-btn").addEventListener("click", clearLogs);
document.querySelectorAll(".sidebar-tab").forEach((button) => {
  button.addEventListener("click", () => activateTab(button.dataset.tab));
});

bootstrap();

async function bootstrap() {
  if (!state.token) {
    showAuth();
    return;
  }

  try {
    await refreshAll();
    showDashboard();
  } catch (error) {
    logout();
  }
}

async function onLogin(event) {
  event.preventDefault();
  loginError.classList.add("hidden");

  try {
    const response = await fetch("/api/admin/login", {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({
        username: document.getElementById("username").value.trim(),
        password: document.getElementById("password").value
      })
    });

    const payload = await response.json();
    if (!response.ok) {
      throw new Error(payload?.error || "Authentication failed");
    }

    state.token = payload.access_token;
    localStorage.setItem("waf_token", state.token);
    await refreshAll();
    showDashboard();
  } catch (error) {
    loginError.textContent = error.message;
    loginError.classList.remove("hidden");
  }
}

function logout() {
  localStorage.removeItem("waf_token");
  state.token = "";
  showAuth();
}

async function refreshAll() {
  const [config, rules, policies, logs, ipEntries, users] = await Promise.all([
    api("/api/admin/config"),
    api("/api/admin/rules"),
    api("/api/admin/security-policies"),
    api("/api/admin/logs?limit=50"),
    api("/api/admin/ip-lists"),
    api("/api/admin/users")
  ]);

  state.config = config;
  state.rules = rules;
  state.policies = policies;
  state.logs = logs;
  state.ipEntries = ipEntries;
  state.users = users;

  renderDashboard();
  renderLogs();
  renderIpEntries();
  renderUsers();
  renderEditors();
  fillConfigForm();
  showStatus("Данные обновлены", false, true);
}

function activateTab(name) {
  state.activeTab = name;
  document.querySelectorAll(".sidebar-tab").forEach((button) => {
    button.classList.toggle("active", button.dataset.tab === name);
  });
  document.querySelectorAll(".tab-panel").forEach((panel) => {
    panel.classList.toggle("hidden", panel.dataset.panel !== name);
  });
}

async function saveConfig(event) {
  event.preventDefault();

  const payload = {
    ...state.config,
    mode: document.getElementById("cfg-mode").value,
    is_enabled: document.getElementById("cfg-enabled").checked,
    target_url: document.getElementById("cfg-target").value.trim(),
    interceptor_host: document.getElementById("cfg-host").value.trim(),
    interceptor_port: Number(document.getElementById("cfg-interceptor-port").value),
    admin_port: Number(document.getElementById("cfg-admin-port").value),
    tls_cert_path: document.getElementById("cfg-cert-path").value.trim(),
    tls_key_path: document.getElementById("cfg-key-path").value.trim()
  };

  try {
    state.config = await api("/api/admin/config", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    renderDashboard();
    showStatus("config.json обновлен", false);
  } catch (error) {
    showStatus(error.message, true);
  }
}

async function reloadConfig() {
  state.config = await api("/api/admin/config");
  fillConfigForm();
  renderDashboard();
  showStatus("config.json загружен", false);
}

async function saveRules() {
  try {
    const payload = JSON.parse(document.getElementById("rules-editor").value);
    state.rules = await api("/api/admin/rules", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    renderEditors();
    showStatus("rules.json обновлен", false);
  } catch (error) {
    showStatus(error.message, true);
  }
}

async function reloadRules() {
  state.rules = await api("/api/admin/rules");
  renderEditors();
  showStatus("rules.json загружен", false);
}

async function savePolicies() {
  try {
    const payload = JSON.parse(document.getElementById("policies-editor").value);
    state.policies = await api("/api/admin/security-policies", {
      method: "PUT",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    renderEditors();
    showStatus("sec_policies.json обновлен", false);
  } catch (error) {
    showStatus(error.message, true);
  }
}

async function reloadPolicies() {
  state.policies = await api("/api/admin/security-policies");
  renderEditors();
  showStatus("sec_policies.json загружен", false);
}

async function upsertIpEntry(event) {
  event.preventDefault();
  const payload = {
    ip_address: document.getElementById("ip-address").value.trim(),
    list_type: document.getElementById("ip-list-type").value,
    comment: document.getElementById("ip-comment").value.trim() || null,
    expires_at: null
  };

  await api("/api/admin/ip-lists", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  document.getElementById("ip-address").value = "";
  document.getElementById("ip-comment").value = "";
  state.ipEntries = await api("/api/admin/ip-lists");
  renderIpEntries();
  renderDashboard();
  showStatus("IP entry сохранен", false);
}

async function createUser(event) {
  event.preventDefault();
  const payload = {
    username: document.getElementById("new-username").value.trim(),
    password: document.getElementById("new-password").value,
    role: document.getElementById("new-role").value
  };

  await api("/api/admin/users", {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(payload)
  });

  document.getElementById("new-username").value = "";
  document.getElementById("new-password").value = "";
  document.getElementById("new-role").value = "analyst";
  state.users = await api("/api/admin/users");
  renderUsers();
  showStatus("Пользователь добавлен", false);
}

async function updateUser(username) {
  const role = prompt(`Новая роль для ${username} (admin/analyst):`);
  if (!role) {
    return;
  }

  const password = prompt(`Новый пароль для ${username} (или оставьте пустым):`) || "";

  await api(`/api/admin/users/${encodeURIComponent(username)}`, {
    method: "PATCH",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify({
      role: role.trim(),
      password: password.trim() ? password : null
    })
  });

  state.users = await api("/api/admin/users");
  renderUsers();
  showStatus(`Пользователь ${username} обновлен`, false);
}

async function deleteUser(username) {
  if (!confirm(`Удалить пользователя ${username}?`)) {
    return;
  }

  await api(`/api/admin/users/${encodeURIComponent(username)}`, { method: "DELETE" });
  state.users = await api("/api/admin/users");
  renderUsers();
  showStatus(`Пользователь ${username} удален`, false);
}

async function deleteIp(ip) {
  if (!confirm(`Удалить IP ${ip}?`)) {
    return;
  }

  await api(`/api/admin/ip-lists/${encodeURIComponent(ip)}`, { method: "DELETE" });
  state.ipEntries = await api("/api/admin/ip-lists");
  renderIpEntries();
  renderDashboard();
  showStatus(`IP ${ip} удален`, false);
}

async function clearLogs() {
  if (!confirm("Очистить все логи атак?")) {
    return;
  }

  await api("/api/admin/logs/clear", { method: "POST" });
  state.logs = await api("/api/admin/logs?limit=50");
  renderLogs();
  renderDashboard();
  showStatus("Журнал атак очищен", false);
}

async function deleteLog(id) {
  await api(`/api/admin/logs/${id}`, { method: "DELETE" });
  state.logs = await api("/api/admin/logs?limit=50");
  renderLogs();
  renderDashboard();
  showStatus(`Лог #${id} удален`, false);
}

function renderDashboard() {
  document.getElementById("top-summary").textContent =
    `WAF работает в режиме ${state.config.mode}. Точка проксирования: ${state.config.interceptor_host}:${state.config.interceptor_port}, upstream: ${state.config.target_url}.`;
  document.getElementById("mode-pill").textContent = state.config.mode;
  document.getElementById("enabled-pill").textContent = state.config.is_enabled ? "true" : "false";
  document.getElementById("target-pill").textContent = state.config.target_url;
  document.getElementById("logs-count").textContent = String(state.logs.length);

  renderRecentActions();
  renderVectorStats();
  renderDistributionChart();
  renderTimelineChart();
}

function renderRecentActions() {
  const node = document.getElementById("recent-actions");
  const items = state.logs
    .filter((log) => toAttackVector(log.attack_type))
    .slice(0, 8)
    .map((log) => `
      <div class="event-row">
        <div class="flex items-start justify-between gap-3">
          <div>
            <div class="text-sm font-semibold text-bark">${escapeHtml(log.source_ip)} - ${escapeHtml(log.action_taken)}</div>
            <div class="mt-1 text-sm text-bark/70">${escapeHtml(shortReason(log))}</div>
          </div>
          <div class="text-xs text-bark/45">${escapeHtml(log.timestamp)}</div>
        </div>
      </div>
    `)
    .join("");

  node.innerHTML = items || `<div class="event-row text-sm text-bark/60">Событий по трем основным векторам пока нет.</div>`;
}

function renderVectorStats() {
  const vectors = aggregateVectors();
  const items = [
    ["SQL инъекция", vectors.sql],
    ["XSS инъекция", vectors.xss],
    ["Path-traversal", vectors.path]
  ].map(([label, value]) => `
    <div class="summary-pill">
      <span>${label}</span>
      <strong>${value}</strong>
    </div>
  `).join("");

  document.getElementById("vector-stats").innerHTML = items;
}

function renderDistributionChart() {
  const vectors = aggregateVectors();
  const ctx = document.getElementById("distribution-chart");

  if (state.charts.distribution) {
    state.charts.distribution.destroy();
  }

  state.charts.distribution = new Chart(ctx, {
    type: "doughnut",
    data: {
      labels: ["SQL инъекция", "XSS инъекция", "Path-traversal"],
      datasets: [{
        data: [vectors.sql, vectors.xss, vectors.path],
        backgroundColor: ["#8fd14f", "#4ea63b", "#2f7c29"],
        borderWidth: 0
      }]
    },
    options: {
      maintainAspectRatio: false,
      plugins: {
        legend: {
          position: "bottom",
          labels: { color: "#1d331c", usePointStyle: true }
        }
      }
    }
  });
}

function renderTimelineChart() {
  const filtered = state.logs
    .filter((log) => toAttackVector(log.attack_type))
    .slice()
    .reverse();

  const labels = filtered.map((log) => formatTime(log.timestamp));
  const cumulative = [];
  let total = 0;
  filtered.forEach(() => {
    total += 1;
    cumulative.push(total);
  });

  const ctx = document.getElementById("timeline-chart");
  if (state.charts.timeline) {
    state.charts.timeline.destroy();
  }

  state.charts.timeline = new Chart(ctx, {
    type: "line",
    data: {
      labels,
      datasets: [{
        label: "Атаки",
        data: cumulative,
        borderColor: "#4ea63b",
        backgroundColor: "rgba(143,209,79,0.18)",
        tension: 0.32,
        fill: true,
        pointRadius: 3,
        pointBackgroundColor: "#2f7c29"
      }]
    },
    options: {
      maintainAspectRatio: false,
      plugins: { legend: { display: false } },
      scales: {
        x: { ticks: { color: "#365335" }, grid: { color: "rgba(78,166,59,0.08)" } },
        y: { ticks: { color: "#365335", precision: 0 }, grid: { color: "rgba(78,166,59,0.08)" } }
      }
    }
  });
}

function renderLogs() {
  const rows = state.logs.map((log) => `
    <tr>
      <td class="text-xs text-bark/70">${escapeHtml(log.timestamp)}</td>
      <td class="text-sm">${escapeHtml(log.source_ip)}</td>
      <td class="text-sm">${escapeHtml(log.request_url || "-")}</td>
      <td class="text-sm">${escapeHtml(log.attack_type || "-")}</td>
      <td class="text-sm">${escapeHtml(log.action_taken)}</td>
      <td class="text-xs text-bark/70">${escapeHtml(extractMessage(log.payload))}</td>
      <td class="text-right">
        <button class="secondary-btn !py-2 !px-3" onclick="deleteLog(${log.id})">Удалить</button>
      </td>
    </tr>
  `).join("");

  document.getElementById("logs-table").innerHTML = wrapTable(
    ["Время", "IP", "URL", "Тип", "Действие", "Причина", ""],
    rows || emptyRow("Логи отсутствуют", 7)
  );
}

function renderIpEntries() {
  const rows = state.ipEntries.map((entry) => `
    <tr>
      <td>${escapeHtml(entry.ip_address)}</td>
      <td>${escapeHtml(entry.list_type)}</td>
      <td>${escapeHtml(entry.comment || "-")}</td>
      <td class="text-xs text-bark/60">${escapeHtml(entry.created_at)}</td>
      <td class="text-right">
        <button class="secondary-btn !py-2 !px-3" onclick="deleteIp('${escapeJs(entry.ip_address)}')">Удалить</button>
      </td>
    </tr>
  `).join("");

  document.getElementById("ip-table").innerHTML = wrapTable(
    ["IP", "List", "Comment", "Created", ""],
    rows || emptyRow("IP-список пуст", 5)
  );
}

function renderUsers() {
  const rows = state.users.map((user) => `
    <tr>
      <td>${escapeHtml(user.username)}</td>
      <td>${escapeHtml(user.role)}</td>
      <td class="text-xs text-bark/60">${escapeHtml(user.created_at)}</td>
      <td class="text-right space-x-2">
        <button class="secondary-btn !py-2 !px-3" onclick="updateUser('${escapeJs(user.username)}')">Изменить</button>
        <button class="secondary-btn !py-2 !px-3" onclick="deleteUser('${escapeJs(user.username)}')">Удалить</button>
      </td>
    </tr>
  `).join("");

  document.getElementById("users-table").innerHTML = wrapTable(
    ["Username", "Role", "Created", ""],
    rows || emptyRow("Пользователи отсутствуют", 4)
  );
}

function renderEditors() {
  document.getElementById("rules-editor").value = JSON.stringify(state.rules, null, 2);
  document.getElementById("policies-editor").value = JSON.stringify(state.policies, null, 2);
}

function fillConfigForm() {
  document.getElementById("cfg-mode").value = state.config.mode;
  document.getElementById("cfg-enabled").checked = state.config.is_enabled;
  document.getElementById("cfg-target").value = state.config.target_url;
  document.getElementById("cfg-host").value = state.config.interceptor_host;
  document.getElementById("cfg-interceptor-port").value = String(state.config.interceptor_port);
  document.getElementById("cfg-admin-port").value = String(state.config.admin_port);
  document.getElementById("cfg-cert-path").value = state.config.tls_cert_path;
  document.getElementById("cfg-key-path").value = state.config.tls_key_path;
}

function aggregateVectors() {
  const result = { sql: 0, xss: 0, path: 0 };
  state.logs.forEach((log) => {
    const vector = toAttackVector(log.attack_type);
    if (vector) {
      result[vector] += 1;
    }
  });
  return result;
}

function toAttackVector(attackType) {
  const value = String(attackType || "").toLowerCase();
  if (value.includes("sql")) return "sql";
  if (value.includes("xss")) return "xss";
  if (value.includes("path")) return "path";
  return null;
}

function shortReason(log) {
  return `${log.source_ip} - ${extractMessage(log.payload)}`;
}

function extractMessage(payload) {
  try {
    const data = JSON.parse(payload || "{}");
    return data.message || "-";
  } catch {
    return "-";
  }
}

function formatTime(value) {
  const date = new Date(value);
  return Number.isNaN(date.getTime()) ? value : date.toLocaleTimeString();
}

function showStatus(message, isError = false, transient = false) {
  globalStatus.textContent = message;
  globalStatus.className = `status-box mt-4 ${isError ? "status-error" : "status-ok"}`;
  globalStatus.classList.remove("hidden");
  if (transient) {
    window.clearTimeout(showStatus.timer);
    showStatus.timer = window.setTimeout(() => {
      globalStatus.classList.add("hidden");
    }, 2500);
  }
}

function showAuth() {
  dashboardView.classList.add("hidden");
  authView.classList.remove("hidden");
}

function showDashboard() {
  authView.classList.add("hidden");
  dashboardView.classList.remove("hidden");
  activateTab(state.activeTab);
}

async function api(url, options = {}) {
  const headers = new Headers(options.headers || {});
  headers.set("Authorization", `Bearer ${state.token}`);

  const response = await fetch(url, { ...options, headers });
  const payload = response.status === 204 ? null : await safeJson(response);

  if (!response.ok) {
    throw new Error(payload?.error || `Request failed: ${response.status}`);
  }

  return payload;
}

async function safeJson(response) {
  try {
    return await response.json();
  } catch {
    return null;
  }
}

function wrapTable(headers, rows) {
  return `
    <div class="table-wrap overflow-x-auto">
      <table>
        <thead><tr>${headers.map((h) => `<th>${h}</th>`).join("")}</tr></thead>
        <tbody>${rows}</tbody>
      </table>
    </div>
  `;
}

function emptyRow(message, colspan) {
  return `<tr><td colspan="${colspan}" class="px-4 py-6 text-center text-sm text-bark/60">${escapeHtml(message)}</td></tr>`;
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function escapeJs(value) {
  return String(value).replaceAll("\\", "\\\\").replaceAll("'", "\\'");
}

window.deleteLog = deleteLog;
window.deleteIp = deleteIp;
window.deleteUser = deleteUser;
window.updateUser = updateUser;
