const $ = (selector, root = document) => root.querySelector(selector);
const $$ = (selector, root = document) => [...root.querySelectorAll(selector)];
const view = $("#view");
const title = $("#title");
const status = $("#status");
const createButton = $("#create");
const authDialog = $("#auth-dialog");
const editorDialog = $("#editor-dialog");
const labels = Object.fromEntries($$("[data-view]").map(button => [button.dataset.view, button.textContent.trim()]));

const schemas = {
  "proxy-hosts": [
    ["domain_names", "Domain names", "list", true], ["forward_scheme", "Forward scheme", "select", true, ["http", "https"]],
    ["forward_host", "Forward host", "text", true], ["forward_port", "Forward port", "number", true],
    ["access_list_id", "Access list ID", "number"], ["certificate_id", "Certificate ID", "number"],
    ["allow_websocket_upgrade", "WebSocket support", "checkbox"], ["caching_enabled", "Asset caching", "checkbox"],
    ["block_exploits", "Block common exploits", "checkbox"], ["ssl_forced", "Force HTTPS", "checkbox"],
    ["http2_support", "HTTP/2", "checkbox"], ["hsts_enabled", "HSTS", "checkbox"],
  ],
  "redirection-hosts": [
    ["domain_names", "Domain names", "list", true], ["forward_scheme", "Forward scheme", "select", true, ["auto", "http", "https"]],
    ["forward_domain_name", "Destination domain", "text", true], ["forward_http_code", "HTTP status", "select", true, ["301", "302", "307", "308"]],
    ["preserve_path", "Preserve path", "checkbox"], ["certificate_id", "Certificate ID", "number"], ["ssl_forced", "Force HTTPS", "checkbox"],
  ],
  "dead-hosts": [["domain_names", "Domain names", "list", true], ["certificate_id", "Certificate ID", "number"], ["ssl_forced", "Force HTTPS", "checkbox"]],
  streams: [
    ["incoming_port", "Incoming port", "number", true], ["forwarding_host", "Forward host", "text", true],
    ["forwarding_port", "Forward port", "number", true], ["tcp_forwarding", "TCP", "checkbox"],
    ["udp_forwarding", "UDP", "checkbox"], ["certificate_id", "Certificate ID", "number"],
  ],
  certificates: [
    ["nice_name", "Name", "text", true], ["provider", "Provider", "select", true, ["other", "letsencrypt"]],
    ["domain_names", "Domain names", "list"], ["email", "ACME account email", "email"],
    ["challenge_type", "ACME challenge", "select", false, ["http-01", "dns-01"]],
    ["key_type", "Key type", "select", false, ["rsa", "ecdsa"]],
    ["certificate", "Certificate PEM", "textarea"], ["private_key", "Private key PEM", "textarea"],
    ["intermediate_certificate", "Intermediate PEM", "textarea"],
  ],
  "access-lists": [["name", "Name", "text", true], ["satisfy_any", "Satisfy any rule", "checkbox"], ["pass_auth", "Pass auth upstream", "checkbox"]],
  users: [["email", "Email", "email", true], ["name", "Name", "text", true], ["nickname", "Nickname", "text"], ["is_admin", "Administrator", "checkbox"], ["is_disabled", "Disabled", "checkbox"]],
  settings: [["name", "Setting name", "text", true], ["value", "Value", "text", true]],
};
const readonlyViews = new Set(["dashboard", "audit-log", "health"]);
let sessionActive = document.cookie.split("; ").some(value => value.startsWith("portwyrm_csrf="));
let currentView = "dashboard";
let editing = null;
let setupRequired = false;
let principal = null;

const sectionByView = {
  "proxy-hosts": "proxy_hosts", "redirection-hosts": "redirection_hosts",
  "dead-hosts": "dead_hosts", streams: "streams", certificates: "certificates",
  "access-lists": "access_lists",
};

function applyPermissions() {
  $$('[data-admin]').forEach(item => item.hidden = !principal?.is_admin);
  for (const [name, section] of Object.entries(sectionByView)) {
    const permission = principal?.is_admin ? "manage" : (principal?.permissions?.[section] || "hidden");
    $(`[data-view="${name}"]`).hidden = permission === "hidden";
  }
  const section = sectionByView[currentView];
  const permission = principal?.is_admin ? "manage" : principal?.permissions?.[section];
  createButton.hidden = readonlyViews.has(currentView) || !schemas[currentView] || (section && permission !== "manage");
}

function escapeHtml(value) {
  return String(value ?? "").replaceAll("&", "&amp;").replaceAll("<", "&lt;").replaceAll(">", "&gt;").replaceAll('"', "&quot;").replaceAll("'", "&#39;");
}

function resourcePath(name, id = null) {
  if (name === "account") return "/api/v2/me";
  if (name === "tokens") return `/api/v2/tokens${id === null ? "" : `/${encodeURIComponent(id)}`}`;
  const prefix = ["users", "settings", "audit-log"].includes(name) ? "/api" : "/api/nginx";
  return `${prefix}/${name}${id === null ? "" : `/${encodeURIComponent(id)}`}`;
}

async function api(path, options = {}) {
  const headers = {Accept: "application/json", ...(options.headers || {})};
  if (options.body) headers["Content-Type"] = "application/json";
  if (["POST", "PUT", "PATCH", "DELETE"].includes(options.method)) {
    const csrf = document.cookie.split("; ").find(value => value.startsWith("portwyrm_csrf="));
    if (csrf) headers["X-CSRF-Token"] = decodeURIComponent(csrf.split("=").slice(1).join("="));
  }
  const response = await fetch(path, {...options, headers, credentials: "same-origin"});
  const data = response.status === 204 ? null : await response.json().catch(() => ({}));
  if (!response.ok) {
    const error = new Error(data.detail || `${response.status} ${response.statusText}`);
    error.status = response.status;
    throw error;
  }
  return data;
}

function notify(message, kind = "ok") {
  status.textContent = message;
  status.className = `notice ${kind}`;
  status.hidden = !message;
}

function displayValue(key, value) {
  if (key === "enabled" || key.startsWith("is_")) return `<span class="badge">${value ? "Yes" : "No"}</span>`;
  if (Array.isArray(value)) return escapeHtml(value.join(", "));
  if (value && typeof value === "object") return `<code>${escapeHtml(JSON.stringify(value))}</code>`;
  return escapeHtml(value);
}

function table(rows, name) {
  if (!rows.length) return `<div class="empty"><h2>No ${escapeHtml(labels[name]?.toLowerCase() || "resources")} yet</h2><p class="muted">Add the first one to begin managing this part of the control plane.</p>${readonlyViews.has(name) ? "" : '<button class="button" data-action="new">New resource</button>'}</div>`;
  const preferred = ["id", "name", "nice_name", "domain_names", "forward_host", "forwarding_host", "incoming_port", "enabled", "modified_on"];
  const available = new Set(rows.flatMap(Object.keys));
  const keys = preferred.filter(key => available.has(key)).slice(0, 6);
  if (keys.length < 2) [...available].filter(key => !keys.includes(key)).slice(0, 4).forEach(key => keys.push(key));
  const actions = readonlyViews.has(name) ? "" : "<th>Actions</th>";
  return `<div class="table-wrap"><table><thead><tr>${keys.map(key => `<th>${escapeHtml(key.replaceAll("_", " "))}</th>`).join("")}${actions}</tr></thead><tbody>${rows.map(row => `<tr>${keys.map(key => `<td>${displayValue(key, row[key])}</td>`).join("")}${readonlyViews.has(name) ? "" : `<td><div class="row-actions"><button class="button secondary" data-action="edit" data-id="${escapeHtml(row.id)}">Edit</button><button class="button danger" data-action="delete" data-id="${escapeHtml(row.id)}">Delete</button></div></td>`}</tr>`).join("")}</tbody></table></div>`;
}

async function render(name = currentView) {
  currentView = name;
  title.textContent = labels[name] || "Portwyrm";
  createButton.hidden = readonlyViews.has(name) || !schemas[name];
  applyPermissions();
  view.innerHTML = '<div class="skeleton"></div>';
  view.setAttribute("aria-busy", "true");
  notify("");
  try {
    if (name === "dashboard") {
      const families = ["proxy-hosts", "redirection-hosts", "dead-hosts", "streams", "certificates", "access-lists"];
      const readiness = await api("/health/ready");
      const values = sessionActive ? await Promise.all(families.map(family => api(resourcePath(family)).catch(() => []))) : families.map(() => []);
      view.innerHTML = `<div class="grid"><article class="card"><div class="muted">System</div><p class="metric ${readiness.status === "ok" ? "ok" : "warning"}">${escapeHtml(readiness.status)}</p></article>${families.map((family, index) => `<article class="card"><div class="muted">${escapeHtml(labels[family])}</div><p class="metric">${values[index].length}</p></article>`).join("")}</div>${sessionActive ? "" : '<div class="empty"><h2>Sign in to manage Portwyrm</h2><p class="muted">Your control plane is available. Authenticate to see and change resources.</p><button class="button" data-action="signin">Sign in</button></div>'}`;
    } else if (name === "tokens") {
      const tokens = await api("/api/v2/tokens");
      const rows = tokens.map(item => `<tr><td>${escapeHtml(item.name)}</td><td>${escapeHtml(item.created_at)}</td><td>${escapeHtml(item.last_used_at || "Never")}</td><td><button class="button danger" data-action="token-revoke" data-id="${escapeHtml(item.id)}">Revoke</button></td></tr>`).join("");
      view.innerHTML = `<div class="dialog-actions"><button class="button" data-action="token-new">New access token</button></div>${tokens.length ? `<div class="table-wrap"><table><thead><tr><th>Name</th><th>Created</th><th>Last used</th><th>Actions</th></tr></thead><tbody>${rows}</tbody></table></div>` : '<div class="empty"><h2>No access tokens</h2><p>Create one for npmctl or other automation.</p></div>'}`;
    } else if (name === "account") {
      const account = await api("/api/v2/me");
      view.innerHTML = `<article class="card"><p class="eyebrow">Account</p><h2>${escapeHtml(account.nickname || account.name || account.email)}</h2><p>${escapeHtml(account.email)}</p><p class="muted">${account.is_admin ? "Administrator" : "Operator"}</p><button class="button secondary" data-action="${account.mfa_enabled ? "mfa-disable" : "mfa-enroll"}">${account.mfa_enabled ? "Disable MFA" : "Set up MFA"}</button></article>`;
    } else if (name === "health") {
      const [health, version] = await Promise.all([api("/health/ready"), api("/version")]);
      view.innerHTML = `<div class="grid"><article class="card"><p class="eyebrow">Readiness</p><h2 class="${health.status === "ok" ? "ok" : "warning"}">${escapeHtml(health.status)}</h2><pre>${escapeHtml(JSON.stringify(health.components, null, 2))}</pre></article><article class="card"><p class="eyebrow">Release</p><h2>${escapeHtml(version.version)}</h2><p class="muted">API, UIX, repository, and proxy runtime</p></article></div>`;
    } else {
      const data = await api(resourcePath(name));
      view.innerHTML = table(Array.isArray(data) ? data : [data], name);
    }
  } catch (error) {
    view.innerHTML = `<article class="empty"><h2 class="error">Unable to load ${escapeHtml(title.textContent)}</h2><p>${escapeHtml(error.message)}</p>${error.status === 401 ? '<button class="button" data-action="signin">Sign in</button>' : '<button class="button secondary" data-action="retry">Try again</button>'}</article>`;
  } finally {
    view.setAttribute("aria-busy", "false");
  }
}

function fieldMarkup([name, label, type, required, options], value) {
  if (type === "checkbox") return `<label class="check"><input name="${name}" type="checkbox" ${value ? "checked" : ""}>${escapeHtml(label)}</label>`;
  if (type === "select") return `<label>${escapeHtml(label)}<select name="${name}" ${required ? "required" : ""}>${options.map(option => `<option value="${escapeHtml(option)}" ${String(value ?? "") === option ? "selected" : ""}>${escapeHtml(option)}</option>`).join("")}</select></label>`;
  if (type === "textarea") return `<label>${escapeHtml(label)}<textarea name="${name}" rows="6" spellcheck="false" ${required ? "required" : ""}>${escapeHtml(value ?? "")}</textarea></label>`;
  return `<label>${escapeHtml(label)}<input name="${name}" type="${type === "list" ? "text" : type}" value="${escapeHtml(type === "list" && Array.isArray(value) ? value.join(", ") : value ?? "")}" ${type === "number" ? 'min="0"' : ""} ${required ? "required" : ""}>${type === "list" ? '<span class="muted">Separate multiple values with commas.</span>' : ""}</label>`;
}

async function openEditor(id = null) {
  editing = id;
  let resource = {};
  if (id !== null) resource = await api(resourcePath(currentView, id));
  const schema = schemas[currentView] || [];
  $("#editor-context").textContent = labels[currentView];
  $("#editor-title").textContent = id === null ? "New resource" : `Edit resource ${id}`;
  $("#editor-fields").innerHTML = schema.map(field => fieldMarkup(field, resource[field[0]])).join("");
  const known = new Set([...schema.map(field => field[0]), "id", "created_on", "modified_on"]);
  $("#advanced-json").value = JSON.stringify(Object.fromEntries(Object.entries(resource).filter(([key]) => !known.has(key))), null, 2);
  $("#editor-error").textContent = "";
  editorDialog.showModal();
}

function formPayload() {
  const payload = JSON.parse($("#advanced-json").value || "{}");
  for (const [name, , type] of schemas[currentView]) {
    const input = $(`[name="${name}"]`, $("#editor-form"));
    if (type === "checkbox") payload[name] = input.checked ? 1 : 0;
    else if (type === "number") payload[name] = input.value === "" ? 0 : Number(input.value);
    else if (type === "list") payload[name] = input.value.split(",").map(value => value.trim()).filter(Boolean);
    else payload[name] = input.value;
  }
  if (!("enabled" in payload) && ["proxy-hosts", "redirection-hosts", "dead-hosts", "streams"].includes(currentView)) payload.enabled = 1;
  return payload;
}

$("#editor-form").addEventListener("submit", async event => {
  event.preventDefault();
  const submit = $("button[type=submit]", event.currentTarget);
  submit.disabled = true;
  try {
    const payload = formPayload();
    let path = resourcePath(currentView, editing);
    let method = editing === null ? "POST" : "PUT";
    if (currentView === "certificates") {
      if (payload.provider === "letsencrypt" && editing === null) path = "/api/nginx/certificates/request";
      else path = editing === null ? "/api/nginx/certificates/upload" : `/api/nginx/certificates/${editing}/upload`;
      method = "POST";
    }
    await api(path, {method, body: JSON.stringify(payload)});
    editorDialog.close();
    notify(`${labels[currentView]} saved.`);
    await render();
  } catch (error) {
    $("#editor-error").textContent = error.message;
  } finally { submit.disabled = false; }
});

function openAuth() {
  $("#auth-title").textContent = setupRequired ? "Create administrator" : "Sign in";
  $("#auth-copy").textContent = setupRequired ? "Finish first-run setup with the initial administrator account." : "Use your Portwyrm administrator or operator account.";
  $("#auth-error").textContent = "";
  authDialog.showModal();
}

$("#auth-form").addEventListener("submit", async event => {
  event.preventDefault();
  const form = new FormData(event.currentTarget);
  const email = form.get("email");
  const password = form.get("password");
  try {
    if (setupRequired) await api("/api/setup", {method: "POST", body: JSON.stringify({email, password})});
    let result = await api("/api/v2/browser/login", {method: "POST", body: JSON.stringify({identity: email, secret: password, scope: "user"})});
    if (result.result.scope === "mfa") {
      const code = prompt("Enter your authenticator or recovery code:");
      if (!code) throw new Error("MFA verification was cancelled.");
      result = await api("/api/v2/browser/2fa", {method: "POST", body: JSON.stringify({code})});
    }
    sessionActive = true;
    principal = await api("/api/v2/me");
    localStorage.setItem("portwyrm.identity", principal.email);
    setupRequired = false;
    $("#session-label").textContent = principal.email;
    $("#session-action").textContent = "Sign out";
    authDialog.close();
    applyPermissions();
    await render();
  } catch (error) { $("#auth-error").textContent = error.message; }
});

$("nav").addEventListener("click", event => {
  const button = event.target.closest("[data-view]");
  if (!button) return;
  $$("[data-view]").forEach(item => item.removeAttribute("aria-current"));
  button.setAttribute("aria-current", "page");
  render(button.dataset.view);
});

view.addEventListener("click", async event => {
  const button = event.target.closest("[data-action]");
  if (!button) return;
  if (button.dataset.action === "new") await openEditor();
  if (button.dataset.action === "edit") await openEditor(button.dataset.id);
  if (button.dataset.action === "delete" && confirm(`Delete ${labels[currentView]} resource ${button.dataset.id}?`)) {
    try { await api(resourcePath(currentView, button.dataset.id), {method: "DELETE"}); notify("Resource deleted."); await render(); }
    catch (error) { notify(error.message, "error"); }
  }
  if (button.dataset.action === "signin") openAuth();
  if (button.dataset.action === "retry") render();
  if (button.dataset.action === "token-new") {
    const name = prompt("Name this access token:");
    if (!name) return;
    try {
      const created = await api("/api/v2/tokens", {method: "POST", body: JSON.stringify({name, scopes: ["user"]})});
      alert(`Copy this token now. It will not be shown again:\n\n${created.token}`);
      await render("tokens");
    } catch (error) { notify(error.message, "error"); }
  }
  if (button.dataset.action === "token-revoke") {
    if (!confirm("Revoke this access token? Existing automation will stop working.")) return;
    try { await api(`/api/v2/tokens/${button.dataset.id}`, {method: "DELETE"}); await render("tokens"); }
    catch (error) { notify(error.message, "error"); }
  }
  if (button.dataset.action === "mfa-enroll") {
    try {
      const enrollment = await api("/api/v2/mfa/enroll", {method: "POST"});
      const code = prompt(`Add this TOTP secret to your authenticator:\n\n${enrollment.secret}\n\nEnter the current code to confirm:`);
      if (!code) return;
      await api("/api/v2/mfa/confirm", {method: "POST", body: JSON.stringify({code})});
      alert(`Save these one-use recovery codes somewhere safe:\n\n${enrollment.backup_codes.join("\n")}`);
      await render("account");
    } catch (error) { notify(error.message, "error"); }
  }
  if (button.dataset.action === "mfa-disable") {
    const code = prompt("Enter a current authenticator or recovery code to disable MFA:");
    if (!code) return;
    try { await api("/api/v2/mfa", {method: "DELETE", body: JSON.stringify({code})}); await render("account"); }
    catch (error) { notify(error.message, "error"); }
  }
});

createButton.addEventListener("click", () => openEditor());
$("#session-action").addEventListener("click", async () => {
  if (!sessionActive) return openAuth();
  await api("/api/v2/browser/session", {method: "DELETE"}).catch(() => {});
  sessionActive = false;
  principal = null;
  localStorage.removeItem("portwyrm.identity");
  $("#session-label").textContent = "Not signed in";
  $("#session-action").textContent = "Sign in";
  applyPermissions();
  render("dashboard");
});
$("#theme").addEventListener("click", () => {
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem("portwyrm.theme", root.dataset.theme);
});
$$('.close').forEach(button => button.addEventListener("click", () => button.closest("dialog").close()));
document.documentElement.dataset.theme = localStorage.getItem("portwyrm.theme") || "dark";
$("#session-label").textContent = sessionActive ? (localStorage.getItem("portwyrm.identity") || "Signed in") : "Not signed in";
$("#session-action").textContent = sessionActive ? "Sign out" : "Sign in";
$("[data-view=dashboard]").setAttribute("aria-current", "page");

api("/api/setup").then(async result => {
  setupRequired = !result.setup;
  if (sessionActive) {
    try { principal = await api("/api/v2/me"); }
    catch { sessionActive = false; }
  }
  applyPermissions();
  if (setupRequired) openAuth();
}).catch(() => {}).finally(() => render("dashboard"));
