const view = document.querySelector("#view");
const title = document.querySelector("#title");
const status = document.querySelector("#status");
const labels = Object.fromEntries([...document.querySelectorAll("[data-view]")].map(b => [b.dataset.view, b.textContent]));
const token = localStorage.getItem("portwyrm.token");
const headers = token ? {Authorization: `Bearer ${token}`} : {};

async function json(path) {
  const response = await fetch(path, {headers});
  if (!response.ok) throw new Error(`${response.status} ${response.statusText}`);
  return response.json();
}

function escapeHtml(value) {
  return String(value)
    .replaceAll("&", "&amp;")
    .replaceAll("<", "&lt;")
    .replaceAll(">", "&gt;")
    .replaceAll('"', "&quot;")
    .replaceAll("'", "&#39;");
}

function table(rows) {
  if (!rows.length) return `<div class="card"><h2>No resources yet</h2><p class="muted">Create the first resource when you are ready.</p></div>`;
  const keys = [...new Set(rows.flatMap(Object.keys))].slice(0, 6);
  return `<div class="table-wrap"><table><thead><tr>${keys.map(k => `<th>${escapeHtml(k)}</th>`).join("")}</tr></thead><tbody>${rows.map(row => `<tr>${keys.map(k => `<td><code>${escapeHtml(row[k] ?? "")}</code></td>`).join("")}</tr>`).join("")}</tbody></table></div>`;
}

async function render(name) {
  title.textContent = labels[name] || "Portwyrm";
  view.innerHTML = `<div class="skeleton"></div>`;
  view.setAttribute("aria-busy", "true");
  status.textContent = "";
  try {
    if (name === "dashboard") {
      const families = ["proxy-hosts", "redirection-hosts", "dead-hosts", "streams", "certificates", "access-lists"];
      const values = await Promise.all(families.map(f => json(`/api/nginx/${f}`).catch(() => [])));
      view.innerHTML = `<div class="grid">${families.map((f, i) => `<article class="card"><div class="muted">${labels[f]}</div><p class="metric">${values[i].length}</p></article>`).join("")}</div>`;
    } else if (name === "health") {
      const data = await json("/api/");
      view.innerHTML = `<article class="card"><h2 class="ok">Control plane available</h2><pre>${escapeHtml(JSON.stringify(data, null, 2))}</pre></article>`;
    } else {
      const prefix = ["users", "settings", "audit-log", "access-tokens"].includes(name) ? "/api" : "/api/nginx";
      const data = await json(`${prefix}/${name}`);
      view.innerHTML = table(Array.isArray(data) ? data : [data]);
    }
  } catch (error) {
    view.innerHTML = `<article class="card"><h2 class="error">Unable to load this view</h2><p>${escapeHtml(error.message)}</p><p class="muted">Authenticate or retry after the control plane is ready.</p></article>`;
    status.textContent = `Error loading ${title.textContent}`;
  } finally { view.setAttribute("aria-busy", "false"); }
}

document.querySelector("nav").addEventListener("click", event => {
  const button = event.target.closest("[data-view]");
  if (!button) return;
  document.querySelectorAll("[data-view]").forEach(b => b.removeAttribute("aria-current"));
  button.setAttribute("aria-current", "page");
  render(button.dataset.view);
});
document.querySelector("#theme").addEventListener("click", () => {
  const root = document.documentElement;
  root.dataset.theme = root.dataset.theme === "dark" ? "light" : "dark";
  localStorage.setItem("portwyrm.theme", root.dataset.theme);
});
document.documentElement.dataset.theme = localStorage.getItem("portwyrm.theme") || "dark";
document.querySelector('[data-view="dashboard"]').setAttribute("aria-current", "page");
render("dashboard");
