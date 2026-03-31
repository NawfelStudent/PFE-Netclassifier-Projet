/**
 * dashboard.js — Socket.IO + Chart.js + mise à jour temps réel.
 * Chargé uniquement sur la page dashboard.html.
 *
 * Corrections :
 *   - Pause des pollings quand l'onglet est caché (visibilitychange)
 *   - Sanitisation XSS des données reçues via Socket.IO (innerHTML → textContent)
 *   - Gestion d'erreur sur tous les fetch()
 *   - Token CSRF envoyé dans le header X-CSRFToken
 */

// ------------------------------------------------------------------ //
// CSRF TOKEN (meta tag injecté par Flask-WTF dans base.html)         //
// ------------------------------------------------------------------ //
const CSRF_TOKEN = document.querySelector('meta[name="csrf-token"]')?.content ?? "";

function apiFetch(url, options = {}) {
    return fetch(url, {
        ...options,
        headers: {
            "Content-Type": "application/json",
            "X-CSRFToken": CSRF_TOKEN,
            ...(options.headers ?? {}),
        },
    });
}

// ------------------------------------------------------------------ //
// WEBSOCKET                                                           //
// ------------------------------------------------------------------ //
const socket = io("/live");

// ------------------------------------------------------------------ //
// CHARTS                                                              //
// ------------------------------------------------------------------ //
const chartCategories = new Chart(
    document.getElementById("chartCategories").getContext("2d"), {
    type: "doughnut",
    data: {
        labels: ["Streaming", "Réseaux sociaux", "Publicité", "Téléchargement", "Navigation", "Suspect"],
        datasets: [{ data: [0, 0, 0, 0, 0, 0],
            backgroundColor: ["#7c4dff", "#2979ff", "#ff6d00", "#00e676", "#448aff", "#ff1744"] }]
    },
    options: { responsive: true, plugins: { legend: { position: "bottom", labels: { color: "#b0bec5", font: { size: 11 } } } } }
});

const chartActions = new Chart(
    document.getElementById("chartActions").getContext("2d"), {
    type: "doughnut",
    data: {
        labels: ["Allow", "Block", "Limit"],
        datasets: [{ data: [0, 0, 0],
            backgroundColor: ["#00e676", "#ff1744", "#ffa726"] }]
    },
    options: { responsive: true, plugins: { legend: { position: "bottom", labels: { color: "#b0bec5", font: { size: 11 } } } } }
});

const chartTimeline = new Chart(
    document.getElementById("chartTimeline").getContext("2d"), {
    type: "line",
    data: {
        labels: [],
        datasets: [{
            label: "Flux/min", data: [],
            borderColor: "#4fc3f7", borderWidth: 2, tension: 0.3,
            fill: true, backgroundColor: "rgba(79,195,247,0.08)",
            pointRadius: 0
        }]
    },
    options: {
        responsive: true, animation: false,
        scales: {
            x: { ticks: { color: "#546e7a", font: { size: 10 } }, grid: { color: "#1a2332" } },
            y: { ticks: { color: "#546e7a" }, grid: { color: "#2a3a4a" }, beginAtZero: true }
        },
        plugins: { legend: { display: false } }
    }
});

// ------------------------------------------------------------------ //
// HELPERS                                                             //
// ------------------------------------------------------------------ //

/** Échappe une valeur inconnue avant insertion dans le DOM. */
function safe(value) {
    const d = document.createElement("span");
    d.textContent = value ?? "";
    return d.innerHTML;
}

function setText(id, value) {
    const el = document.getElementById(id);
    if (el) el.textContent = value;
}

// ------------------------------------------------------------------ //
// RÉCEPTION FLUX TEMPS RÉEL (Socket.IO)                              //
// ------------------------------------------------------------------ //
socket.on("new_flow", function (f) {
    const tbody = document.getElementById("flowTableBody");
    const row = document.createElement("tr");

    const actionClass = f.action === "Block" ? "badge-block"
                      : f.action === "Limit" ? "badge-limit"
                      : "badge-allow";

    const sniLabel = f.sni || f.requested_server_name || "";
    const appLabel = f.application_name || "";
    const display  = sniLabel ? `${appLabel} [${sniLabel}]` : appLabel;

    // Utilisation de safe() pour éviter XSS sur les données réseau
    row.innerHTML = `
        <td>${safe(new Date().toLocaleTimeString("fr-FR"))}</td>
        <td>${safe(f.username || "?")} <small>(${safe(f.profile || "?")})</small></td>
        <td>${safe(f.src_ip)}:${safe(f.src_port)}</td>
        <td>${safe(f.dst_ip)}:${safe(f.dst_port)}</td>
        <td>${safe(display)}</td>
        <td>${safe(f.category)}</td>
        <td>${f.confidence ? (f.confidence * 100).toFixed(0) + "%" : "-"}</td>
        <td><span class="badge ${actionClass}">${safe(f.action)}</span></td>
    `;
    tbody.insertBefore(row, tbody.firstChild);
    while (tbody.children.length > 80) tbody.removeChild(tbody.lastChild);
});

// ------------------------------------------------------------------ //
// RÉCEPTION STATS AGRÉGÉES (Socket.IO)                               //
// ------------------------------------------------------------------ //
socket.on("stats_update", function (s) {
    setText("kpi-flows",     s.total_flows  ?? 0);
    setText("kpi-bandwidth", ((s.total_bytes ?? 0) / 1048576).toFixed(1));
    setText("kpi-users",     s.active_users ?? 0);
    setText("kpi-blocked",   s.block_count  ?? 0);
    setText("kpi-limited",   s.limit_count  ?? 0);
    setText("kpi-suspect",   s.suspect ?? s.suspect_count ?? 0);

    chartCategories.data.datasets[0].data = [
        s.streaming ?? 0, s.social ?? 0, s.ads      ?? 0,
        s.download  ?? 0, s.web    ?? 0, s.suspect  ?? 0
    ];
    chartCategories.update();

    chartActions.data.datasets[0].data = [
        s.allow_count ?? 0, s.block_count ?? 0, s.limit_count ?? 0
    ];
    chartActions.update();
});

// ------------------------------------------------------------------ //
// POLLING HISTORIQUE (timeline)                                       //
// ------------------------------------------------------------------ //
async function refreshTimeline() {
    try {
        const res = await apiFetch("/api/stats/history?minutes=60");
        if (!res.ok) return;
        const data = await res.json();
        chartTimeline.data.labels              = data.map(d => d.timestamp?.slice(11, 16) ?? "").reverse();
        chartTimeline.data.datasets[0].data    = data.map(d => d.total_flows ?? 0).reverse();
        chartTimeline.update();
    } catch (e) {
        console.warn("Erreur refresh timeline:", e);
    }
}

// Polling backup stats (si Socket.IO déconnecté)
async function refreshKpi() {
    try {
        const res = await apiFetch("/api/stats/realtime");
        if (!res.ok) return;
        const s = await res.json();
        setText("kpi-flows",     s.total_flows ?? 0);
        setText("kpi-bandwidth", ((s.total_bytes ?? 0) / 1048576).toFixed(1));
    } catch (e) { /* silencieux */ }
}

// ------------------------------------------------------------------ //
// GESTION VISIBILITÉ — pause quand onglet caché                      //
// ------------------------------------------------------------------ //
let timelineInterval = null;
let kpiInterval      = null;

function startPolling() {
    if (timelineInterval) return;                // déjà actif
    refreshTimeline();
    timelineInterval = setInterval(refreshTimeline, 10_000);
    kpiInterval      = setInterval(refreshKpi,      15_000);
}

function stopPolling() {
    clearInterval(timelineInterval);
    clearInterval(kpiInterval);
    timelineInterval = null;
    kpiInterval      = null;
}

document.addEventListener("visibilitychange", () => {
    document.hidden ? stopPolling() : startPolling();
});

// Démarrage initial
startPolling();
