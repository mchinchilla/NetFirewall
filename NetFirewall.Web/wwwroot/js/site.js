/* =====================================================================
 * NetFirewall.Web — single centralized JS bundle.
 * Conventions (CLAUDE.md):
 *   - All async work uses async/await; no .then() chains.
 *   - All UI state lives in Alpine stores; no jQuery, no globals.
 *   - Toasts are the canonical UI feedback channel for backend ops.
 * ===================================================================== */

const STORAGE_KEY = "netfw.ui";

const PALETTES = [
    { id: "boulder",     label: "Boulder",     hex: "#767574" },
    { id: "jordy-blue",  label: "Jordy Blue",  hex: "#5a9bd7" },
    { id: "magic-mint",  label: "Magic Mint",  hex: "#70ad8e" },
    { id: "taupe-gray",  label: "Taupe Gray",  hex: "#999883" },
    { id: "twilight",    label: "Twilight",    hex: "#b889bc" },
    { id: "pearl-bush",  label: "Pearl Bush",  hex: "#a99a8a" },
    { id: "woodsmoke",   label: "Woodsmoke",   hex: "#2e2a2a" }
];

const DEFAULT_STATE = Object.freeze({
    theme: "boulder",     // palette id
    mode: "light",        // "light" | "dark"
    sidebar: "auto",      // "auto" | "dark" | "light"
    sidebarCollapsed: false
});

/* ---------- localStorage helpers (async to honor rule #2) ---------- */
async function loadState() {
    try {
        const raw = localStorage.getItem(STORAGE_KEY);
        if (!raw) return { ...DEFAULT_STATE };
        const parsed = JSON.parse(raw);
        return { ...DEFAULT_STATE, ...parsed };
    } catch {
        return { ...DEFAULT_STATE };
    }
}

async function saveState(state) {
    try {
        localStorage.setItem(STORAGE_KEY, JSON.stringify(state));
    } catch {
        /* quota or private mode — ignore silently */
    }
}

function applyDom(state) {
    const html = document.documentElement;
    html.dataset.theme = state.theme;
    html.dataset.mode = state.mode;
    if (state.sidebar === "auto") {
        delete html.dataset.sidebar;
    } else {
        html.dataset.sidebar = state.sidebar;
    }
    html.dataset.sidebarCollapsed = state.sidebarCollapsed ? "true" : "false";
}

/* ---------- Pre-paint hydration (called from <head>, before Alpine boots) ---------- */
window.NetFw = window.NetFw || {};
window.NetFw.hydrateBeforePaint = async function () {
    const state = await loadState();
    applyDom(state);
};

/**
 * Pad a number with a leading zero. Tiny helper used by the runtime tickers.
 */
window.NetFw._pad2 = (n) => String(n).padStart(2, "0");

/**
 * QR-code rendering helper. Centralized so per-page views never construct
 * qrcode() inline (rule #3 — single JS file). Replaces the target's HTML
 * with an inline SVG. Pass cellSize 4-6 for scannable from a phone camera.
 */
window.NetFw.qrcode = {
    render(target, text, opts = {}) {
        if (typeof qrcode !== "function") {
            console.warn("qrcode lib missing");
            return;
        }
        const el = typeof target === "string" ? document.getElementById(target) : target;
        if (!el) return;
        const qr = qrcode(0, opts.errorCorrection || "M");
        qr.addData(text);
        qr.make();
        el.innerHTML = qr.createSvgTag({
            cellSize: opts.cellSize || 5,
            margin: opts.margin ?? 0
        });
    }
};

/**
 * Format a millisecond duration as `Nd HH:MM:SS` (or `HH:MM:SS` for under a day).
 */
window.NetFw.formatUptime = function (ms) {
    const s = Math.max(0, Math.floor(ms / 1000));
    const d = Math.floor(s / 86400);
    const h = Math.floor((s % 86400) / 3600);
    const m = Math.floor((s % 3600) / 60);
    const sec = s % 60;
    const p = window.NetFw._pad2;
    return d > 0 ? `${d}d ${p(h)}:${p(m)}:${p(sec)}` : `${p(h)}:${p(m)}:${p(sec)}`;
};

/**
 * Format a Date as `YYYY-MM-DD HH:MM:SS` in the browser's local timezone.
 */
window.NetFw.formatLocalDateTime = function (date) {
    const p = window.NetFw._pad2;
    return `${date.getFullYear()}-${p(date.getMonth() + 1)}-${p(date.getDate())} ` +
           `${p(date.getHours())}:${p(date.getMinutes())}:${p(date.getSeconds())}`;
};

/**
 * Trigger a browser download of the user's TOTP recovery codes as a .txt file.
 * Called from the enrollment view + Account/Security after regeneration.
 */
window.NetFw.downloadRecoveryCodes = function (codes) {
    if (!Array.isArray(codes) || codes.length === 0) return;
    const body =
        "NetFirewall recovery codes\n\n" +
        codes.join("\n") +
        "\n\nEach code works once. Store them somewhere safe — anyone with one can sign in as you.\n";
    const blob = new Blob([body], { type: "text/plain" });
    const url = URL.createObjectURL(blob);
    const a = document.createElement("a");
    a.href = url;
    a.download = "netfirewall-recovery-codes.txt";
    a.click();
    URL.revokeObjectURL(url);
    window.Alpine?.store("toasts")?.success("Recovery codes downloaded. Store them somewhere safe.");
};

/* =====================================================================
 * Client-side table filter — backs _TableSearch.cshtml in ClientSide mode.
 * Hides <tbody> rows of a target table whose text doesn't contain the query.
 * Used by the non-polling list pages (firewall rules, NAT, port forwards,
 * traffic marks, QoS, schedules, static routes, interfaces, network
 * objects/services). The active query per table id is remembered so it
 * survives HTMX swaps (add/delete refresh, server-side dropdown filters) —
 * see the htmx:afterSwap hook at the bottom of this file. Polling lists
 * (DHCP leases/reservations) filter server-side instead.
 * ===================================================================== */
window.NetFw._tableFilters = window.NetFw._tableFilters || {};

window.NetFw.filterTable = function (tableId, query) {
    window.NetFw._tableFilters[tableId] = query || "";
    window.NetFw._applyTableFilter(tableId);
};

window.NetFw._applyTableFilter = function (tableId) {
    const root = document.getElementById(tableId);
    if (!root) return;
    const q = (window.NetFw._tableFilters[tableId] || "").trim().toLowerCase();
    const rows = root.querySelectorAll("tbody > tr");
    let shown = 0;
    rows.forEach((tr) => {
        const hit = q === "" || tr.textContent.toLowerCase().includes(q);
        tr.classList.toggle("hidden", !hit);
        if (hit) shown++;
    });
    // "No matches" feedback (rule #6) when a query hides every row.
    let notice = root.querySelector("[data-filter-empty]");
    if (q !== "" && rows.length > 0 && shown === 0) {
        if (!notice) {
            notice = document.createElement("div");
            notice.setAttribute("data-filter-empty", "");
            notice.className = "text-sm py-10 text-center text-surface-fg-muted";
            root.appendChild(notice);
        }
        notice.textContent = `No matches for “${window.NetFw._tableFilters[tableId]}”.`;
        notice.classList.remove("hidden");
    } else if (notice) {
        notice.classList.add("hidden");
    }
};

/* =====================================================================
 * Chart.js integration — exposed as window.NetFw.charts
 * Centralized so views never construct Chart() inline (rule #3 — single
 * JS file). Charts auto-retint when the user changes theme/mode.
 * ===================================================================== */
window.NetFw.charts = {
    _instances: new Set(),

    /** Resolve a CSS custom property to a real `rgb(...)` string. */
    readColor(varName) {
        const probe = document.createElement("div");
        probe.style.color = `var(--${varName})`;
        probe.style.display = "none";
        document.body.appendChild(probe);
        const c = getComputedStyle(probe).color;
        probe.remove();
        return c;
    },

    _withAlpha(rgbString, alpha) {
        // getComputedStyle returns "rgb(R, G, B)" or "rgba(R, G, B, A)"
        const m = rgbString.match(/rgba?\(([^)]+)\)/);
        if (!m) return rgbString;
        const parts = m[1].split(",").map(s => s.trim());
        const [r, g, b] = parts;
        return `rgba(${r}, ${g}, ${b}, ${alpha})`;
    },

    _verticalGradient(ctx, height, color) {
        const g = ctx.createLinearGradient(0, 0, 0, height || 200);
        g.addColorStop(0, this._withAlpha(color, 0.35));
        g.addColorStop(1, this._withAlpha(color, 0));
        return g;
    },

    register(chart, retintFn) {
        chart._netfwRetint = retintFn;
        this._instances.add(chart);
    },

    retintAll() {
        for (const chart of this._instances) {
            try {
                if (typeof chart._netfwRetint === "function") chart._netfwRetint();
                chart.update("none");
            } catch { /* chart may have been destroyed by a navigation */ }
        }
    },

    /**
     * Traffic line chart used on the dashboard.
     * data = { labels: string[], inSeries: number[], outSeries: number[] }
     */
    makeTraffic(canvasEl, data) {
        const ctx = canvasEl.getContext("2d");
        const accent = this.readColor("accent");
        const secondary = this.readColor("jordy-blue-500");
        const fgMuted = this.readColor("surface-fg-muted");
        const border = this.readColor("surface-border");
        const elevated = this.readColor("surface-elevated");
        const fg = this.readColor("surface-fg");

        const chart = new Chart(canvasEl, {
            type: "line",
            data: {
                labels: data.labels,
                datasets: [
                    {
                        label: "In",
                        data: data.inSeries,
                        borderColor: accent,
                        backgroundColor: this._verticalGradient(ctx, canvasEl.clientHeight, accent),
                        fill: true,
                        tension: 0.38,
                        pointRadius: 0,
                        borderWidth: 2
                    },
                    {
                        label: "Out",
                        data: data.outSeries,
                        borderColor: secondary,
                        backgroundColor: "transparent",
                        borderDash: [4, 4],
                        tension: 0.38,
                        pointRadius: 0,
                        borderWidth: 2
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: {
                        display: true,
                        position: "bottom",
                        labels: { color: fgMuted, boxWidth: 10, boxHeight: 10, padding: 16, font: { size: 11 } }
                    },
                    tooltip: {
                        backgroundColor: elevated, titleColor: fg, bodyColor: fgMuted,
                        borderColor: border, borderWidth: 1, padding: 10, displayColors: true
                    }
                },
                scales: {
                    x: { grid: { display: false }, ticks: { color: fgMuted, maxTicksLimit: 8, font: { size: 10 } } },
                    y: {
                        grid: { color: border, drawTicks: false },
                        ticks: { color: fgMuted, font: { size: 10 }, callback: (v) => v + " Mbps" },
                        beginAtZero: true
                    }
                }
            }
        });

        this.register(chart, () => {
            const a = this.readColor("accent");
            const s = this.readColor("jordy-blue-500");
            const fm = this.readColor("surface-fg-muted");
            const bd = this.readColor("surface-border");
            const el = this.readColor("surface-elevated");
            const f = this.readColor("surface-fg");
            chart.data.datasets[0].borderColor = a;
            chart.data.datasets[0].backgroundColor = this._verticalGradient(ctx, canvasEl.clientHeight, a);
            chart.data.datasets[1].borderColor = s;
            chart.options.plugins.legend.labels.color = fm;
            chart.options.plugins.tooltip.backgroundColor = el;
            chart.options.plugins.tooltip.titleColor = f;
            chart.options.plugins.tooltip.bodyColor = fm;
            chart.options.plugins.tooltip.borderColor = bd;
            chart.options.scales.x.ticks.color = fm;
            chart.options.scales.y.ticks.color = fm;
            chart.options.scales.y.grid.color = bd;
        });

        return chart;
    },

    /**
     * System resource history — CPU%, Memory%, Load avg (×10 for visibility) on a 0-100 scale.
     * data = { labels: string[], cpu: number[], memory: number[], load: number[] }
     */
    makeSystemHistory(canvasEl, data) {
        const accent = this.readColor("accent");
        const warn   = this.readColor("feedback-warning-fg");
        const ok     = this.readColor("feedback-success-fg");
        const fgMuted = this.readColor("surface-fg-muted");
        const border = this.readColor("surface-border");
        const elevated = this.readColor("surface-elevated");
        const fg = this.readColor("surface-fg");

        const chart = new Chart(canvasEl, {
            type: "line",
            data: {
                labels: data.labels,
                datasets: [
                    { label: "CPU %",    data: data.cpu,    borderColor: accent, backgroundColor: "transparent", tension: 0.3, pointRadius: 0, borderWidth: 2 },
                    { label: "Memory %", data: data.memory, borderColor: ok,     backgroundColor: "transparent", tension: 0.3, pointRadius: 0, borderWidth: 2 },
                    { label: "Load×10",  data: data.load.map(v => v * 10), borderColor: warn, backgroundColor: "transparent", borderDash: [4, 4], tension: 0.3, pointRadius: 0, borderWidth: 2 }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: { display: true, position: "bottom", labels: { color: fgMuted, boxWidth: 10, boxHeight: 10, padding: 14, font: { size: 11 } } },
                    tooltip: { backgroundColor: elevated, titleColor: fg, bodyColor: fgMuted, borderColor: border, borderWidth: 1, padding: 10 }
                },
                scales: {
                    x: { grid: { display: false }, ticks: { color: fgMuted, maxTicksLimit: 8, font: { size: 10 } } },
                    y: { grid: { color: border, drawTicks: false }, ticks: { color: fgMuted, font: { size: 10 } }, beginAtZero: true }
                }
            }
        });
        this.register(chart, () => {
            chart.data.datasets[0].borderColor = this.readColor("accent");
            chart.data.datasets[1].borderColor = this.readColor("feedback-success-fg");
            chart.data.datasets[2].borderColor = this.readColor("feedback-warning-fg");
            const fm = this.readColor("surface-fg-muted");
            const bd = this.readColor("surface-border");
            chart.options.plugins.legend.labels.color = fm;
            chart.options.scales.x.ticks.color = fm;
            chart.options.scales.y.ticks.color = fm;
            chart.options.scales.y.grid.color = bd;
        });
        return chart;
    },

    /**
     * Network bandwidth history — RX + TX rates (bytes/sec). Y-axis labels auto-scale to KB/MB/GB.
     * data = { labels: string[], rx: number[], tx: number[] }
     */
    makeNetworkHistory(canvasEl, data) {
        const ctx = canvasEl.getContext("2d");
        const accent = this.readColor("accent");
        const secondary = this.readColor("jordy-blue-500");
        const fgMuted = this.readColor("surface-fg-muted");
        const border = this.readColor("surface-border");
        const elevated = this.readColor("surface-elevated");
        const fg = this.readColor("surface-fg");

        const fmtBps = (v) => {
            const u = ["B/s", "KB/s", "MB/s", "GB/s"];
            let i = 0; let x = v;
            while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
            return `${x.toFixed(1)} ${u[i]}`;
        };

        const chart = new Chart(canvasEl, {
            type: "line",
            data: {
                labels: data.labels,
                datasets: [
                    { label: "RX", data: data.rx, borderColor: accent,    backgroundColor: this._verticalGradient(ctx, canvasEl.clientHeight, accent), fill: true, tension: 0.3, pointRadius: 0, borderWidth: 2 },
                    { label: "TX", data: data.tx, borderColor: secondary, backgroundColor: "transparent", borderDash: [4, 4], tension: 0.3, pointRadius: 0, borderWidth: 2 }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: { display: true, position: "bottom", labels: { color: fgMuted, boxWidth: 10, boxHeight: 10, padding: 14, font: { size: 11 } } },
                    tooltip: { backgroundColor: elevated, titleColor: fg, bodyColor: fgMuted, borderColor: border, borderWidth: 1, padding: 10, callbacks: { label: (it) => `${it.dataset.label}: ${fmtBps(it.parsed.y)}` } }
                },
                scales: {
                    x: { grid: { display: false }, ticks: { color: fgMuted, maxTicksLimit: 8, font: { size: 10 } } },
                    y: { grid: { color: border, drawTicks: false }, ticks: { color: fgMuted, font: { size: 10 }, callback: fmtBps }, beginAtZero: true }
                }
            }
        });
        this.register(chart, () => {
            const a = this.readColor("accent");
            const s = this.readColor("jordy-blue-500");
            const fm = this.readColor("surface-fg-muted");
            const bd = this.readColor("surface-border");
            chart.data.datasets[0].borderColor = a;
            chart.data.datasets[0].backgroundColor = this._verticalGradient(ctx, canvasEl.clientHeight, a);
            chart.data.datasets[1].borderColor = s;
            chart.options.plugins.legend.labels.color = fm;
            chart.options.scales.x.ticks.color = fm;
            chart.options.scales.y.ticks.color = fm;
            chart.options.scales.y.grid.color = bd;
        });
        return chart;
    },

    /**
     * Live throughput sparkline — a compact in/out line chart updated IN PLACE
     * (no canvas re-creation), so a polling caller can refresh it every few
     * seconds without leaking Chart.js instances. Returns the chart; feed it new
     * data via updateSparkline(chart, data).
     * data = { labels: string[], inSeries: number[], outSeries: number[] }
     */
    makeSparkline(canvasEl, data) {
        const ctx = canvasEl.getContext("2d");
        const accent = this.readColor("accent");
        const secondary = this.readColor("jordy-blue-500");
        const fgMuted = this.readColor("surface-fg-muted");
        const elevated = this.readColor("surface-elevated");
        const fg = this.readColor("surface-fg");

        const chart = new Chart(canvasEl, {
            type: "line",
            data: {
                labels: data.labels,
                datasets: [
                    {
                        label: "In", data: data.inSeries,
                        borderColor: accent,
                        backgroundColor: this._verticalGradient(ctx, canvasEl.clientHeight, accent),
                        fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2
                    },
                    {
                        label: "Out", data: data.outSeries,
                        borderColor: secondary, backgroundColor: "transparent",
                        borderDash: [4, 4], tension: 0.35, pointRadius: 0, borderWidth: 2
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,                       // live updates shouldn't animate
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: elevated, titleColor: fg, bodyColor: fgMuted,
                        borderColor: this.readColor("surface-border"), borderWidth: 1, padding: 8,
                        callbacks: { label: (c) => `${c.dataset.label}: ${c.parsed.y} Mbps` }
                    }
                },
                scales: {
                    x: { display: false },
                    y: { display: false, beginAtZero: true }
                }
            }
        });

        this.register(chart, () => {
            chart.data.datasets[0].borderColor = this.readColor("accent");
            chart.data.datasets[0].backgroundColor =
                this._verticalGradient(ctx, canvasEl.clientHeight, this.readColor("accent"));
            chart.data.datasets[1].borderColor = this.readColor("jordy-blue-500");
        });
        return chart;
    },

    /** Replace a sparkline's data in place (no re-create). */
    updateSparkline(chart, data) {
        if (!chart) return;
        chart.data.labels = data.labels;
        chart.data.datasets[0].data = data.inSeries;
        chart.data.datasets[1].data = data.outSeries;
        chart.update("none");
    },

    /**
     * Single-series sparkline (e.g. CPU% or Memory%) updated in place. y-axis is
     * fixed 0-100 when `percent` is true so the line reflects real load, not a
     * rescaled view. data = { labels: string[], values: number[] }.
     */
    makeSparklineSingle(canvasEl, data, percent) {
        const ctx = canvasEl.getContext("2d");
        const accent = this.readColor("accent");
        const elevated = this.readColor("surface-elevated");
        const fg = this.readColor("surface-fg");
        const fgMuted = this.readColor("surface-fg-muted");

        const chart = new Chart(canvasEl, {
            type: "line",
            data: {
                labels: data.labels,
                datasets: [{
                    data: data.values,
                    borderColor: accent,
                    backgroundColor: this._verticalGradient(ctx, canvasEl.clientHeight, accent),
                    fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2
                }]
            },
            options: {
                responsive: true, maintainAspectRatio: false, animation: false,
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: elevated, titleColor: fg, bodyColor: fgMuted,
                        borderColor: this.readColor("surface-border"), borderWidth: 1, padding: 8,
                        callbacks: { label: (c) => `${c.parsed.y}${percent ? "%" : ""}` }
                    }
                },
                scales: {
                    x: { display: false },
                    y: { display: false, beginAtZero: true, max: percent ? 100 : undefined }
                }
            }
        });

        this.register(chart, () => {
            const a = this.readColor("accent");
            chart.data.datasets[0].borderColor = a;
            chart.data.datasets[0].backgroundColor = this._verticalGradient(ctx, canvasEl.clientHeight, a);
        });
        return chart;
    },

    /** Replace a single-series sparkline's data in place. */
    updateSparklineSingle(chart, data) {
        if (!chart) return;
        chart.data.labels = data.labels;
        chart.data.datasets[0].data = data.values;
        chart.update("none");
    }
};

/* ---------- Alpine wiring ---------- */
document.addEventListener("alpine:init", () => {

    /* ---------- runtimeMetrics ---------- live clock + uptime for system-info card.
     * Pass the server's startedAt (epoch ms) as a constructor arg:
     *   <div x-data="runtimeMetrics(@startedAtMs)" ...>
     * Exposes:
     *   x-text="clock"    -- "YYYY-MM-DD HH:MM:SS" (browser local TZ)
     *   x-text="uptime"   -- "Nd HH:MM:SS" or "HH:MM:SS"
     */
    Alpine.data("runtimeMetrics", (startedAtMs) => ({
        startedAtMs: Number(startedAtMs) || Date.now(),
        nowMs: Date.now(),
        _timer: null,
        init() {
            this._timer = window.setInterval(() => { this.nowMs = Date.now(); }, 1000);
        },
        destroy() {
            if (this._timer) window.clearInterval(this._timer);
        },
        get clock()  { return window.NetFw.formatLocalDateTime(new Date(this.nowMs)); },
        get uptime() { return window.NetFw.formatUptime(this.nowMs - this.startedAtMs); }
    }));

    /* ---------- liveSparkline ---------- polls a JSON series endpoint and
     * updates a Chart.js sparkline IN PLACE every `intervalMs`. Pauses while the
     * tab is hidden. Cleans up its chart + timer on destroy so HTMX swaps and
     * navigations don't leak. Usage:
     *   x-data="liveSparkline('/Home/ThroughputSeries', 10000)"
     *   <canvas x-ref="spark"></canvas>
     */
    Alpine.data("liveSparkline", (url, intervalMs) => ({
        _chart: null,
        _timer: null,
        async init() {
            const data = await this._fetch();
            this._chart = window.NetFw.charts.makeSparkline(this.$refs.spark, data);
            this._timer = window.setInterval(() => {
                if (!document.hidden) this._refresh();
            }, Number(intervalMs) || 10000);
        },
        destroy() {
            if (this._timer) window.clearInterval(this._timer);
            try { this._chart?.destroy(); } catch { /* already gone */ }
        },
        async _fetch() {
            try {
                const r = await fetch(url, { headers: { "X-Requested-With": "XMLHttpRequest" } });
                if (!r.ok) return { labels: [], inSeries: [], outSeries: [] };
                return await r.json();
            } catch {
                return { labels: [], inSeries: [], outSeries: [] };
            }
        },
        async _refresh() {
            const data = await this._fetch();
            window.NetFw.charts.updateSparkline(this._chart, data);
        }
    }));

    /* ---------- liveStat ---------- like liveSparkline but for a single metric
     * (CPU% / Memory%). Polls a JSON endpoint, reads `field` from the response,
     * shows the latest value reactively (x-text="current") and keeps a fixed
     * 0-100 sparkline updated in place. Usage:
     *   x-data="liveStat('/Home/SystemSeries', 'cpu', 10000)"
     *   <span x-text="current + '%'"></span>
     *   <canvas x-ref="spark"></canvas>
     */
    Alpine.data("liveStat", (url, field, intervalMs) => ({
        current: "—",
        _chart: null,
        _timer: null,
        async init() {
            const data = await this._series();
            this._chart = window.NetFw.charts.makeSparklineSingle(this.$refs.spark, data, true);
            this._setCurrent(data.values);
            this._timer = window.setInterval(() => {
                if (!document.hidden) this._refresh();
            }, Number(intervalMs) || 10000);
        },
        destroy() {
            if (this._timer) window.clearInterval(this._timer);
            try { this._chart?.destroy(); } catch { /* already gone */ }
        },
        async _series() {
            try {
                const r = await fetch(url, { headers: { "X-Requested-With": "XMLHttpRequest" } });
                if (!r.ok) return { labels: [], values: [] };
                const j = await r.json();
                return { labels: j.labels || [], values: (j[field] || []) };
            } catch {
                return { labels: [], values: [] };
            }
        },
        _setCurrent(values) {
            this.current = values.length ? values[values.length - 1] : "—";
        },
        async _refresh() {
            const data = await this._series();
            window.NetFw.charts.updateSparklineSingle(this._chart, data);
            this._setCurrent(data.values);
        }
    }));

    /* ---------- addressPicker ---------- tag input with object autocomplete.
     * Used in firewall rule editors (filter/NAT/port forward/mangle) for
     * source/destination address fields. Stores the comma-separated value in
     * a hidden input so server-side parsing stays unchanged.
     *
     * Backing store: <input type="hidden" name="..." x-ref="hidden">
     * Visible UI: tag chips + text input + dropdown of suggestions.
     *
     * Each tag is either a literal CIDR/IP or an object name (the resolver
     * disambiguates server-side, so we only need to pass the strings through).
     *
     *   <div x-data="addressPicker()" data-initial="192.168.1.0/24, DB_SERVERS">
     *     <input type="hidden" x-ref="hidden" name="SourceAddresses" :value="csv">
     *     ...template...
     *   </div>
     */
    Alpine.data("addressPicker", () => ({
        tags: [],            // current chips
        input: "",           // text the user is typing
        suggestions: [],     // current dropdown rows
        open: false,         // dropdown open?
        active: -1,          // keyboard-highlighted suggestion index
        _searchTimer: null,

        init() {
            // Initial CSV comes from data-initial (set server-side). Reading it
            // from a data-attribute instead of an x-data argument avoids quoting
            // bugs when the value contains commas/quotes inside the HTML attribute.
            this.tags = (this.$el.dataset.initial || "")
                .split(",")
                .map(s => s.trim())
                .filter(s => s.length > 0);
        },

        get csv() { return this.tags.join(", "); },

        looksLikeLiteral(v) {
            return v.includes("/") || v.includes("-") || /^\d+\.\d+\.\d+\.\d+$/.test(v);
        },

        addTag(value) {
            const v = (value || "").trim();
            if (!v) return;
            if (!this.tags.includes(v)) this.tags.push(v);
            this.input = "";
            this.suggestions = [];
            this.open = false;
            this.active = -1;
            this.$nextTick(() => this.$refs.hidden && (this.$refs.hidden.value = this.csv));
        },

        removeTag(idx) {
            this.tags.splice(idx, 1);
            this.$nextTick(() => this.$refs.hidden && (this.$refs.hidden.value = this.csv));
        },

        async search() {
            if (this._searchTimer) clearTimeout(this._searchTimer);
            const q = this.input.trim();
            if (!q) { this.suggestions = []; this.open = false; return; }

            this._searchTimer = setTimeout(async () => {
                try {
                    const resp = await fetch(`/Network/Objects/autocomplete?q=${encodeURIComponent(q)}`, {
                        headers: { "Accept": "application/json" }
                    });
                    if (!resp.ok) { this.suggestions = []; return; }
                    this.suggestions = await resp.json();
                    this.open = this.suggestions.length > 0;
                    this.active = this.suggestions.length > 0 ? 0 : -1;
                } catch {
                    this.suggestions = [];
                    this.open = false;
                }
            }, 150); // debounce
        },

        onKey(e) {
            if (e.key === "ArrowDown") {
                e.preventDefault();
                if (this.suggestions.length === 0) return;
                this.active = (this.active + 1) % this.suggestions.length;
                this.open = true;
            } else if (e.key === "ArrowUp") {
                e.preventDefault();
                if (this.suggestions.length === 0) return;
                this.active = (this.active - 1 + this.suggestions.length) % this.suggestions.length;
            } else if (e.key === "Enter") {
                e.preventDefault();
                if (this.open && this.active >= 0) this.addTag(this.suggestions[this.active].name);
                else if (this.input.trim()) this.addTag(this.input);
            } else if (e.key === "," || e.key === " ") {
                if (this.input.trim()) { e.preventDefault(); this.addTag(this.input); }
            } else if (e.key === "Backspace" && !this.input && this.tags.length > 0) {
                this.removeTag(this.tags.length - 1);
            } else if (e.key === "Escape") {
                this.open = false;
                this.active = -1;
            }
        }
    }));

    /* ---------- portPicker ---------- mirror of addressPicker but L4-aware.
     * Used in firewall rule destination_ports fields. Tags are either literal
     * numeric ports / "start-end" ranges, or service names from /Network/Services.
     * Same hidden-input pattern so server-side parsing stays unchanged.
     */
    Alpine.data("portPicker", () => ({
        tags: [],
        input: "",
        suggestions: [],
        open: false,
        active: -1,
        _searchTimer: null,

        init() {
            // Initial CSV via data-initial (see addressPicker for rationale).
            this.tags = (this.$el.dataset.initial || "")
                .split(",")
                .map(s => s.trim())
                .filter(s => s.length > 0);
        },

        get csv() { return this.tags.join(", "); },

        looksLikeLiteral(v) {
            // Pure number, or "start-end" with both halves numeric
            if (/^\d+$/.test(v)) return true;
            const dash = v.indexOf("-");
            if (dash > 0 && dash < v.length - 1) {
                const left = v.slice(0, dash).trim();
                const right = v.slice(dash + 1).trim();
                return /^\d+$/.test(left) && /^\d+$/.test(right);
            }
            return false;
        },

        addTag(value) {
            const v = (value || "").trim();
            if (!v) return;
            if (!this.tags.includes(v)) this.tags.push(v);
            this.input = "";
            this.suggestions = [];
            this.open = false;
            this.active = -1;
            this.$nextTick(() => this.$refs.hidden && (this.$refs.hidden.value = this.csv));
        },

        removeTag(idx) {
            this.tags.splice(idx, 1);
            this.$nextTick(() => this.$refs.hidden && (this.$refs.hidden.value = this.csv));
        },

        async search() {
            if (this._searchTimer) clearTimeout(this._searchTimer);
            const q = this.input.trim();
            if (!q) { this.suggestions = []; this.open = false; return; }

            this._searchTimer = setTimeout(async () => {
                try {
                    const resp = await fetch(`/Network/Services/autocomplete?q=${encodeURIComponent(q)}`, {
                        headers: { "Accept": "application/json" }
                    });
                    if (!resp.ok) { this.suggestions = []; return; }
                    this.suggestions = await resp.json();
                    this.open = this.suggestions.length > 0;
                    this.active = this.suggestions.length > 0 ? 0 : -1;
                } catch {
                    this.suggestions = [];
                    this.open = false;
                }
            }, 150);
        },

        onKey(e) {
            if (e.key === "ArrowDown") {
                e.preventDefault();
                if (this.suggestions.length === 0) return;
                this.active = (this.active + 1) % this.suggestions.length;
                this.open = true;
            } else if (e.key === "ArrowUp") {
                e.preventDefault();
                if (this.suggestions.length === 0) return;
                this.active = (this.active - 1 + this.suggestions.length) % this.suggestions.length;
            } else if (e.key === "Enter") {
                e.preventDefault();
                if (this.open && this.active >= 0) this.addTag(this.suggestions[this.active].name);
                else if (this.input.trim()) this.addTag(this.input);
            } else if (e.key === "," || e.key === " ") {
                if (this.input.trim()) { e.preventDefault(); this.addTag(this.input); }
            } else if (e.key === "Backspace" && !this.input && this.tags.length > 0) {
                this.removeTag(this.tags.length - 1);
            } else if (e.key === "Escape") {
                this.open = false;
                this.active = -1;
            }
        }
    }));

    /* ---------- wizardStep2Lan ----------
     * Live overlap detection + DHCP range sizing for the Setup Wizard's Step 2.
     *
     *   <form x-data='wizardStep2Lan({ wans: @Json.Serialize(Model.WanCidrs), rows: N })'>
     *     <article x-data="{ cidr: '...', rangeStart: '...', rangeEnd: '...' }">
     *       ... :class="{ 'input-error': $root.wanOverlap(cidr) || $root.peerOverlap(cidr, index) }"
     *       <span x-text="$root.rangeSize(rangeStart, rangeEnd) + ' usable IPs'"></span>
     *
     * Helpers are pure functions over CIDR strings — no DOM access — so individual
     * rows can call them from per-card Alpine state without coordination.
     */
    Alpine.data("wizardStep2Lan", ({ wans = [], rows = 0 } = {}) => ({
        wans: Array.isArray(wans) ? wans : [],
        rowCidrs: Array.from({ length: rows }, () => ""),

        _ipv4ToInt(ip) {
            const m = /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/.exec(String(ip || "").trim());
            if (!m) return null;
            const parts = m.slice(1, 5).map(Number);
            if (parts.some(p => p < 0 || p > 255)) return null;
            return (parts[0] << 24 >>> 0) + (parts[1] << 16) + (parts[2] << 8) + parts[3];
        },

        _parseCidr(cidr) {
            const s = String(cidr || "").trim();
            const slash = s.indexOf("/");
            if (slash < 0) return null;
            const ip = this._ipv4ToInt(s.slice(0, slash));
            const prefix = parseInt(s.slice(slash + 1), 10);
            if (ip === null || isNaN(prefix) || prefix < 0 || prefix > 32) return null;
            return { ip, prefix };
        },

        cidrOverlap(a, b) {
            const pa = this._parseCidr(a), pb = this._parseCidr(b);
            if (!pa || !pb) return false;
            const min = Math.min(pa.prefix, pb.prefix);
            const mask = min === 0 ? 0 : (0xFFFFFFFF << (32 - min)) >>> 0;
            return ((pa.ip & mask) >>> 0) === ((pb.ip & mask) >>> 0);
        },

        wanOverlap(cidr) {
            if (!cidr) return false;
            return this.wans.some(w => this.cidrOverlap(cidr, w));
        },

        peerOverlap(cidr, idx) {
            if (!cidr) return false;
            return this.rowCidrs.some((c, i) => i !== idx && c && this.cidrOverlap(cidr, c));
        },

        setRowCidr(idx, cidr) { this.rowCidrs[idx] = cidr || ""; },

        /** "192.168.1.10" "192.168.1.250" → 241 usable IPs. Returns "—" on bad input. */
        rangeSize(start, end) {
            const s = this._ipv4ToInt(start), e = this._ipv4ToInt(end);
            if (s === null || e === null || e < s) return "—";
            return String(e - s + 1);
        }
    }));

    /* ---------- wizardApplyProgress ----------
     * Modal that tracks the four sub-steps of /setup/wizard/complete. Server-side
     * the four ApplyXAsync calls happen inline in one POST, so we can't stream
     * per-step events without a refactor. Instead we paint the modal optimistically
     * and reconcile on response:
     *   - apply-progress  → reset, mark first step running, show modal
     *   - wizard-apply-done with ok=true → all four become "ok"
     *   - wizard-apply-done with ok=false → find which step the error message
     *       names (e.g. "WireGuard apply failed") and mark it "fail"; earlier
     *       steps become "ok" since the server runs them sequentially.
     */
    Alpine.data("wizardApplyProgress", () => ({
        visible: false,
        done:    false,
        steps: [
            { key: "interfaces", label: "Interfaces → fw_interfaces", state: "pending", match: /interface/i },
            { key: "lan",        label: "DHCP scopes → dhcp_subnets",  state: "pending", match: /(lan|dhcp|subnet)/i },
            { key: "firewall",   label: "Firewall rules → fw_filter_rules / fw_nat_rules", state: "pending", match: /(firewall|nft|filter|nat)/i },
            { key: "services",   label: "Services (DNS / WireGuard / QoS)", state: "pending", match: /(dns|wireguard|wg|qos|tc)/i }
        ],

        onStart() {
            this.done = false;
            this.visible = true;
            this.steps.forEach((s, i) => { s.state = i === 0 ? "running" : "pending"; });
        },

        onDone(e) {
            const ok = !!(e?.detail?.ok);
            const body = e?.detail?.response || "";

            if (ok) {
                this.steps.forEach(s => s.state = "ok");
            } else {
                // Find which step the failure message points at. Default to the
                // last step still pending/running so the user sees the failure
                // somewhere even if our regex misses.
                let msg = "";
                try { msg = JSON.parse(body)?.message || ""; } catch { msg = body; }

                let failIdx = this.steps.findIndex(s => s.match.test(msg));
                if (failIdx < 0) failIdx = this.steps.findIndex(s => s.state !== "ok");
                if (failIdx < 0) failIdx = this.steps.length - 1;

                this.steps.forEach((s, i) => {
                    if (i <  failIdx) s.state = "ok";
                    else if (i === failIdx) s.state = "fail";
                    else s.state = "pending";
                });
            }
            this.done = true;
        }
    }));

    Alpine.store("ui", {
        ...DEFAULT_STATE,
        palettes: PALETTES,

        async init() {
            const persisted = await loadState();
            Object.assign(this, persisted);
            applyDom(this);
        },

        async setTheme(theme) {
            this.theme = theme;
            applyDom(this);
            await saveState(this.snapshot());
        },

        async setMode(mode) {
            this.mode = mode;
            applyDom(this);
            await saveState(this.snapshot());
        },

        async setSidebarVariant(variant) {
            this.sidebar = variant;
            applyDom(this);
            await saveState(this.snapshot());
        },

        async toggleSidebar() {
            this.sidebarCollapsed = !this.sidebarCollapsed;
            applyDom(this);
            await saveState(this.snapshot());
        },

        snapshot() {
            return {
                theme: this.theme,
                mode: this.mode,
                sidebar: this.sidebar,
                sidebarCollapsed: this.sidebarCollapsed
            };
        }
    });

    // Re-tint all live charts whenever theme, mode or sidebar variant changes.
    Alpine.effect(() => {
        const ui = Alpine.store("ui");
        // Touch the reactive props so the effect tracks them:
        void ui.theme; void ui.mode; void ui.sidebar;
        // Defer one frame so the CSS variables have been recomputed.
        requestAnimationFrame(() => window.NetFw.charts.retintAll());
    });

    /* ---------- Drawer store (singleton lateral drawer) ----------
     * Opens HTMX-loaded content into #drawer-body.
     *   Alpine.store('drawer').open({ title: 'Edit interface', url: '/network/edit/eth0' })
     * For inline content (no HTMX fetch), call openRaw(title) and inject yourself.
     */
    Alpine.store("drawer", {
        open: false,
        title: "",
        loading: false,

        openRaw(title) {
            this.title = title || "";
            this.loading = false;
            this.open = true;
        },

        async openUrl({ title = "", url } = {}) {
            this.title = title;
            this.loading = true;
            this.open = true;
            try {
                const res = await fetch(url, { headers: { "HX-Request": "true" } });
                const html = await res.text();
                const target = document.getElementById("drawer-body");
                if (target) target.innerHTML = html;
                if (window.htmx) window.htmx.process(target);
                // Manual injection bypasses htmx:afterSwap, so init Alpine on the
                // new subtree ourselves (x-data/x-init pickers, etc.).
                if (target && window.Alpine?.initTree) window.Alpine.initTree(target);
            } catch (err) {
                window.Alpine?.store("toasts")?.error(`Failed to load: ${err.message}`);
                this.close();
                return;
            } finally {
                this.loading = false;
            }
        },

        close() {
            this.open = false;
        }
    });

    /* ---------- Confirm dialog store ----------
     * Singleton modal rendered once by _ConfirmDialog.cshtml in _Layout.
     * Two ways to use (both async per rule #2):
     *   1. Promise:  const ok = await Alpine.store('confirm').ask({title, message, level});
     *                if (ok) { ... await fetch() ... }
     *   2. Callback: Alpine.store('confirm').open({title, message, onConfirm: async () => {...}});
     */
    Alpine.store("confirm", {
        open: false,
        title: "Confirm action",
        message: "",
        confirmLabel: "Confirm",
        cancelLabel: "Cancel",
        level: "default",          // "default" | "danger" | "warning"
        _resolver: null,
        _onConfirm: null,

        ask(opts = {}) {
            this._show(opts);
            return new Promise((resolve) => { this._resolver = resolve; });
        },

        show(opts = {}) {
            this._show({ ...opts, _onConfirm: opts.onConfirm });
        },

        _show(opts) {
            this.title        = opts.title        ?? "Confirm action";
            this.message      = opts.message      ?? "";
            this.confirmLabel = opts.confirmLabel ?? "Confirm";
            this.cancelLabel  = opts.cancelLabel  ?? "Cancel";
            this.level        = opts.level        ?? "default";
            this._onConfirm   = opts._onConfirm   ?? null;
            this.open = true;
        },

        async confirm() {
            const onConfirm = this._onConfirm;
            const resolver  = this._resolver;
            this._teardown();
            if (typeof onConfirm === "function") { await onConfirm(); }
            if (resolver) { resolver(true); }
        },

        cancel() {
            const resolver = this._resolver;
            this._teardown();
            if (resolver) { resolver(false); }
        },

        _teardown() {
            this.open = false;
            this._resolver = null;
            this._onConfirm = null;
        }
    });

    /* ---------- Elevation store (TOTP step-up modal) ----------
     * Opened automatically when any HTMX request hits a [RequireElevated]
     * endpoint and gets back HX-Trigger:showElevationModal. Stores the
     * original request so it can be replayed verbatim after success.
     */
    Alpine.store("elevation", {
        open: false,
        code: "",
        error: "",
        busy: false,
        retry: null, // { url, method }

        request(retry) {
            this.retry = retry || null;
            this.code = "";
            this.error = "";
            this.busy = false;
            this.open = true;
            // Focus the input next tick (after x-show toggles).
            requestAnimationFrame(() => document.getElementById("elev-code")?.focus());
        },

        cancel() {
            this.open = false;
            this.retry = null;
            this.code = "";
        },

        async submit() {
            if (this.busy) return;
            const code = (this.code || "").trim();
            if (!/^\d{6}$/.test(code)) {
                this.error = "Enter the 6-digit code from your authenticator.";
                return;
            }
            this.error = "";
            this.busy = true;

            const meta = document.querySelector('meta[name="request-token"]');
            const form = new FormData();
            form.append("code", code);
            form.append("retryUrl", this.retry?.url ?? "");
            form.append("retryMethod", this.retry?.method ?? "");

            try {
                const res = await fetch("/auth/elevate", {
                    method: "POST",
                    body: form,
                    credentials: "same-origin",
                    headers: {
                        "HX-Request": "true",
                        "RequestVerificationToken": meta?.getAttribute("content") ?? ""
                    }
                });

                if (!res.ok) {
                    this.error = res.status === 401
                        ? "Invalid code — try again."
                        : `Verification failed (HTTP ${res.status}).`;
                    this.busy = false;
                    return;
                }

                // Success — close modal and replay the original request.
                const retry = this.retry;
                this.cancel();
                if (retry?.url && window.htmx) {
                    const verb = (retry.method || "GET").toLowerCase();
                    window.htmx.ajax(verb, retry.url, { target: "body", swap: "none" });
                }
            } catch (err) {
                this.error = `Network error: ${err.message}`;
                this.busy = false;
            }
        }
    });

    Alpine.store("toasts", {
        items: [],
        _seq: 0,

        push({ level = "info", title = "", message = "", timeout = 4500 } = {}) {
            const id = ++this._seq;
            this.items.push({ id, level, title, message });
            if (timeout > 0) {
                window.setTimeout(() => this.dismiss(id), timeout);
            }
            return id;
        },

        dismiss(id) {
            const idx = this.items.findIndex(t => t.id === id);
            if (idx !== -1) this.items.splice(idx, 1);
        },

        success(message, title = "Success")  { return this.push({ level: "success", title, message }); },
        error(message,   title = "Error")    { return this.push({ level: "error",   title, message, timeout: 7000 }); },
        info(message,    title = "Info")     { return this.push({ level: "info",    title, message }); },
        warning(message, title = "Warning")  { return this.push({ level: "warning", title, message }); }
    });
});

/* ---------- HTMX integration ----------
 * Backend can trigger toasts by setting:
 *   Response.Headers["HX-Trigger"] =
 *     JsonSerializer.Serialize(new { showToast = new { level = "success", message = "..." } });
 * The backend should also surface ServiceResponse<T>.Message via this channel
 * so every operation produces visible feedback (project rule #6).
 */
document.addEventListener("showToast", (event) => {
    const detail = event.detail || {};
    const store = window.Alpine?.store("toasts");
    if (!store) return;
    store.push({
        level: detail.level || "info",
        title: detail.title || "",
        message: detail.message || ""
    });
});

/* Auto-attach the ASP.NET Core anti-forgery token to every HTMX request.
 * The token is rendered into <meta name="request-token"> by _HeadStyles.cshtml. */
document.addEventListener("htmx:configRequest", (event) => {
    const meta = document.querySelector('meta[name="request-token"]');
    if (meta) event.detail.headers["RequestVerificationToken"] = meta.getAttribute("content");
});

/* Step-up modal trigger from RequireElevated 401 responses. */
document.addEventListener("showElevationModal", (event) => {
    const elev = window.Alpine?.store("elevation");
    if (!elev) return;
    elev.request(event.detail || null);
});

/* HTMX server errors → red toast. Skip the noise on 401 elevation challenges
 * (the elevation modal handles those). */
document.addEventListener("htmx:responseError", async (event) => {
    const status = event.detail?.xhr?.status ?? "?";
    if (status === 401) {
        // If the server triggered the elevation modal, htmx already dispatched
        // showElevationModal — don't double-toast.
        const trigger = event.detail?.xhr?.getResponseHeader?.("HX-Trigger") ?? "";
        if (trigger.includes("showElevationModal")) return;
    }
    const store = window.Alpine?.store("toasts");
    if (!store) return;
    store.error(`Server returned HTTP ${status}.`);
});

/* HTMX network errors → red toast. */
document.addEventListener("htmx:sendError", async () => {
    const store = window.Alpine?.store("toasts");
    if (!store) return;
    store.error("Network error — check your connection.");
});

/* JSON envelope responses must never be painted into the DOM.
 * Drawer forms (filter / NAT / port-forward / mangle rule editors) post with
 * hx-swap="outerHTML", but their save endpoints return a ServiceResponse<T> as
 * application/json plus an HX-Trigger header (showToast + refresh<X>). HTMX
 * swaps any 2xx body by default, so without this it would dump the raw JSON
 * into the drawer. Here we suppress the swap for JSON responses — the toast and
 * list-refresh already ride on HX-Trigger — and on success we close the drawer.
 * On error (4xx/422) we keep the drawer open so the user can correct input;
 * the error toast is already triggered server-side. */
document.addEventListener("htmx:beforeSwap", (event) => {
    const xhr = event.detail?.xhr;
    const ct = xhr?.getResponseHeader?.("Content-Type") ?? "";
    if (!ct.includes("application/json")) return;

    const status = xhr?.status ?? 0;

    // 401 + showElevationModal is the step-up TOTP challenge, not a failure:
    // the elevation modal opens (via HX-Trigger) and replays the original
    // request after the code is verified. Mark it non-error so HTMX stops
    // logging a scary "Response Status Error Code 401" to the console.
    if (status === 401) {
        const trigger = xhr?.getResponseHeader?.("HX-Trigger") ?? "";
        if (trigger.includes("showElevationModal")) event.detail.isError = false;
    }

    event.detail.shouldSwap = false;          // never paint JSON
    if (status >= 200 && status < 300) {
        window.Alpine?.store("drawer")?.close();
    }
});

/* Initialize Alpine on HTMX-swapped content.
 * Alpine v3 only scans the DOM on its own start; it does NOT process nodes
 * that HTMX injects later. Without this, any x-data swapped into the page
 * (e.g. the address/port pickers in the drawer rule editors) never runs its
 * init(), so pre-filled tag chips never render and the field looks empty.
 * htmx:afterSwap fires after the new subtree is in the DOM — hand it to
 * Alpine.initTree so x-data/x-init on the swapped element take effect.
 * initTree skips nodes Alpine has already initialized, so this is idempotent. */
document.addEventListener("htmx:afterSwap", (event) => {
    const target = event.detail?.target;
    if (target && window.Alpine?.initTree) window.Alpine.initTree(target);
    // Re-apply any active client-side table filter to the freshly-swapped rows
    // (a list-refresh after add/delete, or a server-side dropdown filter, wipes
    // the rows the filter was hiding — restore the active query's effect).
    if (target?.id && window.NetFw._tableFilters && target.id in window.NetFw._tableFilters) {
        window.NetFw._applyTableFilter(target.id);
    }
});
