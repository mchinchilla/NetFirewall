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
    }
};

/* ---------- Alpine wiring ---------- */
document.addEventListener("alpine:init", () => {
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

/* HTMX server errors → red toast. */
document.addEventListener("htmx:responseError", async (event) => {
    const store = window.Alpine?.store("toasts");
    if (!store) return;
    const status = event.detail?.xhr?.status ?? "?";
    store.error(`Server returned HTTP ${status}.`);
});

/* HTMX network errors → red toast. */
document.addEventListener("htmx:sendError", async () => {
    const store = window.Alpine?.store("toasts");
    if (!store) return;
    store.error("Network error — check your connection.");
});
