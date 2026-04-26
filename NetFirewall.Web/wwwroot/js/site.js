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
