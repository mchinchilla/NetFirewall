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
    sidebarCollapsed: false,
    soundAlerts: true     // audible cue on danger alerts (WAN/VPN down) + recovery
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
 * Audible alert cues, fully synthesized with the Web Audio API — no audio
 * assets, lives entirely here (rules #1 and #3). Each cue is a short sequence
 * of oscillator beeps shaped by a gain envelope so it's recognizable but not
 * jarring:
 *
 *   "down"     — two descending tones (alarm). For WAN/VPN-down danger alerts.
 *   "recovery" — two ascending tones, softer. For a cleared danger condition.
 *   "test"     — a single mid tone. Played when the user enables sound.
 *
 * Browsers block audio until the first user gesture (autoplay policy); we lazily
 * create/resume the AudioContext and also resume it on the first document click
 * (see the listener wired in alpine:init). Volume is intentionally low.
 */
window.NetFw.alarm = (function () {
    let ctx = null;
    const MASTER_GAIN = 0.12; // subtle

    function ensureCtx() {
        if (!ctx) {
            const AC = window.AudioContext || window.webkitAudioContext;
            if (!AC) return null;
            ctx = new AC();
        }
        return ctx;
    }

    // One beep: frequency (Hz), start offset (s), duration (s), wave shape.
    function beep(audio, freq, startAt, dur, type = "sine") {
        const osc = audio.createOscillator();
        const gain = audio.createGain();
        osc.type = type;
        osc.frequency.value = freq;
        // Quick attack, smooth exponential release — avoids clicky edges.
        const t0 = audio.currentTime + startAt;
        gain.gain.setValueAtTime(0.0001, t0);
        gain.gain.exponentialRampToValueAtTime(MASTER_GAIN, t0 + 0.02);
        gain.gain.exponentialRampToValueAtTime(0.0001, t0 + dur);
        osc.connect(gain).connect(audio.destination);
        osc.start(t0);
        osc.stop(t0 + dur + 0.02);
    }

    const PATTERNS = {
        // Descending minor-third pair — reads as "something's wrong".
        down:     (a) => { beep(a, 660, 0, 0.18, "triangle"); beep(a, 440, 0.20, 0.30, "triangle"); },
        // Ascending pair, gentler sine — reads as "all clear".
        recovery: (a) => { beep(a, 523, 0, 0.14, "sine"); beep(a, 784, 0.16, 0.22, "sine"); },
        // Single confirmation tone.
        test:     (a) => { beep(a, 600, 0, 0.16, "sine"); },
    };

    return {
        // Resume the context within a user gesture so later programmatic plays
        // (from an HTMX poll, no gesture) are allowed.
        unlock() {
            const a = ensureCtx();
            if (a && a.state === "suspended") a.resume().catch(() => {});
        },
        // Play a named cue. Respects the persisted soundAlerts toggle unless
        // forced (the toggle-on confirmation passes force=true via "test").
        play(pattern) {
            try {
                const enabled = window.Alpine?.store?.("ui")?.soundAlerts ?? true;
                if (!enabled && pattern !== "test") return;
                const a = ensureCtx();
                if (!a) return;
                if (a.state === "suspended") a.resume().catch(() => {});
                (PATTERNS[pattern] || PATTERNS.test)(a);
            } catch {
                /* audio unavailable / blocked — never throw into a poll handler */
            }
        },
    };
})();

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
 * IANA timezone catalog for the schedule (and profile) picker. Built from
 * `Intl.supportedValuesOf('timeZone')` so the list is the same database the
 * browser uses; falls back to a short common set if the API is missing.
 */
window.NetFw.ianaTimezones = (function () {
    const FALLBACK = Object.freeze([
        "UTC",
        "America/Los_Angeles", "America/Denver", "America/Chicago", "America/New_York",
        "America/Mexico_City", "America/Bogota", "America/Lima", "America/Sao_Paulo",
        "America/Tegucigalpa", "America/Argentina/Buenos_Aires",
        "Europe/London", "Europe/Madrid", "Europe/Berlin", "Europe/Paris",
        "Europe/Rome", "Europe/Amsterdam", "Europe/Athens",
        "Africa/Cairo", "Africa/Johannesburg", "Africa/Lagos",
        "Asia/Dubai", "Asia/Kolkata", "Asia/Bangkok", "Asia/Shanghai",
        "Asia/Tokyo", "Asia/Seoul", "Australia/Sydney", "Pacific/Auckland"
    ]);

    function ids() {
        let list = [];
        try {
            if (typeof Intl !== "undefined" && typeof Intl.supportedValuesOf === "function") {
                list = Intl.supportedValuesOf("timeZone");
            }
        } catch { /* ignore — use fallback */ }
        if (!Array.isArray(list) || list.length === 0) list = FALLBACK.slice();
        if (!list.includes("UTC")) list = ["UTC", ...list];
        return list;
    }

    function offset(id) {
        try {
            const fmt = new Intl.DateTimeFormat("en-US", {
                timeZone: id,
                timeZoneName: "shortOffset"
            });
            const name = fmt.formatToParts(new Date()).find(p => p.type === "timeZoneName")?.value;
            if (name) return name.replace(/^GMT/, "UTC");
        } catch { /* shortOffset unsupported — leave blank */ }
        return "";
    }

    function local() {
        try { return Intl.DateTimeFormat().resolvedOptions().timeZone || "UTC"; }
        catch { return "UTC"; }
    }

    function region(id) {
        if (id === "UTC") return "UTC";
        const slash = id.indexOf("/");
        return slash < 0 ? "Other" : id.slice(0, slash);
    }

    return { ids, offset, local, region };
})();

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
 * Log-prefix suggestion for filter rules.
 *
 * A drop rule with no prefix is invisible in `journalctl -k`: you know traffic
 * is being dropped but not by which rule. Almost nobody fills this in, and the
 * ones who do invent a different convention every time. Derive a stable one
 * from what the form already says — verdict, port or protocol, interface —
 * e.g. DROP-22-ENS224:. Purely a suggestion; typing anything wins.
 * ===================================================================== */
window.NetFw.suggestLogPrefix = function (form) {
    if (!form || !form.elements) return "";

    const val = (name) => {
        const el = form.elements[name];
        return el && typeof el.value === "string" ? el.value.trim() : "";
    };
    // Interface selects carry the display text ("ens224 (WAN)"); we want the name.
    const ifaceName = (name) => {
        const el = form.elements[name];
        if (!el || !el.options || el.selectedIndex < 0) return "";
        const text = el.options[el.selectedIndex].text || "";
        return text === "any" ? "" : text.split(" ")[0];
    };

    const parts = [val("Action")];

    const ports = val("DestinationPorts");
    if (ports) parts.push(ports.split(",")[0]);
    else if (val("Protocol")) parts.push(val("Protocol"));

    parts.push(ifaceName("InterfaceInId"));

    const label = parts
        .filter(Boolean)
        .join("-")
        .replace(/[^A-Za-z0-9_-]/g, "")
        .toUpperCase()
        .slice(0, 28);

    return label ? label + ": " : "";
};

/* =====================================================================
 * Filter-rule default-deny guard — client mirror of FwFilterRuleGuard.cs
 * (NetFirewall.Models/Firewall). Given the filter-rule form, returns the
 * reason the rule would make its chain's default-deny policy unreachable, or
 * null when it is legitimately narrowed.
 *
 * An accept with no interface, no address and no port matches EVERY packet
 * reaching the chain, shadowing every rule below it. The trap is `limit rate`:
 * it reads like a throttle but only bounds *when the rule matches*, so all
 * traffic under the limit is still accepted — that is how a `policy drop`
 * firewall ended up answering on every listening TCP port from the Internet.
 *
 * The server rejects the same shape on save (and the nft generator skips it),
 * so this is a courtesy, not the enforcement point. Keep the two in step: any
 * change here needs the same change in FwFilterRuleGuard.DescribeBypass.
 * ===================================================================== */
window.NetFw.filterRuleBypass = function (form) {
    if (!form || !form.elements) return null;

    const field = (name) => {
        const el = form.elements[name];
        return el && typeof el.value === "string" ? el.value.trim() : "";
    };
    const checked = (name) => {
        const el = form.elements[name];
        return !!(el && el.checked);
    };
    const csvHasEntries = (csv) => csv.split(",").some((v) => v.trim().length > 0);

    // A disabled rule never reaches the ruleset, so it cannot open anything.
    if (!checked("Enabled")) return null;
    if (field("Action").toLowerCase() !== "accept") return null;

    // output is `policy accept` by design — only the default-deny chains.
    const chain = field("Chain").toLowerCase();
    if (chain !== "input" && chain !== "forward") return null;

    // ICMP has no ports to narrow by; a rate-limited "allow ping" is deliberate.
    const protocol = field("Protocol").toLowerCase();
    if (protocol === "icmp" || protocol === "icmpv6") return null;

    // Any single narrowing condition means the operator scoped the rule.
    if (field("InterfaceInId") || field("InterfaceOutId")) return null;
    if (csvHasEntries(field("SourceAddresses"))) return null;
    if (csvHasEntries(field("DestinationAddresses"))) return null;
    if (csvHasEntries(field("DestinationPorts"))) return null;

    // `established, related` only readmits return traffic — not a way in.
    // No state match at all means every state, new included.
    const states = field("ConnectionStates");
    const admitsNew =
        !csvHasEntries(states) ||
        states.split(",").some((s) => s.trim().toLowerCase() === "new");
    if (!admitsNew) return null;

    let reason =
        `This '${chain}' accept matches all ${protocol ? protocol.toUpperCase() : "IP"} traffic — ` +
        "no interface, no address and no port narrow it — so it would shadow every rule below it and " +
        "make the chain's default-deny policy unreachable. Add a destination port, a source address, " +
        "or an interface.";

    const rate = field("RateLimit");
    if (rate) {
        reason +=
            " The rate limit does not narrow it: 'limit rate' only bounds when the rule matches, " +
            `so all traffic under ${rate} is still accepted.`;
    }
    return reason;
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
    // Filter-rule cards mark rows with [data-filter-row]; classic tables keep
    // using tbody > tr. Prefer the explicit marker when present so a redesigned
    // list doesn't silently stop filtering.
    const marked = root.querySelectorAll("[data-filter-row]");
    const rows = marked.length > 0 ? marked : root.querySelectorAll("tbody > tr");
    let shown = 0;
    rows.forEach((el) => {
        const hit = q === "" || el.textContent.toLowerCase().includes(q);
        el.classList.toggle("hidden", !hit);
        if (hit) shown++;
    });
    if (marked.length > 0) {
        root.querySelectorAll("[data-filter-group]").forEach((group) => {
            const anyVisible = Array.from(group.querySelectorAll("[data-filter-row]"))
                .some((el) => !el.classList.contains("hidden"));
            group.classList.toggle("hidden", !anyVisible);
        });
    } else {
        // Grouped tables (legacy filter-rules thead/tbody) hide a section
        // header whose own tbody got filtered away.
        root.querySelectorAll("thead").forEach((head) => {
            const body = head.nextElementSibling;
            if (!body || body.tagName !== "TBODY") return;
            const anyVisible = Array.from(body.querySelectorAll("tr"))
                .some((tr) => !tr.classList.contains("hidden"));
            head.classList.toggle("hidden", !anyVisible);
        });
    }

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
        const secondary = this.readColor("chart-out");
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
            const s = this.readColor("chart-out");
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
        const secondary = this.readColor("chart-out");
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
            const s = this.readColor("chart-out");
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
        const secondary = this.readColor("chart-out");
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
            chart.data.datasets[1].borderColor = this.readColor("chart-out");
        });
        return chart;
    },

    /**
     * Copy in/out series off Alpine proxies (Chart.js will not draw reactive
     * arrays). Accepts camelCase or PascalCase from the JSON payload.
     */
    plainSeries(data) {
        if (!data) return { labels: [], inSeries: [], outSeries: [] };
        const labels = data.labels || data.Labels || [];
        const inSeries = data.inSeries || data.InSeries || [];
        const outSeries = data.outSeries || data.OutSeries || [];
        return {
            labels: Array.from(labels),
            inSeries: Array.from(inSeries),
            outSeries: Array.from(outSeries)
        };
    },

    /** Replace a sparkline's data in place (no re-create). */
    updateSparkline(chart, data) {
        if (!chart) return;
        const s = this.plainSeries(data);
        chart.data.labels = s.labels;
        chart.data.datasets[0].data = s.inSeries;
        chart.data.datasets[1].data = s.outSeries;
        chart.update("none");
        try { chart.resize(); } catch { /* canvas not laid out yet */ }
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
    },

    /**
     * Live per-WAN up/down chart. Same data shape as makeSparkline
     * ({ labels, inSeries, outSeries }). `compact` hides axes/legend for
     * dashboard cards; the full variant is the Monitoring page.
     */
    makeLiveTraffic(canvasEl, data, compact) {
        const ctx = canvasEl.getContext("2d");
        const inbound = this.readColor("chart-in");
        const outbound = this.readColor("chart-out");
        const fgMuted = this.readColor("surface-fg-muted");
        const border = this.readColor("surface-border");
        const elevated = this.readColor("surface-elevated");
        const fg = this.readColor("surface-fg");
        const isCompact = compact === true;

        const fmt = (v) => {
            if (v >= 1000) return `${(v / 1000).toFixed(2)} Gbps`;
            if (v >= 1) return `${v.toFixed(1)} Mbps`;
            if (v >= 0.001) return `${(v * 1000).toFixed(0)} kbps`;
            return "0";
        };

        const series = this.plainSeries(data);
        const chart = new Chart(canvasEl, {
            type: "line",
            data: {
                labels: series.labels,
                datasets: [
                    {
                        label: "Down", data: series.inSeries,
                        borderColor: inbound,
                        backgroundColor: this._verticalGradient(ctx, canvasEl.clientHeight, inbound),
                        fill: true, tension: 0.35, pointRadius: 0, borderWidth: 2
                    },
                    {
                        label: "Up", data: series.outSeries,
                        borderColor: outbound, backgroundColor: "transparent",
                        borderDash: [4, 4], tension: 0.35, pointRadius: 0, borderWidth: 2
                    }
                ]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: {
                        display: !isCompact,
                        position: "bottom",
                        labels: { color: fgMuted, boxWidth: 10, boxHeight: 10, padding: 12, font: { size: 11 } }
                    },
                    tooltip: {
                        backgroundColor: elevated, titleColor: fg, bodyColor: fgMuted,
                        borderColor: border, borderWidth: 1, padding: 8,
                        callbacks: { label: (c) => `${c.dataset.label}: ${fmt(c.parsed.y)}` }
                    }
                },
                scales: {
                    x: {
                        display: !isCompact,
                        grid: { display: false },
                        ticks: { color: fgMuted, maxTicksLimit: 6, font: { size: 10 } }
                    },
                    y: {
                        display: !isCompact,
                        beginAtZero: true,
                        grid: { color: border, drawTicks: false },
                        ticks: { color: fgMuted, font: { size: 10 }, callback: fmt }
                    }
                }
            }
        });

        this.register(chart, () => {
            const inn = this.readColor("chart-in");
            const out = this.readColor("chart-out");
            const fm = this.readColor("surface-fg-muted");
            const bd = this.readColor("surface-border");
            chart.data.datasets[0].borderColor = inn;
            chart.data.datasets[0].backgroundColor =
                this._verticalGradient(ctx, canvasEl.clientHeight, inn);
            chart.data.datasets[1].borderColor = out;
            if (chart.options.plugins.legend?.labels)
                chart.options.plugins.legend.labels.color = fm;
            if (chart.options.scales.x?.ticks) chart.options.scales.x.ticks.color = fm;
            if (chart.options.scales.y?.ticks) chart.options.scales.y.ticks.color = fm;
            if (chart.options.scales.y?.grid) chart.options.scales.y.grid.color = bd;
        });
        return chart;
    },

    /** Semantic palette for per-interface 24h series (one hue per NIC). */
    ifacePalette() {
        return [
            this.readColor("chart-in"),
            this.readColor("chart-out"),
            this.readColor("surface-fg"),
            this.readColor("surface-fg-muted"),
            this.readColor("accent"),
            this.readColor("feedback-info-bd")
        ];
    },

    /**
     * Multi-interface 24h traffic chart. Datasets are pre-built by the Alpine
     * host (two per NIC: down solid, up dashed) so toggling visibility is
     * just dataset.hidden + update.
     */
    makeInterfaceTraffic(canvasEl, labels, datasets) {
        const ctx = canvasEl.getContext("2d");
        const fgMuted = this.readColor("surface-fg-muted");
        const border = this.readColor("surface-border");
        const elevated = this.readColor("surface-elevated");
        const fg = this.readColor("surface-fg");

        const fmt = (v) => {
            if (v >= 1000) return `${(v / 1000).toFixed(2)} Gbps`;
            if (Math.abs(v) >= 1) return `${Number(v).toFixed(1)} Mbps`;
            if (Math.abs(v) >= 0.001) return `${(v * 1000).toFixed(0)} kbps`;
            return "0";
        };

        const chart = new Chart(canvasEl, {
            type: "line",
            data: { labels, datasets },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                animation: false,
                interaction: { mode: "index", intersect: false },
                plugins: {
                    legend: { display: false },
                    tooltip: {
                        backgroundColor: elevated, titleColor: fg, bodyColor: fgMuted,
                        borderColor: border, borderWidth: 1, padding: 10,
                        callbacks: { label: (c) => `${c.dataset.label}: ${fmt(c.parsed.y)}` }
                    }
                },
                scales: {
                    x: { grid: { display: false }, ticks: { color: fgMuted, maxTicksLimit: 8, font: { size: 10 } } },
                    y: {
                        beginAtZero: true,
                        grid: { color: border, drawTicks: false },
                        ticks: { color: fgMuted, font: { size: 10 }, callback: fmt }
                    }
                }
            }
        });
        this.register(chart, () => {
            const fm = this.readColor("surface-fg-muted");
            const bd = this.readColor("surface-border");
            chart.options.plugins.tooltip.backgroundColor = this.readColor("surface-elevated");
            chart.options.plugins.tooltip.titleColor = this.readColor("surface-fg");
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

    /* ---------- store: tpl ---------- shared state for the setup wizard's Step 3.
     * When the rule-template picker successfully generates a rule set it sets
     * applied=true; the manual baseline section below collapses (the operator can
     * still reveal it with "Adjust manually"). Lives in a store so the picker and
     * the manual <form> — separate x-data scopes — can talk. */
    Alpine.store("tpl", {
        applied: false,            // a template was generated this session
        showManual: false,         // operator chose to reveal manual toggles anyway
        markApplied() { this.applied = true; this.showManual = false; },
    });

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

    function htmxJson(event) {
        if (!event?.detail?.successful) return null;
        try { return JSON.parse(event.detail.xhr.response); }
        catch { return null; }
    }

    /* ---------- liveSparkline ---------- HTMX loads JSON; Alpine keeps one
     * Chart.js sparkline and updates it in place (never swap the canvas).
     *   x-data="liveSparkline()"
     *   <div hx-get="..." hx-trigger="load, every 10s" hx-swap="none"
     *        @htmx:after-request="onHtmx($event)">
     *   <canvas x-ref="spark"></canvas>
     */
    Alpine.data("liveSparkline", () => {
        let chart = null;
        return {
            destroy() { try { chart?.destroy(); } catch { /* gone */ } chart = null; },
            onHtmx(event) {
                const data = htmxJson(event) || { labels: [], inSeries: [], outSeries: [] };
                if (!chart) {
                    if (!this.$refs.spark) return;
                    chart = window.NetFw.charts.makeSparkline(this.$refs.spark, data);
                    return;
                }
                window.NetFw.charts.updateSparkline(chart, data);
            }
        };
    });

    /* ---------- liveStat ---------- HTMX + Alpine sparkline for one metric
     * (CPU% / Memory%). Usage:
     *   x-data="liveStat('cpu')"
     *   hx-get="/Home/SystemSeries" hx-swap="none" @htmx:after-request="onHtmx($event)"
     */
    Alpine.data("liveStat", (field) => {
        let chart = null;
        return {
            current: "—",
            destroy() { try { chart?.destroy(); } catch { /* gone */ } chart = null; },
            onHtmx(event) {
                const j = htmxJson(event);
                const data = { labels: j?.labels || [], values: (j && j[field]) || [] };
                this.current = data.values.length ? data.values[data.values.length - 1] : "—";
                if (!chart) {
                    if (!this.$refs.spark) return;
                    chart = window.NetFw.charts.makeSparklineSingle(this.$refs.spark, data, true);
                    return;
                }
                window.NetFw.charts.updateSparklineSingle(chart, data);
            }
        };
    });

    /* ---------- liveWanCharts ---------- HTMX polls JSON; Alpine owns one
     * Chart.js canvas per WAN and updates in place. Pause/History come from
     * the parent via :hx-trigger. Usage:
     *   x-data="liveWanCharts(true)"
     *   hx-get="..." hx-swap="none" @htmx:after-request="onHtmx($event)"
     */
    Alpine.data("liveWanCharts", (compact) => {
        // Chart.js instances must NOT live on Alpine reactive state — the
        // proxy breaks draw/update. Canvas lookup by [data-iface] also raced
        // x-for, so each canvas binds itself via x-init.
        const charts = {};
        const canvases = {};
        return {
        wans: [],
        status: "loading",
        compact: compact === true,
        destroy() {
            for (const name of Object.keys(charts)) {
                try { charts[name].destroy(); } catch { /* already gone */ }
                delete charts[name];
            }
        },
        fmtMbps(v) {
            const n = Number(v);
            if (!Number.isFinite(n)) return "—";
            if (n >= 1000) return `${(n / 1000).toFixed(2)} Gbps`;
            if (n >= 1) return `${n.toFixed(1)} Mbps`;
            if (n >= 0.001) return `${(n * 1000).toFixed(0)} kbps`;
            return "0";
        },
        bindCanvas(el, name) {
            if (!el || !name) return;
            if (charts[name] && charts[name].canvas !== el) {
                try { charts[name].destroy(); } catch { /* stale canvas */ }
                delete charts[name];
            }
            canvases[name] = el;
            this._ensureChart(name);
        },
        async onHtmx(event) {
            const payload = htmxJson(event);
            if (!payload) {
                if (this.status === "loading") this.status = "error";
                return;
            }
            const next = Array.isArray(payload.wans) ? payload.wans : (payload.Wans || []);
            this.wans = next.map(w => ({
                name: w.name || w.Name,
                label: w.label || w.Label,
                role: w.role || w.Role,
                labels: w.labels || w.Labels || [],
                inSeries: w.inSeries || w.InSeries || [],
                outSeries: w.outSeries || w.OutSeries || [],
                inMbps: w.inMbps ?? w.InMbps ?? 0,
                outMbps: w.outMbps ?? w.OutMbps ?? 0
            }));
            this.status = this.wans.length === 0 ? "empty" : "ready";
            await this.$nextTick();
            this._syncCharts();
        },
        _ensureChart(name) {
            const wan = this.wans.find(w => w.name === name);
            const canvas = canvases[name];
            if (!wan || !canvas) return;
            const series = window.NetFw.charts.plainSeries(wan);
            if (!charts[name]) {
                charts[name] = window.NetFw.charts.makeLiveTraffic(canvas, series, this.compact);
            } else {
                window.NetFw.charts.updateSparkline(charts[name], series);
            }
            requestAnimationFrame(() => {
                try { charts[name]?.resize(); } catch { /* not laid out */ }
            });
        },
        _syncCharts() {
            const seen = new Set(this.wans.map(w => w.name));
            for (const wan of this.wans) this._ensureChart(wan.name);
            for (const name of Object.keys(charts)) {
                if (seen.has(name)) continue;
                try { charts[name].destroy(); } catch { /* already gone */ }
                delete charts[name];
                delete canvases[name];
            }
        }
        };
    });

    function cssEscape(value) {
        if (window.CSS && typeof window.CSS.escape === "function") return window.CSS.escape(value);
        return String(value).replace(/"/g, '\\"');
    }

    /* ---------- interfaceTrafficChart ---------- 24h per-interface traffic
     * with chip toggles. WAN defaults visible; LAN/other start hidden.
     *   x-data="interfaceTrafficChart('/Monitoring/interface-traffic-hourly?hours=24')"
     */
    Alpine.data("interfaceTrafficChart", () => {
        // Chart.js instances must NOT live on Alpine reactive state — the
        // proxy breaks hide/show and meta updates (chips change, lines don't).
        let chart = null;
        let canvas = null;
        return {
        status: "loading",
        labels: [],
        ifaces: [],
        destroy() {
            try { chart?.destroy(); } catch { /* already gone */ }
            chart = null;
            canvas = null;
        },
        get hasNonWan() {
            return this.ifaces.some(i => String(i.type).toUpperCase() !== "WAN");
        },
        get stats() {
            const vis = this.ifaces.filter(i => i.visible);
            const n = this.labels.length;
            if (!vis.length || n === 0)
                return { avgIn: 0, avgOut: 0, totalBytes: 0 };
            let inSum = 0, outSum = 0, bytes = 0;
            for (const i of vis) {
                inSum += (i.inMbps || []).reduce((a, b) => a + b, 0);
                outSum += (i.outMbps || []).reduce((a, b) => a + b, 0);
                bytes += i.totalBytes || 0;
            }
            return { avgIn: inSum / n, avgOut: outSum / n, totalBytes: bytes };
        },
        colorFor(idx) {
            const pal = window.NetFw.charts.ifacePalette();
            return pal[idx % pal.length];
        },
        fmtMbps(v) {
            const n = Number(v);
            if (!Number.isFinite(n)) return "—";
            if (n >= 1000) return `${(n / 1000).toFixed(2)} Gbps`;
            if (n >= 1) return `${n.toFixed(1)} Mbps`;
            if (n >= 0.001) return `${(n * 1000).toFixed(0)} kbps`;
            return "0";
        },
        fmtBytes(bytes) {
            const u = ["B", "KB", "MB", "GB", "TB", "PB"];
            let i = 0; let x = Number(bytes) || 0;
            while (x >= 1024 && i < u.length - 1) { x /= 1024; i++; }
            return `${x.toFixed(x >= 10 || i === 0 ? 0 : 2)} ${u[i]}`;
        },
        bindCanvas(el) {
            canvas = el;
            this._syncChart();
        },
        toggle(name) {
            this.ifaces = this.ifaces.map(i =>
                i.name === name ? { ...i, visible: !i.visible } : i);
            this._syncChart();
        },
        showAll() {
            this.ifaces = this.ifaces.map(i => ({ ...i, visible: true }));
            this._syncChart();
        },
        showWanOnly() {
            this.ifaces = this.ifaces.map(i => ({
                ...i,
                visible: String(i.type).toUpperCase() === "WAN"
            }));
            this._syncChart();
        },
        _visibleDatasets() {
            return this.ifaces.flatMap((iface, idx) => {
                if (!iface.visible) return [];
                const color = this.colorFor(idx);
                return [
                    {
                        label: `${iface.name} ↓`,
                        data: iface.inMbps, borderColor: color,
                        backgroundColor: "transparent", fill: false,
                        tension: 0.35, pointRadius: 0, borderWidth: 2
                    },
                    {
                        label: `${iface.name} ↑`,
                        data: iface.outMbps, borderColor: color,
                        backgroundColor: "transparent", borderDash: [4, 4],
                        fill: false, tension: 0.35, pointRadius: 0, borderWidth: 2
                    }
                ];
            });
        },
        _syncChart() {
            if (!canvas) return;
            const datasets = this._visibleDatasets();
            if (!chart) {
                chart = window.NetFw.charts.makeInterfaceTraffic(canvas, this.labels, datasets);
            } else {
                chart.data.labels = this.labels;
                chart.data.datasets = datasets;
                chart.update("none");
            }
            try { chart.resize(); } catch { /* canvas not laid out yet */ }
        },
        onHtmx(event) {
            const j = htmxJson(event);
            if (!j) { this.status = "error"; return; }
            const list = Array.isArray(j.interfaces) ? j.interfaces : [];
            const prev = new Map(this.ifaces.map(i => [i.name, i.visible]));
            this.labels = j.labels || [];
            this.ifaces = list.map(i => {
                const type = String(i.type || i.Type || "");
                const flagged = i.defaultVisible === true || i.DefaultVisible === true;
                const name = i.name || i.Name;
                const visible = prev.has(name)
                    ? prev.get(name)
                    : (flagged || type.toUpperCase() === "WAN");
                return {
                    name,
                    label: i.label || i.Label,
                    type,
                    inMbps: i.inMbps || i.InMbps || [],
                    outMbps: i.outMbps || i.OutMbps || [],
                    totalBytes: i.totalBytes || i.TotalBytes || 0,
                    visible
                };
            });
            this.status = this.ifaces.length === 0 ? "empty" : "ready";
            this._syncChart();
        }
        };
    });

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
        tags: [],
        input: "",
        open: false,
        active: -1,
        openOnEmpty: false,
        _blurTimer: null,

        init() {
            this.tags = (this.$el.dataset.initial || "")
                .split(",")
                .map(s => s.trim())
                .filter(s => s.length > 0);
            this.openOnEmpty = this.$el.dataset.openEmpty === "true";
        },

        get csv() { return this.tags.join(", "); },

        rows() {
            return this.$refs.list
                ? [...this.$refs.list.querySelectorAll("[data-object]")]
                : [];
        },

        looksLikeLiteral(v) {
            return v.includes("/") || v.includes("-") || /^\d+\.\d+\.\d+\.\d+$/.test(v);
        },

        addTag(value) {
            const v = (value || "").trim();
            if (!v) return;
            if (!this.tags.includes(v)) this.tags.push(v);
            this.input = "";
            this.active = -1;
            this.$nextTick(() => {
                if (this.$refs.hidden) this.$refs.hidden.value = this.csv;
                if (this.openOnEmpty) this.suggest();
                else this.closeList();
            });
        },

        removeTag(idx) {
            this.tags.splice(idx, 1);
            this.$nextTick(() => this.$refs.hidden && (this.$refs.hidden.value = this.csv));
        },

        pick(e) {
            const el = e.target.closest("[data-object]");
            if (el) this.addTag(el.dataset.object);
        },

        suggest() {
            if (this.$refs.text && window.htmx) window.htmx.trigger(this.$refs.text, "suggest");
        },

        onSuggestSwap() {
            this.open = true;
            this.active = this.rows().length > 0 ? 0 : -1;
            this.highlight();
        },

        highlight() {
            this.rows().forEach((el, i) => el.classList.toggle("is-active", i === this.active));
            const cur = this.rows()[this.active];
            if (cur) cur.scrollIntoView({ block: "nearest" });
        },

        closeList() {
            this.open = false;
            this.active = -1;
        },

        onBlur() {
            if (this._blurTimer) clearTimeout(this._blurTimer);
            this._blurTimer = setTimeout(() => this.closeList(), 150);
        },

        onKey(e) {
            const n = this.rows().length;
            if (e.key === "ArrowDown") {
                e.preventDefault();
                if (n === 0) { this.suggest(); return; }
                this.active = (this.active + 1) % n;
                this.highlight();
                this.open = true;
            } else if (e.key === "ArrowUp") {
                e.preventDefault();
                if (n === 0) return;
                this.active = (this.active - 1 + n) % n;
                this.highlight();
            } else if (e.key === "Enter") {
                e.preventDefault();
                const cur = this.rows()[this.active];
                if (this.open && cur) this.addTag(cur.dataset.object);
                else if (this.input.trim()) this.addTag(this.input);
            } else if (e.key === "," || e.key === " ") {
                if (this.input.trim()) { e.preventDefault(); this.addTag(this.input); }
            } else if (e.key === "Backspace" && !this.input && this.tags.length > 0) {
                this.removeTag(this.tags.length - 1);
            } else if (e.key === "Escape") {
                this.closeList();
            }
        }
    }));

    /* ---------- filterRulesPage ---------- header controls for Filter rules.
     * Holds the chain filter and the view mode, both sent to the table
     * endpoint via hx-vals, so grouping is decided server-side where it can be
     * unit tested (FilterRuleGrouper) instead of reshuffled in the DOM.
     *
     * "Evaluation" is first and default on purpose: it is the only arrangement
     * that matches how the kernel walks the chains. The others regroup for
     * answering a question and the table banners say so.
     */
    /* ---------- wgEgressPicker ---------- LAN devices/subnets that exit via
     * the tunnel. Extra CIDRs are Alpine-owned (no innerHTML). Search filters
     * the lease list client-side.
     */
    Alpine.data("wgEgressPicker", (initialExtras) => ({
        q: "",
        extra: "",
        extras: Array.isArray(initialExtras) ? initialExtras.slice() : [],
        match(hay) {
            const q = (this.q || "").trim().toLowerCase();
            return !q || String(hay || "").toLowerCase().includes(q);
        },
        addExtra() {
            let v = (this.extra || "").trim();
            if (!v) return;
            if (!v.includes("/")) v = `${v}/32`;
            if (!this.extras.includes(v)) this.extras.push(v);
            this.extra = "";
        },
        removeExtra(v) {
            this.extras = this.extras.filter(x => x !== v);
        }
    }));

    Alpine.data("filterRulesPage", () => ({
        chain: "",
        view: "evaluation",
        hideDisabled: false
    }));

    /* ---------- timePolicyForm ---------- bedtime / online-hours composer.
     * Mode drives the summary sentence. Submit is blocked client-side when
     * the address picker hasn't produced any sources (hidden input).
     */
    Alpine.data("timePolicyForm", () => ({
        mode: "allow-during",

        init() {
            const picked = this.$el.querySelector("input[name=Mode]:checked");
            if (picked) this.mode = picked.value;
        },

        onSubmit(e) {
            const src = (this.$el.querySelector("[name=Sources]")?.value || "").trim();
            if (!src) {
                e.preventDefault();
                e.stopPropagation();
                this.missingSources = true;
            }
        },

        missingSources: false
    }));

    /* ---------- connStatePicker ---------- conntrack states as toggles.
     * Backs _ConnStatePicker.cshtml. Hints are written in traffic terms, not
     * kernel terms, because that is the part people actually get wrong: they
     * know "replies to connections I allowed out", not "established".
     */
    Alpine.data("connStatePicker", () => ({
        states: [],
        options: [
            { id: "new",         label: "New",         hint: "The first packet of a connection - someone starting a conversation." },
            { id: "established", label: "Established", hint: "Traffic belonging to a conversation already allowed." },
            { id: "related",     label: "Related",     hint: "A side channel of an allowed conversation: FTP data, ICMP errors." },
            { id: "invalid",     label: "Invalid",     hint: "Packets conntrack cannot place. Normally dropped, never accepted." }
        ],

        init() {
            this.states = (this.$el.dataset.initial || "")
                .split(",")
                .map(s => s.trim().toLowerCase())
                .filter(s => s.length > 0);
        },

        has(id) { return this.states.includes(id); },

        toggle(id) {
            const i = this.states.indexOf(id);
            if (i >= 0) this.states.splice(i, 1);
            else this.states.push(id);
        },

        get csv() { return this.states.join(", "); }
    }));

    /* ---------- dayOfWeekPicker ---------- Sun–Sat toggles for schedules.
     * The checkboxes themselves are the posted values; Alpine only drives
     * Weekdays/Weekend/Every-day presets and the empty-state hint. Visual
     * on/off is CSS :checked (.dow-pill) so a click restyles without JS.
     *
     *   <div x-data="dayOfWeekPicker()" data-initial="1,2,3,4,5">
     */
    Alpine.data("dayOfWeekPicker", () => ({
        empty: false,

        init() {
            this.onChange();
            const form = this.$el.closest("form");
            if (form) {
                form.addEventListener("submit", (e) => {
                    this.onChange();
                    if (this.empty) {
                        e.preventDefault();
                        e.stopPropagation();
                    }
                });
            }
        },

        boxes() {
            return [...this.$el.querySelectorAll('input[type="checkbox"]')];
        },

        onChange() {
            this.empty = this.boxes().filter(b => b.checked).length === 0;
        },

        setDays(ids) {
            const want = new Set(ids);
            for (const b of this.boxes()) b.checked = want.has(Number(b.value));
            this.onChange();
        },

        weekdays() { this.setDays([1, 2, 3, 4, 5]); },
        weekend()  { this.setDays([0, 6]); },
        everyday() { this.setDays([0, 1, 2, 3, 4, 5, 6]); }
    }));

    /* ---------- timezonePicker ---------- searchable IANA combobox.
     * Hidden input holds the last valid id (what the server receives). The
     * visible field filters the list. Focusing it with the current value
     * still shows EVERY zone — a <datalist> would filter down to "UTC" and
     * look empty, which is the bug this replaces.
     *
     *   <div x-data="timezonePicker()" data-initial="UTC">
     *     <input type="hidden" x-ref="hidden" name="Timezone">
     */
    Alpine.data("timezonePicker", () => ({
        value: "UTC",
        query: "",
        open: false,
        active: -1,
        zones: [],
        listId: "",
        _blurTimer: null,

        init() {
            this.value = this.$el.dataset.initial || "UTC";
            this.query = this.value;
            this.listId = (this.$refs.text?.id || "tz") + "-list";
            const tz = window.NetFw.ianaTimezones;
            this.zones = tz.ids().map(id => ({
                id,
                label: id,
                region: tz.region(id),
                offset: tz.offset(id),
                search: `${id} ${id.replace(/_/g, " ")} ${tz.offset(id)}`.toLowerCase()
            }));
            if (this.$refs.hidden) this.$refs.hidden.value = this.value;
        },

        get filtered() {
            const q = (this.query || "").trim().toLowerCase();
            // Show the full catalog when the field still holds the selected id
            // (i.e. the user opened the list, they didn't start typing).
            if (!q || q === (this.value || "").toLowerCase()) return this.zones;
            const needle = q.replace(/_/g, " ");
            return this.zones.filter(z => z.search.includes(needle));
        },

        get grouped() {
            const groups = [];
            const map = new Map();
            for (const z of this.filtered) {
                if (!map.has(z.region)) {
                    const g = { region: z.region, zones: [] };
                    map.set(z.region, g);
                    groups.push(g);
                }
                map.get(z.region).zones.push(z);
            }
            return groups;
        },

        get flat() { return this.filtered; },

        flatIndex(gi, i) {
            let n = 0;
            const groups = this.grouped;
            for (let k = 0; k < gi; k++) n += groups[k].zones.length;
            return n + i;
        },

        select(id) {
            this.value = id;
            this.query = id;
            this.open = false;
            this.active = -1;
            if (this.$refs.hidden) this.$refs.hidden.value = id;
        },

        useLocal() {
            this.select(window.NetFw.ianaTimezones.local());
        },

        openList() {
            this.open = true;
            this.$refs.text?.focus();
            this.$nextTick(() => {
                const el = this.$refs.list?.querySelector("[data-selected='true']");
                el?.scrollIntoView({ block: "nearest" });
            });
        },

        closeList() { this.open = false; this.active = -1; },

        onInput() {
            this.open = true;
            this.active = this.filtered.length > 0 ? 0 : -1;
        },

        onBlur() {
            if (this._blurTimer) clearTimeout(this._blurTimer);
            this._blurTimer = setTimeout(() => {
                const typed = (this.query || "").trim();
                const exact = this.zones.find(z => z.id.toLowerCase() === typed.toLowerCase());
                if (exact) this.select(exact.id);
                else if (this.filtered.length === 1) this.select(this.filtered[0].id);
                else this.query = this.value;
                this.closeList();
            }, 150);
        },

        onKey(e) {
            const list = this.filtered;
            if (e.key === "ArrowDown") {
                e.preventDefault();
                this.open = true;
                this.active = list.length === 0 ? -1 : (this.active + 1) % list.length;
            } else if (e.key === "ArrowUp") {
                e.preventDefault();
                this.open = true;
                this.active = list.length === 0 ? -1
                    : (this.active - 1 + list.length) % list.length;
            } else if (e.key === "Enter") {
                if (this.open && this.active >= 0 && list[this.active]) {
                    e.preventDefault();
                    this.select(list[this.active].id);
                }
            } else if (e.key === "Escape") {
                this.query = this.value;
                this.closeList();
            }
        }
    }));

    /* ---------- filterRuleGuard ---------- wraps the filter-rule form.
     * Blocks the submit while the rule would make its chain's default-deny
     * policy unreachable, showing the same sentence the server would answer
     * with. FirewallService rejects the shape too — this only saves the
     * round-trip and explains the problem before the operator hits save.
     *
     * Re-checks on click and keyup as well as input/change: the address and
     * port pickers write their hidden inputs directly (no input event fires),
     * and the $nextTick here lands after their own $nextTick write.
     */
    Alpine.data("filterRuleGuard", () => ({
        bypass: null,
        scheduleOn: false,
        _suggested: "",

        init() {
            this.recheck();
        },

        recheck() {
            this.$nextTick(() => {
                this.bypass = window.NetFw.filterRuleBypass(this.$el);
                this.updateLogPrefix();
                const el = this.$el.elements["ScheduleId"];
                this.scheduleOn = !!(el && el.value);
            });
        },

        /**
         * Keep the log prefix in step with the rule while it is still ours.
         * The moment the operator types their own, `current` stops matching the
         * last value we wrote and we never touch the field again.
         */
        updateLogPrefix() {
            const el = this.$el.elements["LogPrefix"];
            if (!el) return;

            const current = (el.value || "").trim();
            if (current !== "" && current !== this._suggested) return;

            const action = (this.$el.elements["Action"]?.value || "").trim().toLowerCase();
            if (action !== "drop" && action !== "reject" && action !== "log") {
                // An accept rule logs nothing; clear a prefix only if we put it there.
                if (current === this._suggested) { el.value = ""; this._suggested = ""; }
                return;
            }

            this._suggested = window.NetFw.suggestLogPrefix(this.$el);
            el.value = this._suggested;
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
            // Empty query is allowed on purpose: focusing the field lists the
            // service catalogue, so an operator who doesn't know the port names
            // discovers them instead of facing a blank box.
            const q = this.input.trim();

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

    /* ---------- terminal ---------- interactive root PTY via xterm.js.
     * Flow: TOTP confirm -> POST /terminal/open (gets a one-time ticket) ->
     * open WebSocket to /terminal/ws?ticket=... -> pump bytes <-> xterm.
     * Binary frames carry shell I/O; a JSON text frame {"t":"resize",...} carries
     * window size. Themed from the live semantic CSS tokens so it matches the app.
     * All async/await, no .then() (rule #2). Requires window.Terminal + window.FitAddon
     * (loaded by the Terminal view's Scripts section). */
    Alpine.data("terminal", () => ({
        state: "auth",      // auth | connected | closed
        code: "",
        error: "",
        busy: false,
        _term: null,
        _fit: null,
        _ws: null,
        _onResize: null,
        _dataDisposable: null,

        init() {
            // Clean up on navigation away / HTMX swap.
            this.$el.addEventListener("alpine:destroyed", () => this._teardown());
        },

        async open() {
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
            try {
                const res = await fetch("/terminal/open", {
                    method: "POST",
                    body: form,
                    credentials: "same-origin",
                    headers: {
                        "HX-Request": "true",
                        "RequestVerificationToken": meta?.getAttribute("content") ?? ""
                    }
                });
                const env = await res.json().catch(() => null);
                if (!res.ok || !env?.success || !env?.data?.ticket) {
                    this.error = env?.message || `Authorization failed (HTTP ${res.status}).`;
                    this.busy = false;
                    return;
                }
                this.code = "";
                await this._connect(env.data.ticket);
            } catch (err) {
                this.error = `Network error: ${err.message}`;
                this.busy = false;
            }
        },

        async _connect(ticket) {
            const scheme = window.location.protocol === "https:" ? "wss" : "ws";
            const url = `${scheme}://${window.location.host}/terminal/ws?ticket=${encodeURIComponent(ticket)}`;

            const term = new window.Terminal({
                cursorBlink: true,
                fontFamily: "ui-monospace, SFMono-Regular, Menlo, Consolas, monospace",
                fontSize: 13,
                theme: this._theme()
            });
            const fit = new window.FitAddon.FitAddon();
            term.loadAddon(fit);
            this._term = term;
            this._fit = fit;

            this.state = "connected";
            // Wait a tick so x-show reveals the container before we open/fit into it.
            await this.$nextTick();
            term.open(this.$refs.term);
            fit.fit();
            term.focus();

            const ws = new WebSocket(url);
            ws.binaryType = "arraybuffer";
            this._ws = ws;

            ws.addEventListener("open", () => {
                this._sendResize();
            });
            ws.addEventListener("message", (ev) => {
                if (typeof ev.data === "string") {
                    term.write(ev.data);
                } else {
                    term.write(new Uint8Array(ev.data));
                }
            });
            ws.addEventListener("close", () => { this._onClosed(); });
            ws.addEventListener("error", () => { this._onClosed(); });

            // Keystrokes -> shell.
            this._dataDisposable = term.onData((d) => {
                if (ws.readyState === WebSocket.OPEN) ws.send(d);
            });

            // Window resize -> fit -> control frame.
            this._onResize = () => {
                try { fit.fit(); } catch { /* container hidden */ }
                this._sendResize();
            };
            window.addEventListener("resize", this._onResize);
        },

        _sendResize() {
            if (!this._term || !this._ws || this._ws.readyState !== WebSocket.OPEN) return;
            this._ws.send(JSON.stringify({ t: "resize", rows: this._term.rows, cols: this._term.cols }));
        },

        _theme() {
            // Read the live semantic tokens so the terminal matches the active
            // theme/mode (rule #9 — no hardcoded hex).
            const css = getComputedStyle(document.documentElement);
            const v = (name, fallback) => (css.getPropertyValue(name).trim() || fallback);
            return {
                background: v("--surface-bg", "#0b0f14"),
                foreground: v("--surface-fg", "#e6e6e6"),
                cursor: v("--accent", "#7dd3fc"),
                selectionBackground: v("--accent-soft", "rgba(125,211,252,0.3)")
            };
        },

        _onClosed() {
            if (this.state === "closed") return;
            this.state = "closed";
            this._teardown(/* keepTerm */ true);
        },

        close() {
            try { this._ws?.close(); } catch { /* noop */ }
            this._onClosed();
        },

        reset() {
            this._teardown();
            this.state = "auth";
            this.error = "";
        },

        _teardown(keepTerm) {
            if (this._onResize) { window.removeEventListener("resize", this._onResize); this._onResize = null; }
            try { this._dataDisposable?.dispose(); } catch { /* noop */ }
            this._dataDisposable = null;
            try { this._ws?.close(); } catch { /* noop */ }
            this._ws = null;
            if (!keepTerm) {
                try { this._term?.dispose(); } catch { /* noop */ }
                this._term = null;
                this._fit = null;
            }
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

        async toggleSoundAlerts() {
            this.soundAlerts = !this.soundAlerts;
            await saveState(this.snapshot());
            // Confirm the new state audibly when turning it ON (and unlock audio
            // via this user gesture); silent when turning OFF.
            if (this.soundAlerts) { NetFw.alarm.unlock(); NetFw.alarm.play("test"); }
        },

        snapshot() {
            return {
                theme: this.theme,
                mode: this.mode,
                sidebar: this.sidebar,
                sidebarCollapsed: this.sidebarCollapsed,
                soundAlerts: this.soundAlerts
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
    // Notifications: just the unread (active-alert) count that drives the bell
    // dot. The dropdown list itself is HTMX-rendered from /Alerts/menu; the
    // fragment calls setUnread() so the badge reflects real active alerts.
    Alpine.store("notifications", {
        unread: 0,
        setUnread(n) {
            this.unread = Number.isFinite(+n) ? +n : 0;
        },
    });

    // Global flag the Monitoring page's Pause button flips so the app-wide
    // /Alerts/banner poll (in _Layout) freezes alongside the live metrics there.
    // Default false — every other page keeps alerts polling. The htmx:beforeRequest
    // hook below reads this and cancels banner polls while paused.
    Alpine.store("alerts", { paused: false });

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

/* Audible alert cue. The /Alerts/banner poll emits `alertsState` every cycle
 * with the current set of active DANGER alert keys. We diff against the
 * previous set: a key that just APPEARED → "down" alarm; a key that
 * DISAPPEARED → "recovery" chime (the condition cleared). The very first event
 * after page load only seeds the baseline — we don't alarm for alerts that were
 * already active when you opened the page. NetFw.alarm respects the persisted
 * soundAlerts toggle and the browser autoplay policy. */
(function () {
    let known = null; // Set of danger keys; null until the first event (baseline).
    document.addEventListener("alertsState", (event) => {
        // Keep the bell badge live on every poll — no need to open the dropdown.
        // The /Alerts/banner poll runs app-wide (it lives in _Layout), so this
        // updates the unread count on the dashboard, monitoring, anywhere.
        const store = window.Alpine?.store("notifications");
        if (store) store.setUnread(event.detail?.activeCount ?? 0);

        const list = Array.isArray(event.detail?.danger) ? event.detail.danger : [];
        const current = new Set(list.map((d) => d.key).filter(Boolean));

        if (known === null) { known = current; return; } // seed, no sound

        let changed = false;
        for (const key of current) {
            if (!known.has(key)) { NetFw.alarm.play("down"); changed = true; break; }
        }
        for (const key of known) {
            if (!current.has(key)) { NetFw.alarm.play("recovery"); changed = true; break; }
        }
        // When the active set actually changed, refresh an open dropdown so its
        // list reflects the new state immediately (the badge already updated above).
        if (changed && window.htmx) {
            window.htmx.trigger(document.body, "refreshNotifications");
        }
        known = current;
    });
})();

/* Unlock Web Audio on the first user gesture so later programmatic cues (fired
 * from background polls, which have no gesture) are allowed to play. */
(function () {
    const unlock = () => {
        NetFw.alarm.unlock();
        window.removeEventListener("pointerdown", unlock);
        window.removeEventListener("keydown", unlock);
    };
    window.addEventListener("pointerdown", unlock, { once: false });
    window.addEventListener("keydown", unlock, { once: false });
})();

/* Auto-attach the ASP.NET Core anti-forgery token to every HTMX request.
 * The token is rendered into <meta name="request-token"> by _HeadStyles.cshtml. */
document.addEventListener("htmx:configRequest", (event) => {
    const meta = document.querySelector('meta[name="request-token"]');
    if (meta) event.detail.headers["RequestVerificationToken"] = meta.getAttribute("content");
});

/* Honor the Monitoring page's Pause for the app-wide alerts banner poll. The
 * banner lives in _Layout, so its `every 10s` timer keeps firing even when the
 * page sets $store.alerts.paused (HTMX 2.x doesn't re-read a reactively-rewritten
 * hx-trigger). Cancelling the request here is the reliable freeze: no banner
 * swap, no `alertsState` event → no badge update and no sound, until resumed. */
document.addEventListener("htmx:beforeRequest", (event) => {
    const path = event.detail?.requestConfig?.path || event.detail?.pathInfo?.requestPath || "";
    if (window.Alpine?.store("alerts")?.paused && path.indexOf("/Alerts/banner") !== -1) {
        event.preventDefault();
    }
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
    const trigger = event.detail?.xhr?.getResponseHeader?.("HX-Trigger") ?? "";
    if (status === 401 && trigger.includes("showElevationModal")) return;
    // 400/422 already emit showToast via HX-Trigger — don't stack a second
    // generic "Server returned HTTP 422" on top of the real message.
    if ((status === 400 || status === 422) && trigger.includes("showToast")) return;
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

/* Keep the loading overlay up across HX-Redirect full navigations.
 * HTMX drops the htmx-request indicator class the moment the XHR settles,
 * but HX-Redirect means a full page load is about to start — without this
 * the spinner blinks off and the page looks idle while the next document
 * loads (visible on login: TOTP verified → dashboard). Pinning .is-loading
 * on the closest loading-host keeps the overlay visible; the navigation
 * replaces the whole DOM anyway, so it never needs to be un-pinned. */
document.addEventListener("htmx:afterRequest", (event) => {
    if (event.detail?.xhr?.getResponseHeader?.("HX-Redirect")) {
        event.detail.elt?.closest?.(".loading-host")?.classList.add("is-loading");
    }
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
