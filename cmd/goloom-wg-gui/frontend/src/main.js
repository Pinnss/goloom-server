// Frontend logic for the goloom GUI. Plain ES module — Wails serves
// it from the embedded asset filesystem, no build step needed.
//
// We talk to the Go side via two surfaces:
//   1. window.go.main.App.Connect / Disconnect / Status / RecentLogs
//      — RPC calls that the Wails runtime synthesizes from app.go.
//   2. window.runtime.EventsOn("status" | "log", cb) — server-pushed
//      events out of the Service.Subscribe fan-out goroutine.

const els = {
    connstr:   document.getElementById('connstr'),
    btnConn:   document.getElementById('btn-connect'),
    btnDisc:   document.getElementById('btn-disconnect'),
    btnClear:  document.getElementById('btn-clear-log'),
    chkTrace:  document.getElementById('chk-trace'),
    error:     document.getElementById('error'),
    phase:     document.getElementById('phase-chip'),
    sTrans:    document.getElementById('s-transport'),
    sMeeting:  document.getElementById('s-meeting'),
    sLocal:    document.getElementById('s-local'),
    sPeer:     document.getElementById('s-peer'),
    sTx:       document.getElementById('s-tx'),
    sRx:       document.getElementById('s-rx'),
    sErr:      document.getElementById('s-err'),
    log:       document.getElementById('log'),
};

const LOG_MAX = 500; // matches pkg/wgclient logBufCap

// ─── helpers ─────────────────────────────────────────────────────

const emojiPhase = {
    idle: '○',
    connecting: '…',
    handshaking: '…',
    relaying: '●',
    reconnecting: '↻',
    error: '✕',
};

function fmtBytes(n) {
    if (!n) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0;
    let v = Number(n);
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return v.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

function fmtClockHHMMSS(d) {
    const pad = (n) => n.toString().padStart(2, '0');
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function setPhase(phase) {
    els.phase.className = 'chip chip-' + (phase || 'idle');
    els.phase.textContent = (emojiPhase[phase] || '○') + ' ' + (phase || 'idle');
}

function applyStatus(st) {
    if (!st) return;
    setPhase(st.phase);
    els.sTrans.textContent   = st.transport || '—';
    els.sMeeting.textContent = st.meeting || '—';
    els.sLocal.textContent   = st.local_addr || '—';
    els.sPeer.textContent    = st.peer_id || '—';
    els.sTx.textContent      = (st.tx_packets || 0) + ' / ' + fmtBytes(st.tx_bytes || 0);
    els.sRx.textContent      = (st.rx_packets || 0) + ' / ' + fmtBytes(st.rx_bytes || 0);
    els.sErr.textContent     = st.last_error || '—';

    const running = st.phase && st.phase !== 'idle' && st.phase !== 'error';
    els.btnConn.disabled = running;
    els.btnDisc.disabled = !running;
}

function appendLog(line) {
    const div = document.createElement('span');
    div.className = 'line ' + (line.level || 'info');
    const ts = document.createElement('span');
    ts.className = 'ts';
    ts.textContent = fmtClockHHMMSS(new Date(line.time)) + ' ';
    div.appendChild(ts);
    div.appendChild(document.createTextNode(line.text));
    els.log.appendChild(div);

    // Trim oldest if over LOG_MAX.
    while (els.log.childElementCount > LOG_MAX) {
        els.log.removeChild(els.log.firstChild);
    }
    // Auto-scroll if user is near the bottom (heuristic: within 60px).
    const dist = els.log.scrollHeight - els.log.scrollTop - els.log.clientHeight;
    if (dist < 60) els.log.scrollTop = els.log.scrollHeight;
}

function showError(msg) {
    els.error.textContent = msg || '';
}

// ─── wails calls ────────────────────────────────────────────────

async function doConnect() {
    showError('');
    const cs = (els.connstr.value || '').trim();
    if (!cs) {
        showError('Вставь connection string из админки');
        return;
    }
    try {
        await window.go.main.App.Connect(cs);
    } catch (err) {
        showError(err && err.message ? err.message : String(err));
    }
}

async function doDisconnect() {
    showError('');
    try {
        await window.go.main.App.Disconnect();
    } catch (err) {
        showError(err && err.message ? err.message : String(err));
    }
}

// ─── boot ───────────────────────────────────────────────────────

function boot() {
    els.btnConn.addEventListener('click', doConnect);
    els.btnDisc.addEventListener('click', doDisconnect);
    els.btnClear.addEventListener('click', () => { els.log.replaceChildren(); });
    els.chkTrace.addEventListener('change', () => {
        const on = els.chkTrace.checked;
        els.log.classList.toggle('log-hide-trace', !on);
        // Tell the backend to start (or stop) routing trace lines into
        // the ringbuf + event channel. Without this the toggle would
        // be cosmetic only (trace was already filtered server-side).
        if (window.go && window.go.main && window.go.main.App) {
            window.go.main.App.SetVerbose(on).catch((err) => console.warn('SetVerbose:', err));
        }
    });

    // Submit on Ctrl+Enter inside the connstr field.
    els.connstr.addEventListener('keydown', (e) => {
        if (e.key === 'Enter' && (e.ctrlKey || e.metaKey)) {
            e.preventDefault();
            doConnect();
        }
    });

    window.runtime.EventsOn('status', applyStatus);
    window.runtime.EventsOn('log',    appendLog);

    // Initial state pull. Wails RPC may not be ready on the very first
    // tick, so we retry a few times silently.
    const tryPull = (n = 5) => {
        if (!window.go || !window.go.main || !window.go.main.App) {
            if (n > 0) setTimeout(() => tryPull(n - 1), 60);
            return;
        }
        window.go.main.App.Status().then(applyStatus).catch(() => {});
        window.go.main.App.RecentLogs(200).then((lines) => {
            (lines || []).forEach(appendLog);
        }).catch(() => {});
    };
    tryPull();
}

if (document.readyState === 'loading') {
    document.addEventListener('DOMContentLoaded', boot);
} else {
    boot();
}
