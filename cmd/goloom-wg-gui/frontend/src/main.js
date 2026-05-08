// Frontend logic for the goloom GUI. Plain ES module — Wails serves
// it from the embedded asset filesystem, no build step needed.
//
// JS ⇄ Go surface:
//   - window.go.main.App.* — RPC calls auto-synthesised from app.go
//   - window.runtime.EventsOn("status" | "log", cb) — push events from
//     the wgclient.Service fan-out goroutine

const els = {
    connstr:        null, // unused after profile rework, kept to localise rename pain
    btnConn:        document.getElementById('btn-connect'),
    btnDisc:        document.getElementById('btn-disconnect'),
    btnClear:       document.getElementById('btn-clear-log'),
    chkTrace:       document.getElementById('chk-trace'),
    error:          document.getElementById('error'),
    phase:          document.getElementById('phase-chip'),

    sProfile:       document.getElementById('s-profile'),
    sTrans:         document.getElementById('s-transport'),
    sMeeting:       document.getElementById('s-meeting'),
    sLocal:         document.getElementById('s-local'),
    sPeer:          document.getElementById('s-peer'),
    sTx:            document.getElementById('s-tx'),
    sRx:            document.getElementById('s-rx'),
    sErr:           document.getElementById('s-err'),
    log:            document.getElementById('log'),

    // Profiles
    profileEmpty:   document.getElementById('profile-empty'),
    btnAddEmpty:    document.getElementById('btn-add-empty'),
    profileCtrls:   document.getElementById('profile-controls'),
    profileSelect:  document.getElementById('profile-select'),
    btnAdd:         document.getElementById('btn-add'),
    btnEdit:        document.getElementById('btn-edit'),
    btnDelete:      document.getElementById('btn-delete'),

    // Profile dialog
    pdialog:        document.getElementById('profile-dialog'),
    ptitle:         document.getElementById('profile-dialog-title'),
    pname:          document.getElementById('pf-name'),
    pconnstr:       document.getElementById('pf-connstr'),
    ptransport:     document.getElementById('pf-transport'),
    pmeeting:       document.getElementById('pf-meeting'),
    plkRoom:        document.getElementById('pf-lk-room'),
    plkToken:       document.getElementById('pf-lk-token'),
    plkCookies:     document.getElementById('pf-lk-cookies'),
    pvkLink:        document.getElementById('pf-vk-link'),
    plisten:        document.getElementById('pf-listen'),
    pAutoWG:        document.getElementById('pf-autowg'),
    pSaveBtn:       document.getElementById('btn-profile-save'),
    pError:         document.getElementById('profile-dialog-error'),

    // Confirm dialog
    cdialog:        document.getElementById('confirm-dialog'),
    cText:          document.getElementById('confirm-text'),
    cYes:           document.getElementById('btn-confirm-yes'),
};

const LOG_MAX = 500;

const emojiPhase = {
    idle: '○',
    connecting: '…',
    handshaking: '…',
    relaying: '●',
    reconnecting: '↻',
    error: '✕',
};

// In-memory mirror of the profile store, refreshed via App.ListProfiles.
let profiles = [];
let activeProfileId = '';

// Last status snapshot — kept so renderProfileList can re-evaluate
// the Connect/Disconnect button enablement after a profile add/delete
// without needing to re-pull from the backend.
let currentStatus = { phase: 'idle' };

// Modal state — track which profile is being edited (null for new).
let editingProfileId = null;

// ─── helpers ─────────────────────────────────────────────────────

function fmtBytes(n) {
    if (!n) return '0 B';
    const units = ['B', 'KB', 'MB', 'GB', 'TB'];
    let i = 0; let v = Number(n);
    while (v >= 1024 && i < units.length - 1) { v /= 1024; i++; }
    return v.toFixed(i === 0 ? 0 : 1) + ' ' + units[i];
}

function fmtClock(d) {
    const pad = (n) => n.toString().padStart(2, '0');
    return `${pad(d.getHours())}:${pad(d.getMinutes())}:${pad(d.getSeconds())}`;
}

function setPhase(phase) {
    els.phase.className = 'chip chip-' + (phase || 'idle');
    els.phase.textContent = (emojiPhase[phase] || '○') + ' ' + (phase || 'idle');
}

function applyStatus(st) {
    if (!st) return;
    currentStatus = st;
    setPhase(st.phase);
    els.sTrans.textContent   = st.transport || '—';
    els.sMeeting.textContent = st.meeting || '—';
    els.sLocal.textContent   = st.local_addr || '—';
    els.sPeer.textContent    = st.peer_id || '—';
    els.sTx.textContent      = (st.tx_packets || 0) + ' / ' + fmtBytes(st.tx_bytes || 0);
    els.sRx.textContent      = (st.rx_packets || 0) + ' / ' + fmtBytes(st.rx_bytes || 0);
    els.sErr.textContent     = st.last_error || '—';

    const running = st.phase && st.phase !== 'idle' && st.phase !== 'error';
    els.btnConn.disabled = running || profiles.length === 0;
    els.btnDisc.disabled = !running;
    // Profile controls stay enabled during a session — user can still
    // edit / delete other profiles. We only block delete on the
    // currently-running profile to avoid yanking the session config.
    refreshProfileBtnStates(running);
}

function refreshProfileBtnStates(running) {
    const sel = els.profileSelect.value;
    const hasSel = !!sel;
    els.btnEdit.disabled = !hasSel;
    els.btnDelete.disabled = !hasSel || (running && sel === activeProfileId);
}

function appendLog(line) {
    const div = document.createElement('span');
    div.className = 'line ' + (line.level || 'info');
    const ts = document.createElement('span');
    ts.className = 'ts';
    ts.textContent = fmtClock(new Date(line.time)) + ' ';
    div.appendChild(ts);
    div.appendChild(document.createTextNode(line.text));
    els.log.appendChild(div);

    while (els.log.childElementCount > LOG_MAX) {
        els.log.removeChild(els.log.firstChild);
    }
    const dist = els.log.scrollHeight - els.log.scrollTop - els.log.clientHeight;
    if (dist < 60) els.log.scrollTop = els.log.scrollHeight;
}

function showError(msg) { els.error.textContent = msg || ''; }

// ─── profiles ───────────────────────────────────────────────────

async function reloadProfiles(preferId) {
    try {
        profiles = await window.go.main.App.ListProfiles() || [];
        activeProfileId = await window.go.main.App.ActiveProfileID() || '';
    } catch (err) {
        console.warn('ListProfiles:', err);
        profiles = [];
    }
    renderProfileList(preferId);
}

function renderProfileList(preferId) {
    const sel = els.profileSelect;
    sel.replaceChildren();
    if (profiles.length === 0) {
        els.profileEmpty.hidden = false;
        els.profileCtrls.hidden = true;
        els.sProfile.textContent = '—';
    } else {
        els.profileEmpty.hidden = true;
        els.profileCtrls.hidden = false;

        for (const p of profiles) {
            const opt = document.createElement('option');
            opt.value = p.id;
            opt.textContent = p.name;
            sel.appendChild(opt);
        }
        // Selection priority: explicit prefer (from save), then last-active, then first.
        const pick = preferId && profiles.find((p) => p.id === preferId)
            ? preferId
            : (profiles.find((p) => p.id === activeProfileId) ? activeProfileId : profiles[0].id);
        sel.value = pick;
        onProfileSelectionChanged();
    }
    // Profile-set or selection changed — re-apply the cached status so
    // Connect/Disconnect enablement (which depends on profiles.length)
    // refreshes without us having to wait for the next status push.
    applyStatus(currentStatus);
}

function selectedProfile() {
    return profiles.find((p) => p.id === els.profileSelect.value) || null;
}

function onProfileSelectionChanged() {
    const p = selectedProfile();
    els.sProfile.textContent = p ? p.name : '—';
    refreshProfileBtnStates(false);
}

// ─── modal: profile add/edit ─────────────────────────────────────

function openProfileDialog(profile) {
    editingProfileId = profile ? profile.id : null;
    els.ptitle.textContent = profile ? 'Редактировать профиль' : 'Новый профиль';
    els.pname.value = profile ? profile.name : '';
    els.pconnstr.value = '';
    els.pError.textContent = '';

    // Populate manual fields. For edit mode, also default to manual
    // tab; for add, default to connstr tab (one-paste flow).
    const cfg = profile ? profile.config : {};
    els.ptransport.value = cfg.transport || 'telemost';
    // Both Telemost and VK Calls use cfg.meeting — populate whichever
    // input is visible based on transport.
    els.pmeeting.value   = cfg.transport === 'vk-calls' ? '' : (cfg.meeting || '');
    els.pvkLink.value    = cfg.transport === 'vk-calls' ? (cfg.meeting || '') : '';
    els.plkRoom.value    = cfg.livekit_room_url     || '';
    els.plkToken.value   = cfg.livekit_access_token || '';
    els.plkCookies.value = cfg.livekit_cookies      || '';
    els.plisten.value    = cfg.listen_addr          || '';
    // AutoWG defaults to ON for new profiles. For edit mode we
    // reflect the saved value — the backend gates by whether the
    // embedded WG keys exist, so flipping this on for a manual-
    // entry profile that lacks keys silently has no effect.
    els.pAutoWG.checked = profile ? !!cfg.auto_wg : true;
    refreshManualTransportFields();
    setActiveTab(profile ? 'manual' : 'connstr');

    els.pdialog.showModal();
    setTimeout(() => els.pname.focus(), 0);
}

function setActiveTab(name) {
    document.querySelectorAll('.tab').forEach((t) => {
        t.classList.toggle('tab-active', t.dataset.tab === name);
    });
    document.querySelectorAll('.tab-pane').forEach((p) => {
        p.hidden = p.dataset.pane !== name;
    });
}

function refreshManualTransportFields() {
    const t = els.ptransport.value;
    document.querySelectorAll('.manual-fields').forEach((f) => {
        f.hidden = f.dataset.for !== t;
    });
}

async function saveProfileFromDialog() {
    els.pError.textContent = '';
    const activeTab = document.querySelector('.tab.tab-active').dataset.tab;
    const name = (els.pname.value || '').trim();

    try {
        let saved;
        if (activeTab === 'connstr') {
            const cs = (els.pconnstr.value || '').trim();
            if (!cs) {
                els.pError.textContent = 'Вставь connection string';
                return;
            }
            // ImportProfile saves a NEW profile from connstr. For
            // edit mode + connstr we just decode then route through
            // SaveProfile so the existing record is updated in place.
            if (editingProfileId) {
                // Decode locally is hard from JS — round-trip via Connect()'s
                // dry-run isn't ideal. Easiest: call SaveProfile with the
                // existing id and let backend invoke FromConnStr internally
                // through ImportProfile — but ImportProfile always creates.
                // Workaround: ImportProfile creates a new one, then we swap
                // old fields. Cleanest is a dedicated UpdateFromConnStr
                // binding; for now we just create-new-on-edit-via-connstr.
                els.pError.textContent = 'Для редактирования используй вкладку «Вручную».';
                return;
            }
            saved = await window.go.main.App.ImportProfile(cs, name, !!els.pAutoWG.checked);
        } else {
            // Manual mode preserves the existing WG block (when
            // editing a connstr-imported profile) so toggling
            // AutoWG without re-pasting still works.
            const existing = editingProfileId
                ? (profiles.find((p) => p.id === editingProfileId) || {}).config || {}
                : {};
            const transport = els.ptransport.value;
            // Meeting field is shared between Telemost and VK Calls
            // (both take a single URL); pick the right input.
            const meeting = transport === 'vk-calls'
                ? (els.pvkLink.value || '').trim()
                : (els.pmeeting.value || '').trim();
            const cfg = {
                transport,
                meeting,
                livekit_room_url:     (els.plkRoom.value || '').trim(),
                livekit_access_token: (els.plkToken.value || '').trim(),
                livekit_cookies:      (els.plkCookies.value || '').trim(),
                vk_calls_role:        transport === 'vk-calls' ? 'caller' : '',
                display_name: '',
                listen_addr: (els.plisten.value || '').trim(),
                auto_wg: !!els.pAutoWG.checked,
                wg: existing.wg || {},
            };
            saved = await window.go.main.App.SaveProfile(editingProfileId || '', name, cfg);
        }
        await reloadProfiles(saved.id);
        els.pdialog.close();
    } catch (err) {
        els.pError.textContent = (err && err.message) ? err.message : String(err);
    }
}

// ─── modal: confirm-delete ──────────────────────────────────────

function openConfirmDelete(profile) {
    els.cText.textContent = `Профиль «${profile.name}» будет удалён безвозвратно. Соединение это не разорвёт.`;
    els.cYes.onclick = async () => {
        try {
            await window.go.main.App.DeleteProfile(profile.id);
            await reloadProfiles();
        } catch (err) {
            console.warn('DeleteProfile:', err);
        }
        els.cdialog.close();
    };
    els.cdialog.showModal();
}

// ─── connect / disconnect ───────────────────────────────────────

async function doConnect() {
    showError('');
    const p = selectedProfile();
    if (!p) {
        showError('Сначала добавь профиль');
        return;
    }
    try {
        await window.go.main.App.ConnectProfile(p.id);
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
        if (window.go && window.go.main && window.go.main.App) {
            window.go.main.App.SetVerbose(on).catch((err) => console.warn('SetVerbose:', err));
        }
    });

    els.btnAdd.addEventListener('click', () => openProfileDialog(null));
    els.btnAddEmpty.addEventListener('click', () => openProfileDialog(null));
    els.btnEdit.addEventListener('click', () => {
        const p = selectedProfile();
        if (p) openProfileDialog(p);
    });
    els.btnDelete.addEventListener('click', () => {
        const p = selectedProfile();
        if (p) openConfirmDelete(p);
    });
    els.profileSelect.addEventListener('change', onProfileSelectionChanged);

    // Modal interactions.
    els.pSaveBtn.addEventListener('click', saveProfileFromDialog);
    document.querySelectorAll('[data-close-dialog]').forEach((b) => {
        b.addEventListener('click', (e) => {
            const d = e.target.closest('dialog');
            if (d) d.close();
        });
    });
    // Close <dialog> when clicking on the backdrop. The native <dialog>
    // doesn't auto-close on backdrop click; the trick is to detect a
    // click whose target is the dialog element itself (not a descendant).
    document.querySelectorAll('dialog.modal').forEach((d) => {
        d.addEventListener('click', (e) => {
            if (e.target === d) d.close();
        });
    });
    document.querySelectorAll('.tab').forEach((t) => {
        t.addEventListener('click', () => setActiveTab(t.dataset.tab));
    });
    els.ptransport.addEventListener('change', refreshManualTransportFields);

    // Push events from Go.
    window.runtime.EventsOn('status', applyStatus);
    window.runtime.EventsOn('log',    appendLog);

    // Initial pull — profile list, status, recent logs. RPC may not
    // be ready on the very first tick; retry briefly.
    const tryPull = (n = 5) => {
        if (!window.go || !window.go.main || !window.go.main.App) {
            if (n > 0) setTimeout(() => tryPull(n - 1), 60);
            return;
        }
        reloadProfiles().catch(() => {});
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
