// Copyright (C) 2026 Martin Gleason & Arthur Dennis
// Licensed under AGPL-3.0-or-later

// JR Local — Web Admin UI
// Vanilla JavaScript, no framework needed.

// ── Tauri IPC helper ────────────────────────────────────────
// In Tauri context, use invoke(). In browser dev, fall back to fetch().

async function invoke(command, args) {
    if (window.__TAURI__ && window.__TAURI__.core) {
        return window.__TAURI__.core.invoke(command, args || {});
    }
    // Fallback: use fetch API for browser-only development
    return fetchFallback(command, args);
}

async function fetchFallback(command, args) {
    const map = {
        'get_status': { method: 'GET', url: '/api/status' },
        'get_devices': { method: 'GET', url: '/api/devices' },
        'get_session_code': { method: 'GET', url: '/api/config' },
        'get_local_ip': { method: 'GET', url: '/health' },
        'export_data': { method: 'GET', url: '/api/export' },
        'shred_all_data': { method: 'POST', url: '/api/shred' },
        'complete_setup': { method: 'POST', url: '/api/config' },
    };

    const endpoint = map[command];
    if (!endpoint) {
        console.warn('No fetch fallback for command:', command);
        return null;
    }

    const opts = { method: endpoint.method };
    if (endpoint.method === 'POST' && args) {
        opts.headers = { 'Content-Type': 'application/json' };
        opts.body = JSON.stringify(args);
    }

    const resp = await fetch(endpoint.url, opts);
    return resp.json();
}

// ── State ───────────────────────────────────────────────────

let currentSection = 'dashboard';
let selectedMode = 'campaign';
let pollInterval = null;

// ── Initialization ──────────────────────────────────────────

document.addEventListener('DOMContentLoaded', () => {
    initApp();
});

async function initApp() {
    try {
        const status = await invoke('get_status');
        if (status && !status.setup_complete) {
            document.getElementById('setup-overlay').classList.remove('hidden');
        } else {
            document.getElementById('setup-overlay').classList.add('hidden');
            startPolling();
            refreshQR();
            detectIP();
        }
    } catch (e) {
        // Server might not be ready yet — retry
        console.log('Waiting for server...', e);
        setTimeout(initApp, 1000);
    }
}

// ── Dashboard Polling ───────────────────────────────────────

function startPolling() {
    refreshDashboard();
    if (pollInterval) clearInterval(pollInterval);
    pollInterval = setInterval(refreshDashboard, 2000);
}

async function refreshDashboard() {
    try {
        const status = await invoke('get_status');
        if (!status) return;

        // Server dot
        const dot = document.getElementById('server-dot');
        const text = document.getElementById('server-status-text');
        const settingsDot = document.getElementById('settings-server-dot');
        const settingsText = document.getElementById('settings-server-text');

        if (status.running !== false) {
            dot.className = 'status-dot online';
            text.textContent = 'Server Running';
            if (settingsDot) settingsDot.className = 'status-dot online';
            if (settingsText) settingsText.textContent = 'Server Running on port ' + (status.port || 3030);
        } else {
            dot.className = 'status-dot offline';
            text.textContent = 'Server Offline';
            if (settingsDot) settingsDot.className = 'status-dot offline';
            if (settingsText) settingsText.textContent = 'Server Offline';
        }

        // Stats
        document.getElementById('peer-count').textContent = status.peers || 0;
        document.getElementById('campaign-name-display').textContent = status.campaign_name || '—';

        const modeBadge = document.getElementById('mode-badge');
        if (status.mode === 'mutual_aid') {
            modeBadge.textContent = 'Mutual Aid';
        } else {
            modeBadge.textContent = 'Campaign';
        }

        // Session code
        document.getElementById('session-code-display').textContent = status.session_code || '------';
        const settingsCode = document.getElementById('settings-session-code');
        if (settingsCode) settingsCode.textContent = status.session_code || '------';

        // Settings form
        const nameInput = document.getElementById('settings-name');
        if (nameInput && !nameInput.matches(':focus')) {
            nameInput.value = status.campaign_name || '';
        }

        const modeSelect = document.getElementById('settings-mode');
        if (modeSelect && !modeSelect.matches(':focus')) {
            modeSelect.value = status.mode === 'mutual_aid' ? 'mutual_aid' : 'campaign';
        }

    } catch (e) {
        console.error('Dashboard refresh error:', e);
    }

    // Also refresh devices if on that tab
    if (currentSection === 'devices') {
        refreshDevices();
    }
}

// ── Navigation ──────────────────────────────────────────────

function showSection(name) {
    currentSection = name;

    // Update nav buttons
    document.querySelectorAll('nav button').forEach(btn => {
        btn.classList.toggle('active', btn.dataset.section === name);
    });

    // Show/hide sections
    document.querySelectorAll('.section').forEach(sec => {
        sec.classList.toggle('active', sec.id === 'section-' + name);
    });

    // Refresh data for the section
    if (name === 'devices') refreshDevices();
}

// ── QR Code ─────────────────────────────────────────────────

async function refreshQR() {
    const img = document.getElementById('qr-image');
    const loading = document.getElementById('qr-loading');

    try {
        const b64 = await invoke('generate_qr');
        if (b64) {
            img.src = 'data:image/png;base64,' + b64;
            img.style.display = 'block';
            loading.style.display = 'none';
        }
    } catch (e) {
        loading.textContent = 'QR code unavailable';
        console.error('QR generation error:', e);
    }
}

// ── Devices ─────────────────────────────────────────────────

async function refreshDevices() {
    try {
        const result = await invoke('get_devices');
        const list = document.getElementById('device-list');
        const empty = document.getElementById('no-devices');

        if (!result || !result.devices || result.devices.length === 0) {
            list.innerHTML = '';
            empty.style.display = 'block';
            return;
        }

        empty.style.display = 'none';
        list.innerHTML = result.devices.map(device =>
            '<li class="device-item">' +
            '  <span class="device-name">' + escapeHtml(device) + '</span>' +
            '  <span class="device-status">Connected</span>' +
            '</li>'
        ).join('');
    } catch (e) {
        console.error('Devices refresh error:', e);
    }
}

// ── Session Code ────────────────────────────────────────────

async function handleRegenerateCode() {
    if (!confirm('Regenerating the session code will disconnect all paired devices. Continue?')) {
        return;
    }
    try {
        const newCode = await invoke('regenerate_session_code');
        if (newCode) {
            document.getElementById('session-code-display').textContent = newCode;
            const settingsCode = document.getElementById('settings-session-code');
            if (settingsCode) settingsCode.textContent = newCode;
        }
        refreshQR();
    } catch (e) {
        console.error('Regenerate code error:', e);
    }
}

// ── Settings ────────────────────────────────────────────────

async function saveSettings() {
    const name = document.getElementById('settings-name').value;
    const mode = document.getElementById('settings-mode').value;

    try {
        await invoke('complete_setup', { campaign_name: name, mode: mode });
        refreshDashboard();
    } catch (e) {
        console.error('Save settings error:', e);
    }
}

// ── Data Management ─────────────────────────────────────────

async function handleExport() {
    try {
        const data = await invoke('export_data');
        if (data) {
            const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
            const url = URL.createObjectURL(blob);
            const a = document.createElement('a');
            a.href = url;
            a.download = 'jr-local-export.json';
            a.click();
            URL.revokeObjectURL(url);
        }
    } catch (e) {
        console.error('Export error:', e);
    }
}

function handleShred() {
    document.getElementById('shred-confirm').classList.remove('hidden');
}

function cancelShred() {
    document.getElementById('shred-confirm').classList.add('hidden');
}

async function confirmShred() {
    document.getElementById('shred-confirm').classList.add('hidden');

    try {
        await invoke('shred_all_data');
        // Show setup overlay again
        document.getElementById('setup-overlay').classList.remove('hidden');
    } catch (e) {
        console.error('Shred error:', e);
        alert('Shred failed: ' + e);
    }
}

// ── First Launch Setup ──────────────────────────────────────

function selectMode(el) {
    document.querySelectorAll('.mode-option').forEach(opt => opt.classList.remove('selected'));
    el.classList.add('selected');
    selectedMode = el.dataset.mode;
}

async function finishSetup() {
    const name = document.getElementById('setup-name').value.trim();
    if (!name) {
        document.getElementById('setup-name').style.borderColor = 'var(--red)';
        document.getElementById('setup-name').focus();
        return;
    }

    const btn = document.getElementById('setup-start-btn');
    btn.disabled = true;
    btn.textContent = 'Starting...';

    try {
        await invoke('complete_setup', { campaign_name: name, mode: selectedMode });

        document.getElementById('setup-overlay').classList.add('hidden');
        startPolling();
        refreshQR();
        detectIP();
    } catch (e) {
        console.error('Setup error:', e);
        btn.disabled = false;
        btn.textContent = 'Start Server';
    }
}

// ── IP Detection ────────────────────────────────────────────

async function detectIP() {
    try {
        const ip = await invoke('get_local_ip');
        const display = document.getElementById('settings-ip-display');
        if (display && ip) {
            display.textContent = 'LAN IP: ' + ip;
        }
    } catch (e) {
        console.error('IP detection error:', e);
    }
}

// ── Utilities ───────────────────────────────────────────────

function escapeHtml(str) {
    const div = document.createElement('div');
    div.textContent = str;
    return div.innerHTML;
}
