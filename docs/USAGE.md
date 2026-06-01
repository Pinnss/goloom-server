# Usage

[Русская версия](USAGE.ru.md)

This guide covers the day-to-day operator and end-user workflow once the server is installed (see [INSTALL.md](INSTALL.md)).

## Provisioning an inbound

Each tunnelled client gets its own **inbound** — a unique WireGuard interface, a unique connection string, and a unique meeting URL on the carrier service.

1. Open `https://<vps-ip>:9443` and sign in.
2. Click **+ Создать inbound**.
3. Choose **Transport**:
   - **Telemost** — paste a Yandex Telemost meeting URL (`https://telemost.yandex.ru/j/...`).
   - **WB Stream** — paste a Wildberries Stream room URL. You'll need cookies from a browser session (see [WB Stream auth](#wb-stream-auth) below).
   - **VK Calls** — paste a VK call link (`https://vk.com/call/join/...`). Pick a captcha mode:
     - `admin-webview` (default) — the admin panel proxies VK's captcha to your browser. Works on headless VPS.
     - `auto` — server pops the captcha into a system browser. Requires a desktop session on the VPS.
     - `none` — fail-fast on captcha challenges.
   - **VK TURN SRTP** (recommended) — paste a VK call link, then set **Listen address (UDP)** (e.g. `0.0.0.0:56001`, open in the firewall). The server relays WireGuard through VK's TURN servers as fake WebRTC media — no server-side captcha, ~30–40 Mbps. The client link is the **`vkturnproxy://`** link / QR on the inbound card, not a `goloom://` string. See [VK TURN SRTP](#vk-turn-srtp) below.
   - **VK TURN (legacy DTLS)** — deprecated; VK throttles it to ~7–9 KB/s. Use SRTP instead.
4. Click **Создать**. The panel returns a `goloom://...` string and a QR code.
5. Pass the QR / string to the client (mobile or desktop).

## VK Calls captcha (operator)

When a VK inbound first runs, VK demands a captcha solve. With `admin-webview`:

1. A 🛡 badge appears in the dashboard header. Click it.
2. Pick the pending challenge → opens a captcha window in a new tab.
3. Click **Я не робот**. The window self-closes when the token is captured.
4. The inbound transitions to `waiting_for_client`.

VK's `success_token` is single-use (~60 s lifetime), so each VK reconnect on the server side asks again. For long-running inbounds the panel handles this automatically — you'll only see the badge when human intervention is needed.

## VK TURN SRTP

The **VK TURN SRTP** transport relays WireGuard through VK's *own* TURN servers, disguised as a video call's media (RTP/SRTP). The key point: you never run a TURN server. VK's TURN is the relay; the Goloom server is just the "other peer" the client tells VK to forward to. Because VK's TURN can't be blocked without breaking VK calls country-wide, the traffic passes DPI — and SRTP framing dodges VK's media-shape policy, giving ~30–40 Mbps (vs ~7–9 KB/s on the legacy DTLS path).

**Provision (operator):**

1. **+ Создать inbound** → **Transport** = `VK TURN SRTP`.
2. **VK Call link** — `https://vk.com/call/join/<id>`. Only the client uses it (to request TURN credentials); the server never joins the call.
3. **Listen address (UDP)** — public UDP port the relay binds, e.g. `0.0.0.0:56001`. Unique per inbound, open in the firewall.
4. Leave auto-provision WG on → **Создать**.
5. On the inbound card, click **📋 vkturnproxy://** to copy the client link, or show its QR.

**Connect (client):** the `vkturnproxy://` link is consumed directly by the Goloom Android app (it routes the profile to the SRTP-relay path: VK auth → TURN allocations → DTLS-SRTP handshake) and by anton48/Moroka8 clients build125+. Import the link or scan the QR and connect — no `goloom://` connstr is involved for this transport.

## WB Stream auth

WB Stream sits behind Cloudflare Turnstile, which a Go HTTP client cannot pass. The pragmatic workaround is a one-time browser ceremony to extract cookies, then ~14 days of unattended operation until they expire.

### One-time setup

1. Open `https://stream.wb.ru/room/<id>` in a desktop browser.
2. Click **Войти как гость** → display name → ToS → Подключиться. You should be in the room.
3. Click the bookmarklet below. A textarea pops up with a JSON blob (also auto-copied to clipboard).
4. Paste the JSON into the inbound's **WB Stream → Auth** form in the admin panel. Save.

### Bookmarklet

Drag this to your bookmark bar (or paste as the URL of a new bookmark):

```javascript
javascript:(async function(){
  try {
    const slice = JSON.parse(localStorage.getItem('wb_auth_auth_slice') || '{}');
    if (!slice.accessToken) throw new Error('no accessToken — are you signed in as guest?');
    const cookies = await cookieStore.getAll();
    const cookieHeader = cookies.map(c => c.name + '=' + c.value).join('; ');
    const earliest = Math.min(...cookies.filter(c => c.expires).map(c => c.expires)) || null;
    const blob = {
      accessToken: slice.accessToken,
      cookies: cookieHeader,
      cookies_expire_at: earliest ? new Date(earliest).toISOString() : null,
      captured_at: new Date().toISOString(),
      room_url: location.origin + location.pathname,
    };
    const ta = document.createElement('textarea');
    ta.value = JSON.stringify(blob, null, 2);
    ta.style.cssText = 'position:fixed;top:5%;left:5%;width:90%;height:80%;z-index:99999;font:12px monospace;background:#fff;color:#000;border:2px solid #4CD964;padding:8px';
    document.body.appendChild(ta);
    ta.select();
    document.execCommand('copy');
    alert('Tokens copied. Paste into Goloom admin → Inbound → WB Stream auth.\n\nClick the textarea to dismiss.');
    ta.addEventListener('click', () => ta.remove());
  } catch (e) { alert('goloom-bookmarklet error: ' + e.message); }
})();
```

### Re-auth (every ~14 days)

The admin dashboard surfaces a "WB cookies expire tomorrow — please re-auth" alert 24 hours before expiry. Same bookmarklet, paste the new JSON over the old, save.

## Connecting clients

### Windows GUI

1. Download `goloom-wg-gui-windows-amd64.zip` from [Releases](https://github.com/Pinnss/goloom-server/releases).
2. Unzip anywhere (e.g. `C:\Program Files\Goloom\`).
3. Right-click `goloom-wg-gui.exe` → **Run as administrator** (the app needs to install routes for split-tunnel).
4. Click **+** → paste the `goloom://...` connstr → name the profile → Save.
5. For VK Calls profiles, paste the VK call link the server is supposed to dial into the **VK Call link** field.
6. Click **Connect**.

### Windows CLI

Edit `goloom-wg-client.yaml`:

```yaml
transport: "vk-calls"          # or "telemost", "livekit-wb-stream"
meeting:   "https://vk.com/call/join/..."
display_name: "alice-laptop"
listen_addr: "127.0.0.1:51820"
```

Run as Administrator:

```powershell
.\goloom-wg-client.exe -config goloom-wg-client.yaml
```

Then point any WireGuard client (the official Windows app, etc.) at `127.0.0.1:51820`.

### Android

1. Download the latest APK from [goloom-android Releases](https://github.com/Pinnss/goloom-android/releases).
2. Install. Open the app, accept VPN permission.
3. Tap **+ Add profile** → paste the connstr or scan the QR.
4. For VK Calls profiles, fill in the **VK Call link** field.
5. Tap the profile to connect. The first VK Calls connect shows a captcha WebView — solve once. The Android client stores the resolved profile and replays it on reconnect.

## Operating notes

- **Restart server**: `systemctl restart goloom-wg-server`. Existing inbounds and connstrs persist across restarts.
- **Logs**: `journalctl -u goloom-wg-server -f`. Log level can be raised by setting `log_level: "debug"` in the yaml.
- **Disable an inbound**: toggle the switch on its card in the dashboard. Connstrs stay valid; clients just can't connect while disabled.
- **Delete an inbound**: dashboard → ✕ on the card. The corresponding `wg<N>.conf` and routes are removed; the connstr stops working immediately.
