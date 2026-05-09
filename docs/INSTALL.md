# Server install

[Русская версия](INSTALL.ru.md)

End-to-end setup of `goloom-wg-server` on a fresh Debian/Ubuntu VPS.

## Prerequisites

- A VPS with a public IPv4 (1 vCPU / 1 GB RAM is enough)
- Root SSH access
- Open ports: TCP 9443 (admin panel), UDP 51820+ (one per inbound)
- For VK Calls inbounds: a desktop session OR the `admin-webview` captcha mode (no GUI needed; see [USAGE.md](USAGE.md))

## 1. Download the server binary

From the [Releases page](https://github.com/Pinnss/goloom-server/releases) grab the binary for your VPS architecture:

```bash
# amd64 (most VPS providers):
wget -O goloom-wg-server \
  https://github.com/Pinnss/goloom-server/releases/latest/download/goloom-wg-server-linux-amd64
chmod +x goloom-wg-server

# arm64 (Hetzner CAX, Oracle Ampere, AWS Graviton, …):
wget -O goloom-wg-server \
  https://github.com/Pinnss/goloom-server/releases/latest/download/goloom-wg-server-linux-arm64
chmod +x goloom-wg-server
```

Or build from source:

```bash
git clone https://github.com/Pinnss/goloom-server.git
cd goloom-server
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
  -o goloom-wg-server ./cmd/goloom-wg-server
scp goloom-wg-server root@your-vps:/root/
```

## 2. System prep on the VPS

```bash
# WireGuard tools
apt update
apt install -y wireguard wireguard-tools iptables

# IP forwarding (persistent)
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-goloom.conf
sysctl -p /etc/sysctl.d/99-goloom.conf
```

## 3. Bootstrap WireGuard

The systemd unit requires `wg-quick@wg0.service` to be active before goloom starts. Create a minimal `/etc/wireguard/wg0.conf`:

```ini
[Interface]
PrivateKey = <output of `wg genkey`>
Address    = 10.66.0.1/24
ListenPort = 51820
```

Set permissions and enable:

```bash
chmod 600 /etc/wireguard/wg0.conf
systemctl enable --now wg-quick@wg0
```

The admin panel will create per-inbound `wg<N>.conf` files automatically — `wg0` is just a placeholder.

## 4. Install goloom-wg-server

In the directory containing the binary, the example config, and the deploy assets:

```bash
# Create the working layout:
mkdir -p deploy
wget -O goloom-wg-server.yaml \
  https://github.com/Pinnss/goloom-server/raw/main/goloom-wg-server.yaml.example
wget -O deploy/install.sh \
  https://github.com/Pinnss/goloom-server/raw/main/deploy/install.sh
wget -O deploy/goloom-wg-server.service \
  https://github.com/Pinnss/goloom-server/raw/main/deploy/goloom-wg-server.service

# (Optional) edit goloom-wg-server.yaml — defaults work for most setups.
# Common tweaks: admin.listen port, network.wg_subnet_base.

# Run the installer (copies binary to /opt/goloom, drops the systemd
# unit, enables the service):
bash deploy/install.sh
systemctl start goloom-wg-server
journalctl -u goloom-wg-server -n 50
```

The first start prints a one-time admin password:

```
ADMIN bootstrap credentials → username=admin  password=abc123def456...
```

Capture it (printed only once) and open `https://<vps-ip>:9443` in a browser. You'll get a self-signed cert warning — accept it. Log in, then immediately change the password via "⚙ Аккаунт".

## 5. Provision your first inbound

In the dashboard click **+ Создать inbound**:

- **Tag** — display name, e.g. `home`
- **Transport** — `Telemost`, `WB Stream`, or `VK Calls`
- **Meeting URL** — the conference link (or VK call link, or WB Stream room URL)
- **Captcha mode** (VK only) — `admin-webview` for headless servers; the panel itself proxies the captcha to your browser

Save. The panel returns a `goloom://...` connection string + QR code. Hand it to your client.

For WB Stream inbounds you also need to capture browser cookies once — see [USAGE.md → WB Stream auth](USAGE.md#wb-stream-auth).

## 6. Updating

When a new release lands:

```bash
wget -O /tmp/goloom-wg-server.new \
  https://github.com/Pinnss/goloom-server/releases/latest/download/goloom-wg-server-linux-amd64
chmod +x /tmp/goloom-wg-server.new
systemctl stop goloom-wg-server
mv /tmp/goloom-wg-server.new /opt/goloom/goloom-wg-server
systemctl start goloom-wg-server
```

Existing inbounds and their `goloom://...` strings keep working across upgrades.

## Troubleshooting

| Symptom | Likely cause | Fix |
|---|---|---|
| Admin panel doesn't load | Port 9443 closed in provider firewall | Open in firewall config |
| Client connects but no internet | Missing MASQUERADE rule | `wg-quick down wg<N> && wg-quick up wg<N>` re-applies the PostUp |
| `peer initiated re-handshake` errors | Stale peer state from a prior client crash | Recreate the inbound from the panel and re-import on the client |
| VK inbound stuck on `auth_pending` | Captcha needs solving | Click the 🛡 badge in the dashboard, solve in one click |
| WB Stream inbound on `auth_required` | Cookies expired (~14 days) | Re-run the bookmarklet, paste new tokens (see USAGE.md) |
