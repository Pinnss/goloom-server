# VPS deploy (Linux)

Walks through getting `goloom-wg-server` onto a fresh Linux VPS and
configuring it to host VK Calls inbounds (Telemost / WB Stream
inbounds work the same way — the only VPS-specific detail is
`captcha_mode=admin-webview` so VK can solve captchas without a
desktop session).

Tested on Ubuntu 22.04. Adjust paths for other distros as needed.

## 1. Build the Linux binary (from your dev machine)

From the repo root, cross-compile a stripped, statically-linked
binary:

```bash
GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="-s -w" \
    -o goloom-wg-server-linux ./cmd/goloom-wg-server
```

Result: ~24 MB ELF binary at `goloom-wg-server-linux` in the repo
root.

## 2. Prep the VPS (one-time)

SSH to the VPS and prep the kernel + WG bits:

```bash
# Install WireGuard tools + kernel module (kernel ≥ 5.6 has wg
# built-in; older kernels apt installs the wg module).
apt update && apt install -y wireguard wireguard-tools

# Enable IP forwarding (needed for WG masquerade later).
echo "net.ipv4.ip_forward=1" | tee -a /etc/sysctl.conf
sysctl -p

# Bring up at least one wg interface so the goloom systemd unit's
# Requires=wg-quick@wg0.service is satisfied. Empty config is fine —
# admin panel will pre-provision per-inbound interfaces.
cat > /etc/wireguard/wg0.conf <<EOF
[Interface]
PrivateKey = $(wg genkey)
Address = 10.66.0.1/24
ListenPort = 51820
EOF
chmod 600 /etc/wireguard/wg0.conf
systemctl enable --now wg-quick@wg0
```

## 3. Copy files to VPS

From your dev machine, copy the binary, install script, and an
initial config to the VPS:

```bash
# Adjust the IP / user as needed.
VPS=root@45.43.89.67

# Binary + service file + install script + config.
scp goloom-wg-server-linux              "$VPS:/tmp/goloom-wg-server"
scp deploy/goloom-wg-server.service     "$VPS:/tmp/"
scp deploy/install.sh                   "$VPS:/tmp/"
scp goloom-wg-server.yaml.example       "$VPS:/tmp/goloom-wg-server.yaml"
```

## 4. Install on VPS

```bash
ssh root@45.43.89.67
cd /tmp
mkdir -p deploy && mv goloom-wg-server.service deploy/

# Run the installer — copies binary to /opt/goloom, drops the
# systemd unit, enables the service.
bash install.sh
```

The installer expects a `goloom-wg-server` binary in the cwd; we
SCP'd it as `/tmp/goloom-wg-server` so this lines up.

## 5. Configure

Edit `/opt/goloom/goloom-wg-server.yaml`:

```yaml
admin:
  listen: "0.0.0.0:9443"   # or 443 if you want a clean URL
  tls:
    auto_self_signed: true # browser will warn until you swap in a real cert

network:
  external_iface: ""       # auto-detect via ip route get 8.8.8.8
  wg_subnet_base: "10.66.0.0/16"
  wg_port_base: 51820

inbounds: []                 # empty — create via admin panel

log_level: "info"
```

If you want a custom port, also open the firewall:

```bash
ufw allow 9443/tcp
ufw allow 51820:51835/udp   # range covering future inbounds
```

## 6. Start

```bash
systemctl start goloom-wg-server
systemctl status goloom-wg-server
journalctl -u goloom-wg-server -f      # follow logs
```

The first start prints a one-time `admin` password — capture it from
journalctl or the systemd status output:

```
ADMIN bootstrap credentials → username=admin password=<random-string>
```

## 7. First login + create a VK Calls inbound

1. Open `https://45.43.89.67:9443/` in your browser. Accept the
   self-signed cert warning.
2. Login as `admin` with the bootstrap password.
3. **Change the password immediately** via the ⚙ Аккаунт modal.
4. Click **+ Создать inbound**, pick **Transport = VK Calls**, fill
   in the call link, leave Captcha mode = **admin-webview**.
5. Click Создать. Inbound appears with phase `waiting_for_client`.
6. The auth chain immediately needs a captcha — wait a couple of
   seconds and the **🛡 1** badge appears top-right. Click → choose
   the pending challenge → opens the captcha proxy in a new tab.
7. Click "Я не робот". The shim posts the success_token back; the
   tab self-closes.
8. Inbound transitions to `waiting_for_client` (still — VK call has
   only the server in it now). Once you connect the goloom client,
   it'll move to `relaying`.

## 8. Connect a client (from your laptop)

```yaml
# goloom-wg-client.yaml
transport: "vk-calls"
meeting: "https://vk.com/call/join/<id>"
display_name: "alice"
listen_addr: "127.0.0.1:51820"
```

Run as Administrator (Windows) or root (Linux):

```powershell
.\goloom-wg-client.exe -config goloom-wg-client.yaml
```

The client opens a captcha pop-up locally on your machine (CLI uses
auto-proxy mode) and then connects to the VK call. Both sides reach
`session ready` → `relaying`.

## Smoke-test without WireGuard

If you want to verify the new transport plumbing on the VPS without
provisioning a wg interface, ssh in and run:

```bash
cd /opt/goloom
./goloom-wg-server -config goloom-wg-server.yaml &
# … create an inbound via admin UI …
# … or ad-hoc on the dev machine:
go run ./cmd/vkcalls-smoke -role=caller -link=<vk-link>
```

cmd/vkcalls-smoke exercises the production sfu.Transport API
end-to-end without the WG bridge layer — useful for sanity-checking
the captcha-broker / signaling bits separate from the WG plumbing.
