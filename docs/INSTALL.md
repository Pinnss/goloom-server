# Installation

End-to-end setup of `goloom-wg-server` on a fresh Ubuntu/Debian VPS.

## Prerequisites

- A VPS with a public IPv4 (any 1 vCPU / 1 GB RAM works)
- Root access via SSH
- A working Yandex account (for Telemost meeting URLs)
- Open ports: TCP 9443 (admin), UDP 51820+ (one per inbound)

## 1. Build the binary

On any machine with Go 1.22+:

```bash
git clone https://github.com/Pinnss/goloom-server.git
cd goloom-server
go build -o goloom-wg-server ./cmd/goloom-wg-server
```

Cross-compile for the VPS if you're on a different OS/arch:

```bash
GOOS=linux GOARCH=amd64 go build -o goloom-wg-server ./cmd/goloom-wg-server
```

Copy the binary to the VPS:

```bash
scp goloom-wg-server root@your-vps:/root/
```

## 2. System prep on VPS

```bash
# WireGuard tooling
apt update
apt install -y wireguard wireguard-tools iptables

# IP forwarding (persistent)
echo "net.ipv4.ip_forward = 1" > /etc/sysctl.d/99-goloom.conf
sysctl -p /etc/sysctl.d/99-goloom.conf
```

## 3. Bootstrap WireGuard

The unit file requires `wg-quick@wg0.service` to be active before the goloom server starts. Create a minimal `/etc/wireguard/wg0.conf`:

```ini
[Interface]
Address = 10.66.0.1/24
ListenPort = 51820
PrivateKey = <output of `wg genkey`>

PostUp   = iptables -A FORWARD -i %i -j ACCEPT; iptables -A FORWARD -o %i -j ACCEPT; iptables -t nat -A POSTROUTING -s 10.66.0.0/24 -o ens3 -j MASQUERADE
PostDown = iptables -D FORWARD -i %i -j ACCEPT; iptables -D FORWARD -o %i -j ACCEPT; iptables -t nat -D POSTROUTING -s 10.66.0.0/24 -o ens3 -j MASQUERADE
```

Replace `ens3` with your default-route interface (`ip -4 route show default | awk '{print $5}'`).

Then bring it up:

```bash
chmod 600 /etc/wireguard/wg0.conf
systemctl enable --now wg-quick@wg0
```

## 4. Install goloom-wg-server

In the directory containing the binary, the example config, and the deploy assets:

```bash
cd ~/  # where goloom-wg-server (the binary) is
cp goloom-wg-server.yaml.example goloom-wg-server.yaml
nano goloom-wg-server.yaml   # replace REPLACE_ME_WITH_HEX_64 with `openssl rand -hex 32`

bash deploy/install.sh
systemctl start goloom-wg-server
journalctl -u goloom-wg-server -f
```

If everything is fine, you'll see HTTPS panel listening on `:9443`.

## 5. Provision your first inbound

Open `https://<vps-ip>:9443/?token=<your-token>` in a browser. You'll get a self-signed cert warning on first visit — accept it.

Click **Create inbound** → set a tag (e.g. "main") → save. The panel returns a `goloom://…` connection string + QR code.

Hand the QR / string off to your client (mobile or desktop). Done.

## 6. Per-inbound iptables

`goloom-wg-server` automatically writes `/etc/wireguard/wg<N>.conf` for each inbound and brings the interface up. You don't normally need to touch iptables — the wg-quick `PostUp` hook in the generated config handles MASQUERADE and FORWARD rules.

If you migrate the server to a new VPS or change the default-route interface, edit each `wg<N>.conf` to point at the new interface and `systemctl restart wg-quick@wg<N>`.

## 7. Updating

```bash
# Build the new binary, scp it over, then on the VPS:
systemctl stop goloom-wg-server
mv goloom-wg-server /opt/goloom/goloom-wg-server
systemctl start goloom-wg-server
```

Existing inbounds and their `goloom://…` strings keep working across upgrades.

## Troubleshooting

- **Admin panel doesn't load**: check `journalctl -u goloom-wg-server -n 50` and verify port 9443 is open in your hosting provider's firewall.
- **Client connects but no internet**: check `iptables -t nat -L POSTROUTING -nv | grep MASQUERADE` — there should be a rule for `10.66.<N>.0/24`. If it's missing, `wg-quick down wg<N> && wg-quick up wg<N>` re-applies the PostUp.
- **`peer initiated re-handshake` errors**: the server has stale peer state from a prior client crash. Recreate the inbound from the panel and re-import on the client.
