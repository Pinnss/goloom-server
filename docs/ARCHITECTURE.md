# Architecture

How a packet from a phone in Russia ends up at `api.ipify.org` while looking like Yandex Telemost video traffic.

## The two-stage tunnel

```
┌───────────────────┐                                ┌───────────────────┐
│ Phone (client)    │                                │  VPS (server)     │
│                   │                                │                   │
│ ┌───────────────┐ │                                │ ┌───────────────┐ │
│ │ Apps          │ │                                │ │ wg<N>.conf    │ │
│ │ (Chrome, ...) │ │                                │ │ AllowedIPs=   │ │
│ │               │ │                                │ │ 10.66.<N>.<C> │ │
│ │ →  TUN fd     │ │                                │ └───────┬───────┘ │
│ └──────┬────────┘ │                                │         │         │
│        │ IP pkt   │                                │         ▼         │
│ ┌──────▼────────┐ │                                │ ┌───────────────┐ │
│ │ wg-userspace  │ │ encrypted UDP            (5)   │ │ kernel WG     │ │
│ │ (in goloom    │ │ ◄────────────────────────────► │ │ stack         │ │
│ │  .aar)        │ │                                │ └───────┬───────┘ │
│ └──────┬────────┘ │                                │         │ MASQ    │
│        │ wrapped  │                                │         ▼         │
│ ┌──────▼────────┐ │  WebRTC video frames           │ ┌───────────────┐ │
│ │ Goloom relay  │ │ ◄──────── Telemost ─────────►  │ │ Goloom server │ │
│ │ (gomobile)    │ │                                │ │ (joins same   │ │
│ │               │ │  + Yandex SFU + STUN/TURN      │ │  meeting)     │ │
│ └───────────────┘ │                                │ └───────────────┘ │
└───────────────────┘                                └───────────────────┘
```

1. App writes an IP packet to the TUN fd.
2. wg-userspace encrypts it with WireGuard noise crypto, gets back a UDP packet whose destination is `127.0.0.1:51820` (the relay's local listen).
3. The Goloom relay reads that UDP packet and stuffs the bytes into a VP8 video frame (wrapped with framing/sequence so the receiver can reconstruct).
4. Pion WebRTC sends the frame to the Yandex Telemost SFU as if it were camera output — same DTLS-SRTP, same SFU, same ICE candidates, same DPI fingerprint.
5. Server side: another goloom relay sits in the same meeting, reads the frame, unwraps the bytes, and writes them to a UDP socket bound on the loopback to the WG endpoint of the per-inbound interface (`wg<N>` listening on `127.0.0.1:51821+N`).
6. Kernel WireGuard decrypts, gets the original IP packet back, NATs the source via iptables MASQUERADE, sends to the actual internet.

Reply path is symmetric.

## Why this configuration

- **Userspace WG on the client, kernel WG on the server**: clients (especially Android) can't reliably load kernel modules or even rely on `wireguard-android`'s native binding for arbitrary package names — see HANDOFF lessons in the [Android repo](https://github.com/Sv9toslavPinigin/goloom-android). The userspace implementation embedded in the gomobile `.aar` works on every Android since 8.0 with no permissions beyond `BIND_VPN_SERVICE`.
- **WG endpoint = `127.0.0.1`**: WG packets never leave the device naked; they always go via the Goloom relay which wraps them in WebRTC. The "endpoint" in the WG config is therefore loopback by design.
- **One inbound = one wg interface**: lets the admin panel deactivate / regenerate keys without disturbing other clients.

## Connection-string format

The admin panel hands clients one URL of the shape:

```
goloom://<base64url-json>
```

The decoded JSON carries everything the client needs to connect:

| Field | Type | Purpose |
|---|---|---|
| `m` | string | Telemost meeting URL |
| `tag` | string | Inbound tag (just for display) |
| `wgcp` | string | Client private key (base64) |
| `wgsp` | string | Server public key (base64) |
| `wga` | string | Client tunnel address, e.g. `10.66.1.2/24` |
| `wge` | string | WG endpoint — always `127.0.0.1:51820` (loopback) |
| `wgd` | string | DNS, comma-separated |

So scanning a single QR is enough — no separate `.conf` import.

## Source of truth

- Go side: [`internal/connstr/connstr.go`](../internal/connstr/connstr.go)
- Kotlin side: [ConnStr.kt](https://github.com/Sv9toslavPinigin/goloom-android/blob/main/app/src/main/java/app/goloom/client/data/ConnStr.kt)

Both must move in lockstep — change the Go struct → bump a minor version → update Kotlin parser before any new field becomes mandatory.
