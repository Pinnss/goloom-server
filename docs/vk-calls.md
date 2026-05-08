# VK Calls transport

`transport=vk-calls` carries WireGuard datagrams over a VK Calls anonymous
peer-join. We auth with the public `vk.com/call/join/<id>` flow, join the
SFU as a regular participant, and tunnel WG inside an H.264 I_PCM video
track (Reed-Solomon coded). The SFU is a pure RTP forwarder so byte
integrity survives — see `pocs/vk-poc1/BENCH_RESULTS.md` in the private
goloom-poc repo for the validation numbers (28 Mbps raw, 3.35 Mbps payload
with 0 CRC corruptions over a 32 s run).

## When to use it

This is a third option alongside Telemost and WB-Stream. Pick it when:

- You need a non-Telemost path for a particular client (geo, ISP,
  policy, …)
- You want a transport that doesn't require operator-captured cookies
  (unlike WB-Stream's 14-day webview-auth)
- You have a workstation/laptop deploy where a browser pop-up for
  captcha is acceptable

It is **not yet a fit for headless production servers** — VK demands
a captcha solve on every `getAnonymousToken` call (~minute token
lifetime), and the only solver that works without operator interaction
is the local-browser auto-proxy. Headless support via the admin
webview pattern is a planned follow-up.

## Topology

VK call = one URL. Both participants (the goloom server inbound and
the goloom client) join the *same* link as anonymous peers. Roles:

- Server inbound → `role: receiver` (joins first, waits for offer)
- Client → `role: caller` (joins second, drives the offer)

A single VK call link can host one (server, client) pair at a time —
multi-client routing requires multiple call links, one per inbound.

## Server config

Pre-seed a VK Calls inbound by hand-editing
`goloom-wg-server.yaml`'s `inbounds:` list (the admin panel UI for
this lands in a follow-up):

```yaml
inbounds:
  - id: "vk-test-1"
    tag: "vk-test"
    transport: "vk-calls"
    meeting: "https://vk.com/call/join/AmMgBmKMd6Wei0nBvp0uQC7IGgltlMzwNvmOKKb9hGU"
    display_name: "goloom-server"

    vk_calls:
      role: "receiver"          # server pretends to be the call
                                # participant that joins first
      captcha_mode: "auto"      # opens local browser via reverse-proxy
                                # (needs a desktop session on the
                                # server box; switch to "none" to
                                # fail-fast on captcha if you've
                                # bypassed it some other way)

    wg_endpoint: "127.0.0.1:51820"
    wg_iface: "wg0"
    enabled: true
```

`meeting:` is the only mandatory field beyond the standard inbound
plumbing. `vk_calls.role` and `vk_calls.captcha_mode` both have sane
defaults and can be omitted.

## Client config

```yaml
# goloom-wg-client.yaml
transport: "vk-calls"
meeting: "https://vk.com/call/join/AmMgBmKMd6Wei0nBvp0uQC7IGgltlMzwNvmOKKb9hGU"
display_name: "alice-laptop"
listen_addr: "127.0.0.1:51820"

# vk_calls_role: "caller"   # default — clients drive the offer
```

Then run as Administrator (route-table edits for SFU IP exclusion):

```powershell
goloom-wg-client.exe -config goloom-wg-client.yaml
```

The client opens your default browser at `id.vk.com/not_robot_captcha`
the first time auth fires; click "Я не робот" once and the
success_token flows back through the local reverse-proxy automatically.

## Captcha modes (`captcha_mode`)

| Value            | Behaviour                                            | Use when |
|------------------|------------------------------------------------------|----------|
| `"auto"` (default)| Spin up a local reverse-proxy + open the system browser. Operator clicks once. Token flows back through the proxy. | Workstation / laptop / dev box with a desktop session |
| `"none"`         | No solver — auth fails fast on a captcha challenge. | You've bypassed captcha some other way (IP allowlist, pre-baked anonym token, …) |
| `"admin-webview"`| TODO — admin panel proxies the captcha to a connected admin browser. | Headless production servers (planned) |

Tokens issued by `captchaNotRobot.check` expire in roughly a minute,
so each VK reconnect needs a fresh solve. The CLI/GUI user clicks
once per session; for an inbound that supervisor-restarts every few
minutes this becomes noisy — the "admin-webview" mode is the proper
headless solution and lands later.

## Operational notes

- **`b=AS:3000` is ignored.** We send the canonical SDP munge for
  protocol-shape parity with the web client, but VK forwards RTP at
  whatever rate we feed it (we measured 28 Mbps sustained).
- **ICE host exclusion.** `Session.ICEHosts()` returns `vk.com`,
  `id.vk.com`, `calls.okcdn.ru`, `videowebrtc.okcdn.ru` and the
  dynamic TURN/STUN endpoints from the join response. The client's
  route manager pre-resolves and excludes these from default-route
  capture so our pion sockets aren't swallowed by the WG tunnel.
- **Throughput.** The videocode tunnel currently runs at FPS=10 with
  a 240×180 grid; that gives ~3.35 Mbps payload. Bumping FPS or grid
  size scales linearly toward the 28 Mbps SFU ceiling at the cost of
  more CPU. Tune in `internal/sfu/vkcalls/videocode/stream.go`.
- **Session lifetime.** A fresh `Connect()` is required after a
  rehandshake (token expiry). The supervise loop in
  `pkg/wgclient/service.go` already retries with backoff; for an
  inbound the `inbound.Manager` does the same.

## Smoke test (no WG required)

`cmd/vkcalls-smoke` exercises the production `sfu.Transport` /
`sfu.Session` API end-to-end without the WG bridge layer — useful
for validating that the transport plumbing works on a new machine
before plumbing real WireGuard underneath.

```powershell
# Terminal 1 — receiver
go run ./cmd/vkcalls-smoke -role=receiver -link=https://vk.com/call/join/<id>

# Terminal 2 — caller
go run ./cmd/vkcalls-smoke -role=caller -link=https://vk.com/call/join/<id>
```

Look for `session ready ✓` on both sides plus `gaps` and `corrupt`
counters that stay tiny (gaps≤1% expected, corrupt=0 always).
