# ShieldGate

Kernel-level adaptive firewall for **Attack-Defense CTF**. Written in Go,
intercepts traffic through **NFQUEUE + nftables** (no Docker, no userspace
proxy), learns what legitimate traffic looks like while the scoring board's
checker is green, and then iteratively shrinks the attack surface by
temp-banning groups of similar flows and watching whether the checker stays
green.

## How it works

1. **Board integration** — ShieldGate polls the scoring board (ForcAD, CTFd
   with AD plugin, or FAUST gameserver) for the service list, checker status,
   your team IP and the list of opponent team IPs.
2. **Learning phase** — once a service checker is green, incoming requests are
   fingerprinted (dynamic data such as tokens, cookies, IPs and timestamps is
   normalized away) and clustered into *flow groups*. If the checker survives
   `n*2` (n = round duration), all collected groups become **Allowed**.
3. **Flag detection** — any payload matching the flag regex (default
   `[A-Za-z0-9]{31}=`) marks the flow; flagged traffic is dropped immediately.
4. **Optimization loop** — every cycle, a weighted random 25% of allowed
   groups are **TempBanned** for `n*2`:
   * checker still green → those groups become permanently **Banned**
     (banned packets are mirrored to other teams via a raw socket);
   * checker red → groups are restored to Allowed with a −25% weight penalty
     (lower weight = picked later in future cycles), plus one extra `n*2`
     recovery window.
5. **Policy** — Allowed → ACCEPT · Banned → DROP+RST (+mirror) · TempBanned →
   DROP silently · Unknown → DROP (conservative).

## Quick start

```sh
make build
sudo ./shieldgate -config shieldgate.yaml
```

Requires Linux with nftables support and root (CAP_NET_ADMIN + CAP_NET_RAW).
The Web UI is served on `:8080`.

## Development

```sh
make test          # unit tests
make web-dev       # frontend dev server (proxies API to :8080)
```

## Layout

| Path | Purpose |
|---|---|
| `cmd/shieldgate` | entry point / wiring |
| `internal/engine/nfqueue` | NFQUEUE handling + nftables rules |
| `internal/engine/classifier` | flows, fingerprints, flow groups |
| `internal/engine/reassembler` | TCP stream reassembly |
| `internal/engine/policy` | verdict decision engine |
| `internal/engine/mirror` | packet mirroring to other teams |
| `internal/board/*` | ForcAD / CTFd / FAUST adapters |
| `internal/state` | services, learning, optimizer |
| `internal/storage` | SQLite persistence + pcap dump |
| `internal/api` | REST + WebSocket for the UI |
| `web/` | React + TypeScript + Tailwind UI |

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for details.
