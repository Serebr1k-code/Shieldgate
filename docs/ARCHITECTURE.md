# ShieldGate Architecture

```
KERNEL                          USER SPACE (Go)
┌──────────┐   ┌────────────┐   ┌─────────────────────────────┐
│ Incoming │──▶│ nftables   │──▶│ NFQUEUE (one per svc port)  │
│ packet   │   │ queue rule │   │  engine.Handle()            │
└──────────┘   └────────────┘   └──────────────┬──────────────┘
                                               │ decode L3/L4
                             ┌─────────────────▼─────────────────┐
                             │ classifier.Manager  (flow + payload)│
                             └─────────────────┬─────────────────┘
                        flag scan │ fingerprint+group
                             ┌─────────────────▼─────────────────┐
                             │ policy.Evaluate                    │
                             │ Allowed→ACCEPT  Banned→DROP+RST    │
                             │ TempBanned→DROP  Unknown→DROP      │
                             └───────┬───────────────┬───────────┘
                                 mirror          storage/SQLite
                              (banned only)      decisions+flags
```

## Components

* **nfqueue** — binds kernel queues (`florianl/go-nfqueue/v2`) and installs
  nftables rules (`google/nftables`): table `shieldgate`, chain
  `input-queue`, one `tcp dport X queue num N bypass` rule per service port.
* **classifier** — canonical 5-tuple flow IDs, ring buffers for the last N KB
  of each direction, HTTP-aware normalization (query values, cookies,
  header values, numeric path IDs, IPv4/timestamps/hex IDs masked), SHA-256
  exact match plus Levenshtein fuzzy match at ≥0.85 similarity.
* **reassembler** — gopacket/reassembly with force-start Accept so mid-capture
  flows are assembled; ordered bytes delivered per direction to sinks.
* **policy** — pure function flow/group → verdict; TempBanned and flagged
  traffic never mirrored.
* **mirror** — rewrites dst IP in raw IP packets (IP/TCP/UDP checksums
  recomputed) and sends via `AF_INET/SOCK_RAW/IPPROTO_RAW`.
* **board** — `BoardClient` interface; adapters translate board-specific JSON
  into services/checker status/team lists. Status strings ("up", "GOOD",
  "MUMBLE", …) map onto green/red/unknown.
* **state** — per-service phase machine: Idle → Learning (n×2 window,
  reset if checker drops) → Filtering → Optimizing (1/4 weighted-random
  temp-ban cycles with −25% weight penalty on failure, weight reset on
  success). Groups marked `is_checker` by the operator are excluded from
  temp-ban selection forever.
* **storage** — SQLite (WAL): groups, settings, decision log, flag hits;
  optional pcap writer (LINKTYPE_RAW).
* **api** — chi REST under `/api/v1` plus a WebSocket hub at `/ws`
  broadcasting `checker.update`, `phase.change`, `group.update`,
  `flag.detected`.

## Verdict matrix

| Condition                | Verdict | RST | Mirrored |
|--------------------------|---------|-----|----------|
| Flag seen in flow        | DROP    | ✓   | ✗        |
| Group Banned             | DROP    | ✓   | ✓        |
| Group TempBanned         | DROP    | ✗   | ✗        |
| Group Allowed            | ACCEPT  |     |          |
| Unknown / no group       | DROP    | ✗   | ✗        |

## Optimization

Default strategy `optimize.strategy: binary` — agenda-based binary splitting:

1. Agenda starts with the full Allowed set of a service.
2. Take a chunk, split into halves (smaller half tested first with 70%
   probability), temp-ban one half for the test window (n×2).
3. The checker is polled every `check_interval` (5s): a confirmed failure
   (2 consecutive red samples not matching baseline flakiness signatures)
   aborts the window immediately.
4. Green whole window ⇒ the chunk is proven safe → permanent Ban;
   the other half stays on the agenda.
   Red ⇒ restore chunk, push its halves back (recursion).
5. Single-group chunks that fail are marked **critical** (`IsChecker=true`,
   failure message stored): their traffic stays Allowed forever and they
   never re-enter the search.

Convergence: O(log N) windows per critical group; services search in
parallel since each has its own checker. ForcAD failure messages
("Could not get flag", "Checker timed out", ...) are compared against a
pre-window baseline so background flakiness does not derail the search.

Legacy `strategy: random` keeps the old behaviour: weighted random selection
(Efraimidis–Spirakis) of `floor(len * ban_fraction)` groups per n×2 cycle,
−25% weight penalty on failure.

## Performance notes

NFQUEUE callbacks must stay cheap: packet parsing is zero-copy where possible
(`NoCopy` decode option), payloads stored in fixed-size ring buffers, SQLite
writes happen off the hot verdict path only for drops/flags.

Grouping cost control: exact fingerprint matches hit a SHA-256 index (~300ns).
Fuzzy comparison is bounded by a length-difference prefilter and a 512-byte
template cap, so the worst-case Levenshtein is ~0.5ms and only runs when a
*new* template shape appears (rare outside learning). A future eBPF/TC
fast-path can short-circuit established Allowed flows without entering
userspace (see `bpf/`).
