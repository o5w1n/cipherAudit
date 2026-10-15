# CipherAudit — Technical Requirements Document (TRD)

**Version:** 0.1 (Foundation phase)
**Status:** Draft
**Companion doc:** `PRD.md` (what and why). Requirement IDs (PR-1, CI-3, ...) refer to the PRD.

---

## 1. Key technical decisions

| Decision | Choice | Why |
|---|---|---|
| Language | **Python 3.13+** | Cross-platform (testssl.sh is bash, painful on Windows). 3.13 is required for `SSLSocket.get_unverified_chain()`. |
| Handshake probing | **Our own raw TLS wire layer** (build ClientHello bytes, parse server responses) | Same approach as testssl.sh's socket mode. Lets us test SSLv2/SSLv3, export ciphers, etc. regardless of what the local OpenSSL supports (PR-2). Also keeps the core logic ours, which is the point of the foundation phase. |
| Full handshakes | Python `ssl` module | Only where we need a completed handshake (TLS 1.3 certificate retrieval, trust validation). |
| X.509 parsing / validation | `cryptography` (incl. `x509.verification`) + `certifi` root store | Mature, well-maintained. |
| HTTP headers | `httpx` | Simple, sync + async. |
| CLI | `typer` | Clean subcommands and flags. |
| Terminal output | `rich` | Colors, tables, progress. |
| Data models | `pydantic` v2 | Typed results, free JSON serialization with a stable schema. |
| HTML report | `jinja2` | Single self-contained HTML file. |
| Tests | `pytest` + Docker test targets | |
| Lint / types | `ruff`, `mypy` (strict on `wire/` and `core/`) | |

**Explicitly not used for enumeration:** OpenSSL / the `ssl` module's cipher lists. A modern local OpenSSL refuses legacy protocols and ciphers, so results would reflect our machine rather than the server.

---

## 2. Architecture

```
            ┌───────────────────────────────────────────────┐
            │                 CLI (typer)                   │
            │   authorization gate · options · progress     │
            └──────────────────────┬────────────────────────┘
                                   │
            ┌──────────────────────▼────────────────────────┐
            │              Scan orchestrator                │
            │  runs cores in order, passes results forward  │
            └──┬──────────┬──────────┬──────────┬───────────┘
               │          │          │          │
         ┌─────▼───┐ ┌────▼────┐ ┌───▼─────┐ ┌──▼──────────┐
         │ Core 1  │ │ Core 2  │ │ Core 3  │ │  Core 4     │
         │Protocols│ │ Ciphers │ │ Cert &  │ │ Vulns       │
         │         │ │ Groups  │ │ Config  │ │ derived +   │
         │         │ │         │ │         │ │ active      │
         └────┬────┘ └────┬────┘ └───┬─────┘ └──┬──────────┘
              │           │          │          │
         ┌────▼───────────▼──────────▼──────────▼──────────┐
         │   wire/ — raw TLS: build ClientHello, send,     │
         │   parse records/handshake msgs/alerts           │
         │   + net/ — sockets, timeouts, rate limiter      │
         └─────────────────────────────────────────────────┘

                    ScanResult (raw facts, pydantic)
                                   │
            ┌──────────────────────▼────────────────────────┐
            │   Core 5 — Evaluation                          │
            │   rules engine → Findings (from catalog)       │
            │   scoring → score + grade                      │
            └──────────────────────┬────────────────────────┘
                                   │
                 ┌─────────────────┼─────────────────┐
                 ▼                 ▼                 ▼
               JSON            Terminal            HTML
```

**Core principle: facts and judgments are separate.** Cores 1–4 only record what the server *does* (`ScanResult`). Core 5 decides what that *means* (`Finding`, score). This keeps probes testable, lets us change scoring or wording without re-scanning, and later lets the same rules run on a config file instead of a live scan.

---

## 3. Project structure

```
cipheraudit/
├── pyproject.toml
├── README.md
├── PRD.md
├── TRD.md
├── src/cipheraudit/
│   ├── __init__.py
│   ├── cli.py                 # typer app, authorization gate
│   ├── orchestrator.py        # runs cores, builds ScanResult
│   ├── config.py              # ScanOptions (timeouts, rate limit, flags)
│   ├── net/
│   │   ├── connection.py      # TCP connect w/ timeout, STARTTLS later
│   │   └── ratelimit.py
│   ├── wire/                  # raw TLS — no judgments here
│   │   ├── constants.py       # versions, content types, alert codes, ext IDs
│   │   ├── records.py         # record layer encode/decode
│   │   ├── client_hello.py    # build TLS ClientHello (1.0–1.3) and SSLv2 CLIENT-HELLO
│   │   ├── server_msgs.py     # parse ServerHello, HRR, Certificate, ServerKeyExchange, alerts
│   │   ├── extensions.py      # SNI, supported_versions, supported_groups, sig_algs, ALPN, ...
│   │   └── handshake.py       # send hello → read until ServerHelloDone/alert/HRR/timeout
│   ├── data/
│   │   ├── ciphers.json       # IANA registry: code → names, kx, auth, enc, mac, bits, category
│   │   ├── groups.json        # named groups incl. hybrid PQ
│   │   ├── findings.yaml      # finding catalog (text, severity, NIST refs, remediation)
│   │   └── clients.json       # client profiles for simulation (P2)
│   ├── core/
│   │   ├── protocols.py       # Core 1
│   │   ├── ciphers.py         # Core 2
│   │   ├── certificate.py     # Core 3 (cert)
│   │   ├── server_config.py   # Core 3 (renegotiation, resumption, headers)
│   │   └── vulns/             # Core 4
│   │       ├── derived.py
│   │       ├── heartbleed.py
│   │       ├── ccs_injection.py
│   │       └── compression.py
│   ├── models/
│   │   ├── results.py         # ScanResult and per-core result models
│   │   └── findings.py        # Finding, Severity, Report
│   ├── evaluation/
│   │   ├── rules.py           # ScanResult → list[Finding]
│   │   └── scoring.py         # findings → score, grade, caps
│   └── report/
│       ├── json_out.py
│       ├── terminal.py
│       └── html/
│           ├── render.py
│           └── report.html.j2
└── tests/
    ├── unit/                  # wire encode/decode from recorded bytes, rules, scoring
    ├── fixtures/              # captured server responses (hex)
    ├── integration/           # against docker + public test targets
    └── targets/
        └── docker-compose.yml
```

---

## 4. The wire layer (`wire/`)

This is the foundation everything rests on. Build and test it first.

### 4.1 Responsibilities
- Encode TLS records and handshake messages byte-exact to RFC 5246 (TLS 1.2) / RFC 8446 (TLS 1.3), plus the SSLv2 CLIENT-HELLO format.
- Decode server responses into typed objects: `ServerHello`, `HelloRetryRequest`, `Certificate`, `ServerKeyExchange`, `ServerHelloDone`, `Alert`, or `ConnectionClosed` / `Timeout`.
- **Never** complete key exchange or encrypt anything. We stop reading as soon as we have what we need.

### 4.2 Core API

```python
@dataclass
class HelloParams:
    version: ProtocolVersion               # record + legacy_version to send
    cipher_suites: list[int]               # IANA codes
    sni: str | None
    supported_versions: list[ProtocolVersion] | None   # TLS 1.3 ext
    supported_groups: list[int] | None
    signature_algorithms: list[int] | None
    key_shares: list[int] | None           # groups to send key_share for (TLS 1.3)
    alpn: list[str] | None
    compression_methods: list[int] = [0]   # [1, 0] to test CRIME
    extra_extensions: list[Extension] = []

def probe(conn_factory, params: HelloParams, read_until: ReadUntil) -> ProbeOutcome:
    """Open a connection, send one ClientHello, read and parse the response."""
```

`ProbeOutcome` is one of: `Accepted(server_hello, extra_msgs)`, `HelloRetry(hrr)`, `Rejected(alert)`, `Closed`, `Timeout`, `ProtocolError(raw_bytes)`.

### 4.3 Rules
- Every socket operation has a timeout (default connect 5 s, read 5 s, configurable).
- Every probe goes through the rate limiter (default: max 4 new connections/second per host).
- Malformed or unexpected server bytes produce `ProtocolError` with the raw bytes kept for debugging — never an unhandled exception.
- TLS 1.3 key shares: we can send a random 32-byte X25519 public key without having the private key, since we never complete the handshake. For other groups, prefer sending `supported_groups` with **no** `key_share` and reading the group the server names in its `HelloRetryRequest`. This avoids generating large ML-KEM shares.

---

## 5. The five cores

### Core 1 — Protocol probing (`core/protocols.py`) → PR-1..5

**Method:** one probe per protocol version, each offering a broad cipher list valid for that version.

| Version | How |
|---|---|
| SSLv2 | SSLv2-format CLIENT-HELLO with all SSLv2 cipher kinds. Supported if server returns SERVER-HELLO. |
| SSLv3, TLS 1.0, 1.1, 1.2 | Record version and `legacy_version` set to target version, no `supported_versions` ext. Supported if `ServerHello.version` equals the offered version. If the server answers with a *different* version, record it as not supported (but note the downgrade behavior). |
| TLS 1.3 | `legacy_version` = 0x0303, `supported_versions` = [0x0304], TLS 1.3 suites + X25519 key share. Supported if ServerHello (or HRR) contains `supported_versions` = 0x0304. |

**ALPN (PR-3):** on the highest supported version, offer `["h2", "http/1.1"]` and record the server's choice.

**Output:**
```python
class ProtocolResult(BaseModel):
    supported: dict[ProtocolVersion, bool | None]   # None = inconclusive
    alpn_selected: str | None
    notes: list[str]
```

### Core 2 — Cipher enumeration (`core/ciphers.py`) → CI-1..6

**Enumeration (CI-1), per supported protocol:** iterative removal.
```
remaining = all ciphers valid for this protocol (from ciphers.json)
accepted  = []
loop:
    outcome = probe(offer=remaining)
    if Accepted: c = outcome.cipher; accepted.append(c); remaining.remove(c)
    else: break
```
Large cipher lists can make some servers reject the ClientHello; if `remaining` exceeds ~128 suites, split it into chunks and enumerate each chunk, then merge.

**Server preference (CI-3):** take the two strongest accepted ciphers A and B, offer [A, B] then [B, A]. Same choice both times → server enforces order. If it does, the order in which the removal loop accepted ciphers *is* the server's preference order. If not, mark order as "client-decided".

**Forward secrecy (CI-4):** derived from accepted cipher key-exchange fields (ECDHE/DHE vs RSA). All TLS 1.3 suites are forward-secret.

**Groups (CI-5):**
- TLS 1.2: offer one ECDHE cipher and one group at a time; read the curve from `ServerKeyExchange`.
- TLS 1.3: offer `supported_groups` = [candidate] with no key share; a `HelloRetryRequest` naming the candidate (or a ServerHello for X25519 when a share was sent) → supported.
- Candidate list from `groups.json`, including `X25519MLKEM768` (0x11EC) and other hybrid PQ codepoints.

**DH size (CI-6):** for accepted DHE suites, parse `p` length from `ServerKeyExchange`.

**Cipher classification (CI-2):** comes entirely from `ciphers.json`. Each entry:
```json
{"code": "0x000A", "iana": "TLS_RSA_WITH_3DES_EDE_CBC_SHA", "openssl": "DES-CBC3-SHA",
 "protocols": ["SSLv3","TLS1.0","TLS1.1","TLS1.2"],
 "kx": "RSA", "auth": "RSA", "enc": "3DES", "mode": "CBC", "bits": 112, "mac": "SHA1",
 "category": "3DES", "fs": false, "aead": false}
```
Build this file from the IANA TLS Cipher Suites registry (plus the SSLv2 cipher kinds). It is data, not code — treat it as reviewed reference material.

### Core 3 — Certificate & server configuration → CE-1..7

**Certificate chain (CE-1..4, `core/certificate.py`):**
- If TLS ≤ 1.2 is supported: read the plaintext `Certificate` message from a raw probe (no OpenSSL dependence).
- Otherwise (TLS 1.3-only server): full handshake with `ssl` (verification off), then `get_unverified_chain()`.
- Parse with `cryptography`: subject, issuer, SAN, key type/size (RSA bits, EC curve), signature algorithm, notBefore/notAfter, days to expiry, OCSP/CRL URLs, embedded SCTs.
- Trust: validate with `cryptography.x509.verification` against the `certifi` store, with the target hostname. Record pass/fail and the reason (expired, untrusted root, incomplete chain, hostname mismatch, self-signed).

**OCSP stapling (CE-5):** send `status_request` extension in a TLS 1.2 probe and check for a `CertificateStatus` message.

**Renegotiation / resumption (CE-6, `core/server_config.py`):**
- Secure renegotiation: offer `renegotiation_info` ext / SCSV; check ServerHello echoes it.
- Session resumption: full handshake with `ssl`, reconnect with the session object, check `session_reused`.

**HTTP headers (CE-7):** one `GET /` via `httpx` (follow up to 3 redirects, same host only). Record HSTS (parsed into max-age, includeSubDomains, preload), X-Content-Type-Options, X-Frame-Options, Content-Security-Policy presence.

**Output:** `CertificateResult`, `ServerConfigResult`.

### Core 4 — Vulnerability testing (`core/vulns/`) → VU-1..6

**Derived checks** (`derived.py`) — pure functions over Core 1–3 results, no network:

| Vuln | Condition |
|---|---|
| DROWN (indicator) | SSLv2 supported |
| POODLE (SSL) | SSLv3 supported with any CBC cipher |
| BEAST | TLS 1.0 / SSLv3 with CBC ciphers |
| SWEET32 | any 64-bit block cipher (3DES, IDEA, DES) accepted |
| RC4 | any RC4 suite accepted |
| FREAK | any RSA_EXPORT suite accepted |
| LOGJAM | DHE_EXPORT accepted, or DH prime < 1024 bits (weak if < 2048) |
| LUCKY13 (exposure) | CBC + HMAC suites accepted on TLS ≤ 1.2 |

**Active checks** — each its own module, each built on `wire/`:

| Vuln | Safe detection method |
|---|---|
| Heartbleed | Offer `heartbeat` ext; after ServerHello, send a heartbeat request whose declared payload length exceeds the real payload. A response longer than what we sent → vulnerable. **Discard the response bytes immediately; never log or store them.** |
| CCS injection | Send ChangeCipherSpec right after ServerHello, before key exchange. Server continuing instead of alerting → vulnerable. |
| Compression (CRIME) | Offer compression methods [DEFLATE, NULL]; server selecting DEFLATE → vulnerable. |
| ROBOT (P2) | Later phase. Requires careful timing/oracle analysis. |

Each check returns:
```python
class VulnResult(BaseModel):
    id: str                 # "heartbleed"
    status: Literal["vulnerable", "not_vulnerable", "inconclusive", "not_tested"]
    evidence: str           # short technical reason
```

### Core 5 — Evaluation & reporting → RE-1..7

**5a. Findings catalog (`data/findings.yaml`)** — all human-facing wording lives here, not in code.
```yaml
- id: PROTO_TLS10_ENABLED
  title: "Server accepts TLS 1.0"
  severity: high
  plain: >
    Your server still accepts a version of the security protocol from 1999.
    It has known weaknesses, and modern browsers no longer use it, so keeping
    it on only helps attackers.
  technical: "TLS 1.0 negotiated successfully."
  nist: ["SP 800-52 Rev. 2, §3.1 (TLS 1.2 minimum)"]
  remediation: "Disable TLS 1.0 and TLS 1.1 in your server's TLS settings. Keep TLS 1.2 and 1.3."
  score_impact: {deduct: 20, cap: 79}
```
Remediation text is generic for now. Leave room for a future `remediation_by_stack: {nginx: ..., apache: ...}` key.

**5b. Rules engine (`evaluation/rules.py`):** a list of small rule functions `(ScanResult) -> list[Finding]`, each referencing catalog IDs. One rule per catalog entry where possible. Rules are pure and unit-tested with hand-built `ScanResult` fixtures.

**5c. Scoring (`evaluation/scoring.py`):** deterministic and documented in the report.
```
score = 100 − sum(deductions of all findings)        (floor 0)
score = min(score, lowest cap among all findings)

Severity defaults (overridable per finding):
  critical: deduct 40, cap 39   (e.g. SSLv2, Heartbleed, expired/untrusted cert)
  high:     deduct 20, cap 64   (e.g. SSLv3, TLS 1.0/1.1, RC4, export ciphers)
  medium:   deduct 10           (e.g. 3DES, no forward secrecy on some suites, DH < 2048)
  low:      deduct 3            (e.g. no HSTS, CBC suites on TLS 1.2)
  info:     deduct 0            (e.g. no PQ key exchange, ALPN details)

Grade: A ≥ 90, B ≥ 80, C ≥ 65, D ≥ 50, E ≥ 40, F < 40
```
Caps ensure one critical issue can't be hidden by an otherwise good config. Treat these numbers as v0.1; the PRD lists tuning as an open question.

**5d. Reporters:**
- `json_out.py` — dumps `Report` (metadata + `ScanResult` + findings + score). Include `schema_version`.
- `terminal.py` — score/grade banner, findings sorted by severity with plain text first, technical detail behind `--verbose`.
- `html/` — single self-contained file (inline CSS, no external assets). Page 1: target, date, grade, score, top 3 issues in plain language, PQ readiness. Below: full findings, then raw protocol/cipher/cert tables. Include the scoring method section.

**PQ readiness (RE-7):** derived from Core 2 groups — `ready` if any hybrid ML-KEM group is supported on TLS 1.3, else `not_ready`, with explanation from the catalog.

---

## 6. Data model (top level)

```python
class ScanTarget(BaseModel):
    host: str
    port: int = 443
    ip: str
    sni: str | None

class ScanResult(BaseModel):           # facts only
    target: ScanTarget
    started_at: datetime
    finished_at: datetime
    protocols: ProtocolResult
    ciphers: CipherResult | None
    certificate: CertificateResult | None
    server_config: ServerConfigResult | None
    vulns: list[VulnResult]
    errors: list[str]

class Finding(BaseModel):              # judgments
    id: str
    title: str
    severity: Severity
    plain: str
    technical: str
    nist: list[str]
    remediation: str
    evidence: dict[str, Any]

class Report(BaseModel):
    schema_version: str = "0.1"
    tool_version: str
    scan: ScanResult
    findings: list[Finding]
    score: int
    grade: str
    pq_ready: bool | None
```

---

## 7. CLI

```
cipheraudit scan <host>[:port]
    --i-have-permission        skip interactive authorization prompt (still logged in report)
    --protocols / --ciphers / --cert / --vulns     run selected cores only (default: all)
    --no-active-vulns          derived vulnerability checks only
    --sni <name>               override SNI
    --timeout <sec>            default 5
    --rate <n>                 max new connections/sec, default 4
    --json <path>  --html <path>
    --verbose
cipheraudit version
```
**Authorization gate (X-1):** without `--i-have-permission`, prompt `Do you have permission to scan <host>? [y/N]`; anything but `y` exits with code 2. The report records how authorization was given.

Exit codes: 0 scan completed, 1 scan error, 2 not authorized, 3 target unreachable.

---

## 8. Error handling & performance

- Each core catches its own failures and records them in `ScanResult.errors`; one failing core never aborts the others (unless Core 1 finds no TLS at all).
- `None` / `inconclusive` is always preferred over a guess.
- Target: full scan < 2 minutes. Cipher enumeration is the slowest part; probes for different protocols may run concurrently (thread pool), bounded by the rate limiter.

---

## 9. Testing strategy

**Unit tests (`tests/unit/`):**
- `wire/`: encode ClientHellos and compare to known-good byte captures; decode recorded ServerHello/Alert/HRR/Certificate bytes from `tests/fixtures/`.
- `ciphers.json` integrity: unique codes, valid categories, every suite has a protocol list.
- Rules: hand-built `ScanResult` → expected findings.
- Scoring: findings → expected score/grade, including caps.

**Integration tests (`tests/integration/`, marked `@pytest.mark.network`):**
- Local Docker targets (`tests/targets/docker-compose.yml`):
  - `modern` — nginx, TLS 1.2 + 1.3, AEAD only, ECDSA cert → expect grade A
  - `legacy` — server built on an old OpenSSL (1.0.2) with SSLv3, TLS 1.0, RC4, 3DES, export suites enabled, RSA-1024 self-signed cert → expect many findings
  - `tls13-only` — exercises the TLS 1.3 certificate path
  - `pq` — server with hybrid ML-KEM enabled (OpenSSL 3.5+) → expect `pq_ready`
- Public test endpoints from **badssl.com** (built for exactly this purpose): expired, self-signed, wrong host, untrusted root, 3DES, RC4, DH1024, old TLS versions. Confirm current hostnames/ports on the site before writing the tests.
- **Accuracy check (PRD §7):** for each target, run testssl.sh `--jsonfile` and compare protocols + accepted ciphers to ours. A script `tests/compare_testssl.py` reports mismatches.

Only scan our own containers and badssl.com in tests. Never hardcode third-party hosts.

---

## 10. Build order (for Claude Code)

Follow the PRD milestones. Within each, write tests alongside the code.

1. **M0** — `pyproject.toml`, package skeleton, `cli.py` with authorization gate, `net/connection.py`, rate limiter, `docker-compose.yml` with `modern` and `legacy` targets.
2. **M1** — `wire/constants.py`, `records.py`, `extensions.py`, `client_hello.py`, `server_msgs.py` (ServerHello, HRR, Alert), `handshake.py` → `core/protocols.py`. Verify against both Docker targets.
3. **M2** — `data/ciphers.json`, `data/groups.json` → `core/ciphers.py` (enumeration, preference, FS, groups, DH size). Write `compare_testssl.py` here.
4. **M3** — `server_msgs.py` (Certificate, ServerKeyExchange, CertificateStatus) → `core/certificate.py`, `core/server_config.py`.
5. **M4** — `models/`, `data/findings.yaml`, `evaluation/rules.py`, `evaluation/scoring.py`, `report/json_out.py`, `report/terminal.py`, `orchestrator.py`. First end-to-end scored scan.
6. **M5** — `core/vulns/derived.py` + catalog entries.
7. **M6** — active checks: compression → CCS injection → Heartbleed.
8. **M7** — HTML report, PQ readiness, remaining P1 items.

### Conventions
- `wire/` and `core/` produce facts only. No severities, scores or user-facing prose outside `data/findings.yaml` and `report/`.
- No probe without a timeout and the rate limiter.
- No network access in unit tests.
- Type hints everywhere; `mypy --strict` on `wire/` and `core/`.
- Small, reviewable commits — one milestone sub-step per commit.

---

## 11. References

- RFC 5246 — TLS 1.2
- RFC 8446 — TLS 1.3
- RFC 6101 — SSL 3.0 (historic); SSLv2 draft spec for CLIENT-HELLO format
- RFC 7507 — TLS_FALLBACK_SCSV
- RFC 5746 — Renegotiation indication
- RFC 6520 — Heartbeat extension
- IANA TLS Parameters registry (cipher suites, named groups, extensions)
- NIST SP 800-52 Rev. 2, SP 800-131A, SP 800-57 Part 1, FIPS 203 (confirm current revisions before quoting clauses)
- testssl.sh source (for behavior comparison; GPLv2, so reference only, do not copy code)
