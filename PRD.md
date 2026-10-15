# CipherAudit — Product Requirements Document (PRD)

**Version:** 0.1 (Foundation phase)
**Status:** Draft
**Companion doc:** `TRD.md` (how it's built)

---

## 1. Summary

CipherAudit is a command-line scanner that inspects the TLS configuration of a live server and produces a report a non-specialist can act on. It does what testssl.sh does at its core, and then translates each finding into plain language, a risk score, the NIST requirement it fails, and a concrete fix.

This PRD covers the **foundation phase**: building the five core capabilities that every later feature depends on.

1. Protocol probing
2. Cipher suite enumeration
3. Certificate and server configuration analysis
4. Vulnerability testing
5. Evaluation and reporting

Stack-specific remediation, the config-file mode, a web dashboard and the user study come after the foundation is solid.

---

## 2. Problem

Small organizations (SMEs, startups, university IT teams) often run outdated cryptography: old TLS versions, weak ciphers, short keys, SHA-1 certificates. The padlock still shows in the browser, so nobody notices.

Existing tools find these problems, but they report them in specialist language (`TLS_RSA_WITH_3DES_EDE_CBC_SHA — SWEET32`). Teams without security staff can't tell what matters or what to do about it.

---

## 3. Goals and non-goals

### Goals (foundation phase)
- G1. Accurately detect which SSL/TLS protocol versions a server supports.
- G2. Accurately enumerate accepted cipher suites per protocol, and the server's preference behavior.
- G3. Extract and assess the certificate chain and key server settings.
- G4. Detect a defined set of well-known TLS vulnerabilities using **non-destructive** checks.
- G5. Produce a scored report in both machine-readable (JSON) and human-readable (terminal, HTML) form, with every finding carrying a plain-language explanation and a NIST reference.

### Non-goals (for now)
- Exploiting vulnerabilities or extracting data from targets.
- Mass scanning of IP ranges.
- Scanning non-TLS services (SSH, VPN) — later phase.
- Analyzing internal practices invisible from outside (e.g. password hashing).
- Web UI / hosted SaaS — later phase.
- Stack-specific remediation templates (nginx/Apache/IIS) — next phase, but the data model must leave room for them.

---

## 4. Users

| User | Needs | What they read |
|---|---|---|
| SME owner / manager | "Are we safe? How bad is it?" | Overall score, executive summary |
| Generalist IT / DevOps | "What exactly is wrong and how do I fix it?" | Findings list with explanations and fixes |
| Security auditor | Full technical evidence for client reports | Detailed section, JSON output |
| Our team (developers) | Reliable, testable building blocks | JSON output, logs |

---

## 5. Functional requirements

Priority: **P0** = must ship in foundation phase, **P1** = should ship, **P2** = nice to have.

### Core 1 — Protocol probing

| ID | Requirement | Priority |
|---|---|---|
| PR-1 | Detect support for SSLv2, SSLv3, TLS 1.0, TLS 1.1, TLS 1.2, TLS 1.3. | P0 |
| PR-2 | Detection must not depend on what the local OS/OpenSSL supports (old protocols must still be testable). | P0 |
| PR-3 | Report ALPN protocols offered (e.g. h2, http/1.1). | P1 |
| PR-4 | Support STARTTLS for SMTP, IMAP, POP3, FTP. | P2 |
| PR-5 | Handle unreachable hosts, timeouts, and non-TLS ports with clear errors. | P0 |

### Core 2 — Cipher suite enumeration

| ID | Requirement | Priority |
|---|---|---|
| CI-1 | For each supported protocol, list every accepted cipher suite (IANA name + OpenSSL name). | P0 |
| CI-2 | Classify each suite by strength category: NULL, anonymous, export, RC4, 3DES, CBC, AEAD. | P0 |
| CI-3 | Determine whether the server enforces its own cipher order, and report that order. | P0 |
| CI-4 | Report forward secrecy support (ECDHE/DHE vs static RSA). | P0 |
| CI-5 | List supported key exchange groups (X25519, P-256, P-384, ffdhe*, and hybrid post-quantum groups such as X25519MLKEM768). | P1 |
| CI-6 | Report DH parameter size where finite-field DH is used. | P1 |

### Core 3 — Certificate and server configuration

| ID | Requirement | Priority |
|---|---|---|
| CE-1 | Retrieve the full certificate chain presented by the server. | P0 |
| CE-2 | Report key type and size, signature algorithm, validity dates, days until expiry. | P0 |
| CE-3 | Check hostname match (SAN/CN) and chain completeness. | P0 |
| CE-4 | Check trust against a standard root store. | P0 |
| CE-5 | Report OCSP stapling and Certificate Transparency (SCT) presence. | P1 |
| CE-6 | Report secure renegotiation and session resumption support. | P1 |
| CE-7 | Fetch HTTP security headers (HSTS with max-age/includeSubDomains/preload, plus X-Content-Type-Options, X-Frame-Options, CSP presence). | P1 |

### Core 4 — Vulnerability testing

All checks must be **non-destructive**: detect the condition, never exploit it beyond what's needed to confirm it, never extract server memory content.

| ID | Requirement | Priority |
|---|---|---|
| VU-1 | Derived checks (from Cores 1–3 data, no extra probes): POODLE (SSLv3), BEAST, SWEET32, RC4, FREAK, LOGJAM, DROWN (SSLv2 present), LUCKY13 exposure. | P0 |
| VU-2 | Active check: Heartbleed (safe detection — malformed heartbeat, response length checked, payload discarded). | P1 |
| VU-3 | Active check: CCS injection. | P1 |
| VU-4 | Active check: TLS compression (CRIME). | P1 |
| VU-5 | Active check: ROBOT. | P2 |
| VU-6 | Each vulnerability result: `vulnerable`, `not_vulnerable`, or `inconclusive` — never guess. | P0 |

### Core 5 — Evaluation and reporting

| ID | Requirement | Priority |
|---|---|---|
| RE-1 | Every finding carries: ID, title, severity, plain-language explanation, technical detail, NIST reference, and a generic remediation note. | P0 |
| RE-2 | Compute an overall score (0–100) and letter grade (A–F) using a documented, deterministic model. | P0 |
| RE-3 | Output JSON (complete, stable schema). | P0 |
| RE-4 | Output a readable terminal summary (color, severity-sorted). | P0 |
| RE-5 | Output a standalone HTML report: one-page executive summary on top, technical detail below. | P1 |
| RE-6 | Client simulation: show what common clients (current Chrome, Firefox, Safari, Android, older Windows/Java) would negotiate. | P2 |
| RE-7 | A post-quantum readiness status (supports hybrid ML-KEM key exchange: yes/no + explanation). | P1 |

### Cross-cutting

| ID | Requirement | Priority |
|---|---|---|
| X-1 | **Authorization gate:** before every scan, the user must confirm they own or have written permission to test the target (interactive prompt, or `--i-have-permission` flag for scripted use). | P0 |
| X-2 | Rate-limit connections to a target (configurable, sensible default). | P0 |
| X-3 | Each core can run independently (e.g. `--protocols`, `--ciphers`) or all together. | P0 |
| X-4 | Runs on Windows, macOS, Linux. | P0 |

---

## 6. Example user flow

```
$ cipheraudit scan example.com

  ⚠  Only scan systems you own or have written permission to test.
  Do you have permission to scan example.com? [y/N]: y

  Scanning example.com:443 ...
  [1/5] Protocols ........ done
  [2/5] Cipher suites .... done
  [3/5] Certificate ...... done
  [4/5] Vulnerabilities .. done
  [5/5] Evaluating ....... done

  Overall: 58/100  (Grade C)

  🔴 HIGH   Server still accepts TLS 1.0
           This is a 20+ year-old version of the protocol with known weaknesses.
           Fails NIST SP 800-52 Rev. 2 (TLS 1.2 minimum).
           Fix: disable TLS 1.0 and 1.1 in your server's TLS settings.

  🟠 MEDIUM 3DES cipher accepted (SWEET32)
           ...

  Full report: reports/example.com-2026-10-15.html
```

---

## 7. Success criteria (foundation phase)

1. **Accuracy:** on our test targets (see TRD §9), protocol and cipher results match testssl.sh's output for the same target with zero mismatches.
2. **Coverage:** all P0 requirements implemented and tested.
3. **Explainability:** every finding type has a plain-language explanation reviewed by at least one non-security teammate ("do you understand what's wrong and why it matters?").
4. **Safety:** no scan runs without the authorization step; no check extracts data from the target.
5. **Speed:** a full scan of a typical server completes in under 2 minutes.

---

## 8. Milestones

| # | Milestone | Done when |
|---|---|---|
| M0 | Project skeleton, CLI, authorization gate, test targets running locally | `cipheraudit scan localhost:8443` connects and exits cleanly |
| M1 | Core 1 — Protocol probing | PR-1, PR-2, PR-5 pass against all test targets |
| M2 | Core 2 — Cipher enumeration | CI-1 to CI-4 pass, results match testssl.sh |
| M3 | Core 3 — Certificate & config | CE-1 to CE-4 pass |
| M4 | Core 5 (early) — Findings model, scoring, JSON + terminal output | End-to-end scored report from Cores 1–3 |
| M5 | Core 4 — Derived vulnerability checks | VU-1 complete |
| M6 | Core 4 — Active vulnerability checks | VU-2 to VU-4 |
| M7 | Core 5 (complete) — HTML report, PQ readiness, P1 items | Report reviewed by a non-specialist |

Reporting (M4) deliberately comes before vulnerabilities (M5): it gives us a working end-to-end tool early, and the findings model then shapes how vulnerability results are written.

---

## 9. Ethics and safety

- Scans only systems the user owns or has written permission to test (X-1).
- All checks are detection-only and non-destructive.
- No default target lists, no IP range scanning.
- Reports may contain sensitive information about a target's weaknesses; they are written locally only and never uploaded anywhere.

---

## 10. Open questions

1. Scoring weights — start with the model in TRD §7 and tune after testing on real configurations?
2. Which NIST revision of SP 800-131A do we cite (confirm current status before finalizing reference text)?
3. Do we want a Ghana-specific compliance mapping (Cyber Security Act 2020 / CSA guidance) in the foundation phase or later?
