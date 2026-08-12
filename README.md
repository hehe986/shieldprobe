# ShieldProbe 🛡️
> Audit your web security posture in seconds.

ShieldProbe analyzes the security posture of any website by checking HTTP security headers, SSL/TLS configuration, CORS policy, cookie flags, CSP deep analysis, and server fingerprinting — with a scored report.

## Features
- **11 Security Headers** — CSP, HSTS, X-Frame-Options, COEP, COOP, CORP, Permissions-Policy, dll
- **CSP Deep Analysis** — detect unsafe-inline, unsafe-eval, wildcard sources, missing directives
- **SSL/TLS Audit** — TLS 1.3 check, expiry warning, SAN, self-signed, deprecated protocol
- **Cookie Audit** — HttpOnly, Secure, SameSite, `__Host-` / `__Secure-` prefix validation
- **CORS Check** — wildcard, null origin, ACAO+ACAC credential leak combo
- **HTTP → HTTPS Redirect** check
- **Fingerprinting** — detect exposed server/framework/version info
- **Scoring** — A/B/C/F grade (0–100)
- **Export** — JSON + HTML dark-theme report

## Install

```bash
git clone https://github.com/hehe986/shieldprobe
cd shieldprobe
pip install -r requirements.txt
```

## Usage

```bash
# Scan domain
python shieldprobe.py --url https://target.com

# Scan with custom timeout
python shieldprobe.py --url https://target.com --timeout 15

# Export JSON
python shieldprobe.py --url https://target.com --output json

# Export HTML report
python shieldprobe.py --url https://target.com --output html

# Skip SSL audit
python shieldprobe.py --url https://target.com --no-ssl
```

## Output Example

```
  ┌─ SSL / TLS AUDIT ──────────────────────────────────────────
  │  Protocol  : TLSv1.3
  │  Issuer    : Let's Encrypt
  │  Expiry    : 2026-03-01 (87 days left)
  │  [✓] TLS 1.3 in use (best practice 2025)

  ┌─ SECURITY HEADERS ─────────────────────────────────────────
  │  [✓] Strict-Transport-Security          GOOD
  │  [✗] Content-Security-Policy            MISSING [CRITICAL]
  │       → Remove 'unsafe-inline' and 'unsafe-eval' from CSP
  │  [~] X-Frame-Options                    WEAK
  │  [✗] Cross-Origin-Embedder-Policy       MISSING [MEDIUM]

  ┌─ CORS CHECK ───────────────────────────────────────────────
  │  [✗] Wildcard CORS (*) — allows any origin

  ──────────────────────────────────────────────────────────────
  SCORE  :  55/100  [███████████░░░░░░░░░]  C — HIGH RISK
  ──────────────────────────────────────────────────────────────
```

## Author
- **H1lm1.exe**
- Informatics Engineering — Universitas Amikom Yogyakarta
