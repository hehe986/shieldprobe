<p align="center"><pre>
  ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
  ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
  ███████╗███████║██║█████╗  ██║     ██║  ██║██████╔╝██║   ██║██████╔╝█████╗
  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║██╔═══╝ ██║   ██║██╔══██╗██╔══╝
  ███████║██║  ██║██║███████╗███████╗██████╔╝██║     ╚██████╔╝██████╔╝███████╗
  ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ╚═╝      ╚═════╝ ╚═════╝╚══════╝
</pre></p>

<h1 align="center">ShieldProbe 🛡️</h1>
<p align="center">Audit your web security posture in seconds.</p>
<p align="center">
  <img src="https://img.shields.io/badge/python-3.8+-blue?style=flat-square&logo=python">
  <img src="https://img.shields.io/badge/platform-Linux%20%7C%20Any%20Distro-informational?style=flat-square">
  <img src="https://img.shields.io/badge/license-MIT-green?style=flat-square">
  <img src="https://img.shields.io/badge/headers-11%2B-purple?style=flat-square">
  <img src="https://img.shields.io/badge/version-2.0.0-orange?style=flat-square">
</p>

---

```
  ╔═══════════════════════════════════════════════════════════════════╗
  ║  URL/Domain                                                       ║
  ║      │                                                            ║
  ║      ├──▶  SSL/TLS Audit     (protocol · expiry · SAN)           ║
  ║      ├──▶  Security Headers  (11 headers · CSP deep scan)        ║
  ║      ├──▶  Cookie Audit      (HttpOnly · Secure · SameSite)      ║
  ║      ├──▶  CORS Check        (wildcard · null origin · creds)    ║
  ║      ├──▶  Fingerprinting    (server · framework · version)      ║
  ║      └──▶  Score: 0–100      A / B / C / F                       ║
  ╚═══════════════════════════════════════════════════════════════════╝
```

## What is ShieldProbe?

ShieldProbe analyzes the **security posture** of any website by auditing HTTP security headers,
SSL/TLS configuration, CORS policy, cookie flags, CSP directives, and server fingerprinting —
then gives an overall security score with recommendations.

## Features

| Feature | Description |
|---------|-------------|
| 🔒 11 Security Headers | CSP, HSTS, X-Frame-Options, COEP, COOP, CORP, Permissions-Policy, dll |
| 🧬 CSP Deep Analysis | Detect unsafe-inline, unsafe-eval, wildcard, missing directives |
| 🔐 SSL/TLS Audit | TLS 1.3 check, expiry warning, SAN, self-signed, deprecated protocol |
| 🍪 Cookie Audit | HttpOnly, Secure, SameSite, `__Host-` / `__Secure-` prefix |
| 🌐 CORS Check | Wildcard, null origin, ACAO+ACAC credential leak combo |
| 🔁 HTTP→HTTPS Redirect | Verify HTTP traffic is correctly upgraded |
| 🕵️ Fingerprinting | Detect exposed server/framework/version info |
| 📊 Security Score | 0–100 with grade A/B/C/F |
| 📄 Export | JSON + dark-theme HTML report |

## Headers Checked (2025/2026 Standard)

```
  ✦ Strict-Transport-Security      (HSTS)
  ✦ Content-Security-Policy        (CSP)
  ✦ X-Frame-Options
  ✦ X-Content-Type-Options
  ✦ Referrer-Policy
  ✦ Permissions-Policy
  ✦ Cross-Origin-Embedder-Policy   (COEP)  ← 2024 standard
  ✦ Cross-Origin-Opener-Policy     (COOP)  ← 2024 standard
  ✦ Cross-Origin-Resource-Policy   (CORP)
  ✦ Cache-Control
  ✦ X-XSS-Protection
```

## Install

```bash
git clone https://github.com/hehe986/shieldprobe.git
cd shieldprobe
bash install.sh
```

> **Kali Linux / Ubuntu / Debian:**
> ```bash
> pip install -r requirements.txt --break-system-packages
> ```

> **Arch Linux / Manjaro:**
> ```bash
> pip install -r requirements.txt --break-system-packages
> ```

> **Fedora / RHEL / CentOS:**
> ```bash
> pip3 install -r requirements.txt
> ```

> **openSUSE:**
> ```bash
> pip3 install -r requirements.txt
> ```

> **Universal (semua distro) — via venv:**
> ```bash
> python3 -m venv venv
> source venv/bin/activate
> pip install -r requirements.txt
> ```

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
  │  Expiry    : 2026-10-01 (120 days left)
  │  [✓] TLS 1.3 in use (best practice 2025)
  │  [✓] Certificate valid for 120 days

  ┌─ SECURITY HEADERS ─────────────────────────────────────────
  │  [✓] Strict-Transport-Security          GOOD
  │  [✗] Content-Security-Policy            MISSING [CRITICAL]
  │       → Remove 'unsafe-inline' and 'unsafe-eval' from CSP
  │  [~] X-Frame-Options                    WEAK
  │  [✗] Cross-Origin-Embedder-Policy       MISSING [MEDIUM]

  ┌─ CORS CHECK ───────────────────────────────────────────────
  │  [✓] CORS policy appears correctly configured

  ┌─ FINGERPRINTING ───────────────────────────────────────────
  │  [!] Server: nginx/1.18.0
  │       → Web server & version exposed

  ─────────────────────────────────────────────────────────────
  SCORE  :  55/100  [███████████░░░░░░░░░]  C — HIGH RISK
  ─────────────────────────────────────────────────────────────
```

## Score Grading

```
  A  (85–100)  ██████████████████████  LOW RISK
  B  (70–84)   ██████████████░░░░░░░░  MEDIUM RISK
  C  (50–69)   ███████████░░░░░░░░░░░  HIGH RISK
  F  (0–49)    ██████░░░░░░░░░░░░░░░░  CRITICAL RISK
```

## Author

```
  ╔══════════════════════════════════╗
  ║  H1lm1.exe                       ║
  ║  Informatics Engineering         ║
  ║  Universitas Amikom Yogyakarta   ║
  ╚══════════════════════════════════╝
```

> ⚠️ For educational and authorized security testing purposes only.
