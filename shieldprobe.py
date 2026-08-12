#!/usr/bin/env python3

import ssl
import sys
import json
import socket
import argparse
import datetime
from urllib.parse import urlparse

try:
    import requests
    from colorama import init, Fore, Style
    init(autoreset=True)
except ImportError:
    print("Missing dependencies. Run: pip install requests colorama")
    sys.exit(1)

# ─────────────────────────────────────────────
#  BANNER
# ─────────────────────────────────────────────

BANNER = r"""
  ███████╗██╗  ██╗██╗███████╗██╗     ██████╗ ██████╗ ██████╗  ██████╗ ██████╗ ███████╗
  ██╔════╝██║  ██║██║██╔════╝██║     ██╔══██╗██╔══██╗██╔══██╗██╔═══██╗██╔══██╗██╔════╝
  ███████╗███████║██║█████╗  ██║     ██║  ██║██████╔╝██████╔╝██║   ██║██████╔╝█████╗
  ╚════██║██╔══██║██║██╔══╝  ██║     ██║  ██║██╔═══╝ ██╔══██╗██║   ██║██╔══██╗██╔══╝
  ███████║██║  ██║██║███████╗███████╗██████╔╝██║     ██║  ██║╚██████╔╝██████╔╝███████╗
  ╚══════╝╚═╝  ╚═╝╚═╝╚══════╝╚══════╝╚═════╝ ╚═╝     ╚═╝  ╚═╝ ╚═════╝ ╚═════╝╚══════╝
"""

VERSION = "1.1.0"

def print_banner():
    print(Fore.CYAN + BANNER)
    print(Fore.CYAN + "  ShieldProbe - HTTP Security Header Analyzer")
    print(Fore.CYAN + "  Author  : H1lm1.exe")
    print(Fore.CYAN + f"  Version : {VERSION}")
    print(Fore.CYAN + "  Target  : Headers · SSL/TLS · CORS · Cookies · CSP · Fingerprint · DNS")
    print(Fore.CYAN + "  " + "─" * 65)
    print()

# ─────────────────────────────────────────────
#  SECURITY HEADERS — 2025/2026 STANDARD
# ─────────────────────────────────────────────

SECURITY_HEADERS = {
    'Strict-Transport-Security': {
        'desc': 'Enforces HTTPS (HSTS)',
        'severity': 'CRITICAL',
        'check': lambda v: 'max-age' in v.lower() and int(
            __import__('re').search(r'max-age=(\d+)', v.lower()).group(1)
            if __import__('re').search(r'max-age=(\d+)', v.lower()) else '0'
        ) >= 31536000,
        'recommendation': 'Set max-age >= 31536000 (1 year), add includeSubDomains'
    },
    'Content-Security-Policy': {
        'desc': 'Prevents XSS & data injection (CSP)',
        'severity': 'CRITICAL',
        'check': lambda v: "unsafe-inline" not in v and "unsafe-eval" not in v and len(v) > 10,
        'recommendation': "Remove 'unsafe-inline' and 'unsafe-eval' from CSP"
    },
    'X-Frame-Options': {
        'desc': 'Prevents clickjacking (legacy — use CSP frame-ancestors)',
        'severity': 'HIGH',
        'check': lambda v: v.upper() in ['DENY', 'SAMEORIGIN'],
        'recommendation': "Set to DENY or SAMEORIGIN"
    },
    'X-Content-Type-Options': {
        'desc': 'Prevents MIME sniffing',
        'severity': 'HIGH',
        'check': lambda v: v.lower().strip() == 'nosniff',
        'recommendation': "Set to 'nosniff'"
    },
    'Referrer-Policy': {
        'desc': 'Controls referrer info leakage',
        'severity': 'MEDIUM',
        'check': lambda v: v.lower().strip() in [
            'no-referrer', 'strict-origin', 'strict-origin-when-cross-origin', 'same-origin'
        ],
        'recommendation': "Use 'strict-origin-when-cross-origin' or stricter"
    },
    'Permissions-Policy': {
        'desc': 'Controls browser APIs (camera, mic, geolocation)',
        'severity': 'MEDIUM',
        'check': lambda v: len(v.strip()) > 3,
        'recommendation': "Restrict unused APIs: camera=(), microphone=(), geolocation=()"
    },
    'Cross-Origin-Embedder-Policy': {
        'desc': 'Prevents cross-origin resource loading (COEP) — 2024 standard',
        'severity': 'MEDIUM',
        'check': lambda v: v.lower().strip() in ['require-corp', 'credentialless'],
        'recommendation': "Set to 'require-corp'"
    },
    'Cross-Origin-Opener-Policy': {
        'desc': 'Isolates browsing context (COOP) — 2024 standard',
        'severity': 'MEDIUM',
        'check': lambda v: v.lower().strip() in ['same-origin', 'same-origin-allow-popups'],
        'recommendation': "Set to 'same-origin'"
    },
    'Cross-Origin-Resource-Policy': {
        'desc': 'Protects resources from cross-origin reads (CORP)',
        'severity': 'MEDIUM',
        'check': lambda v: v.lower().strip() in ['same-origin', 'same-site'],
        'recommendation': "Set to 'same-origin' or 'same-site'"
    },
    'Cache-Control': {
        'desc': 'Prevents sensitive data caching',
        'severity': 'LOW',
        'check': lambda v: 'no-store' in v.lower() or 'private' in v.lower(),
        'recommendation': "Use 'no-store' for sensitive pages, 'private' for user data"
    },
    'X-XSS-Protection': {
        'desc': 'Legacy XSS filter (deprecated in modern browsers)',
        'severity': 'LOW',
        'check': lambda v: v.startswith('0') or v.startswith('1; mode=block'),
        'recommendation': "Set to '0' (disabled, rely on CSP instead) or '1; mode=block'"
    },
}

SEVERITY_SCORE  = {'CRITICAL': 15, 'HIGH': 10, 'MEDIUM': 5, 'LOW': 2}
SEVERITY_COLOR  = {
    'CRITICAL': Fore.RED,
    'HIGH':     Fore.YELLOW,
    'MEDIUM':   Fore.MAGENTA,
    'LOW':      Fore.BLUE,
}

# Dangerous CSP directives
CSP_DANGEROUS = [
    ("'unsafe-inline'",   "Allows inline scripts — XSS risk"),
    ("'unsafe-eval'",     "Allows eval() — XSS risk"),
    ("'unsafe-hashes'",   "Weakens CSP hash-based protection"),
    ("data:",             "Allows data: URIs — potential XSS vector"),
    ("*",                 "Wildcard source — too permissive"),
    ("http:",             "Allows HTTP sources — downgrade risk"),
]

# ─────────────────────────────────────────────
#  UTILS
# ─────────────────────────────────────────────

def normalize_url(url: str) -> str:
    if not url.startswith('http://') and not url.startswith('https://'):
        url = 'https://' + url
    return url

def get_domain(url: str) -> str:
    return urlparse(url).netloc.split(':')[0]

def get_header(headers: dict, name: str) -> str | None:
    return next((v for k, v in headers.items() if k.lower() == name.lower()), None)

# ─────────────────────────────────────────────
#  REDIRECT CHAIN
# ─────────────────────────────────────────────

def get_redirect_chain(url: str, timeout: int) -> list:
    chain = []
    try:
        resp = requests.get(url, allow_redirects=True, timeout=timeout,
                            headers={'User-Agent': 'ShieldProbe/2.0'}, verify=True)
        for r in resp.history:
            chain.append({'url': r.url, 'status': r.status_code})
        chain.append({'url': resp.url, 'status': resp.status_code})
    except Exception:
        pass
    return chain

# ─────────────────────────────────────────────
#  SSL / TLS AUDIT — 2025 STANDARDS
# ─────────────────────────────────────────────

def audit_ssl(domain: str) -> dict:
    result = {
        'valid': False, 'expiry': None, 'days_left': None,
        'issuer': None, 'protocol': None, 'self_signed': False,
        'expired': False, 'issues': [], 'good': []
    }
    try:
        ctx = ssl.create_default_context()
        with ctx.wrap_socket(socket.create_connection((domain, 443), timeout=10),
                             server_hostname=domain) as s:
            cert  = s.getpeercert()
            proto = s.version()
            result['protocol'] = proto

            # Protocol check — TLS 1.3 recommended in 2025
            if proto == 'TLSv1.3':
                result['good'].append('TLS 1.3 in use (best practice 2025)')
            elif proto == 'TLSv1.2':
                result['issues'].append('TLS 1.2 — acceptable but TLS 1.3 preferred')
            elif proto in ['TLSv1', 'TLSv1.1', 'SSLv2', 'SSLv3']:
                result['issues'].append(f'Deprecated protocol: {proto} — upgrade immediately')

            # Expiry
            expiry_str = cert.get('notAfter', '')
            if expiry_str:
                expiry    = datetime.datetime.strptime(expiry_str, '%b %d %H:%M:%S %Y %Z')
                days_left = (expiry - datetime.datetime.now(datetime.timezone.utc).replace(tzinfo=None)).days
                result['expiry']    = expiry.strftime('%Y-%m-%d')
                result['days_left'] = days_left
                if days_left < 0:
                    result['expired'] = True
                    result['issues'].append('Certificate is EXPIRED')
                elif days_left < 14:
                    result['issues'].append(f'Certificate expiring in {days_left} days — renew NOW')
                elif days_left < 30:
                    result['issues'].append(f'Certificate expiring in {days_left} days — renew soon')
                else:
                    result['good'].append(f'Certificate valid for {days_left} days')

            # Issuer
            issuer  = dict(x[0] for x in cert.get('issuer', []))
            subject = dict(x[0] for x in cert.get('subject', []))
            result['issuer'] = issuer.get('organizationName', 'Unknown')

            # Self-signed
            if issuer == subject:
                result['self_signed'] = True
                result['issues'].append('Self-signed certificate — not trusted by browsers')

            # SANs (Subject Alternative Names)
            sans = [v for t, v in cert.get('subjectAltName', []) if t == 'DNS']
            result['sans'] = sans

            result['valid'] = True

    except ssl.SSLCertVerificationError as e:
        result['issues'].append(f'SSL verification failed: {e}')
    except ssl.SSLError as e:
        result['issues'].append(f'SSL error: {e}')
    except ConnectionRefusedError:
        result['issues'].append('Port 443 refused — HTTPS not available')
    except Exception as e:
        result['issues'].append(f'SSL check error: {e}')
    return result

# ─────────────────────────────────────────────
#  CSP DEEP ANALYSIS
# ─────────────────────────────────────────────

def analyze_csp(csp_value: str) -> list:
    issues = []
    if not csp_value:
        return issues
    for directive, reason in CSP_DANGEROUS:
        if directive in csp_value:
            issues.append(f"CSP contains {directive} — {reason}")
    if 'frame-ancestors' not in csp_value:
        issues.append("CSP missing 'frame-ancestors' — use instead of X-Frame-Options")
    if 'default-src' not in csp_value and 'script-src' not in csp_value:
        issues.append("CSP missing 'default-src' or 'script-src' directive")
    if 'upgrade-insecure-requests' not in csp_value:
        issues.append("CSP missing 'upgrade-insecure-requests'")
    return issues

# ─────────────────────────────────────────────
#  HEADER ANALYSIS
# ─────────────────────────────────────────────

def analyze_headers(headers: dict) -> tuple:
    results   = []
    csp_issues = []

    for header_name, meta in SECURITY_HEADERS.items():
        value = get_header(headers, header_name)
        if value is None:
            results.append({
                'header': header_name,
                'status': 'MISSING',
                'severity': meta['severity'],
                'desc': meta['desc'],
                'value': None,
                'recommendation': meta.get('recommendation', f'Add {header_name}')
            })
        else:
            try:
                ok = meta['check'](value)
            except Exception:
                ok = False
            results.append({
                'header': header_name,
                'status': 'GOOD' if ok else 'WEAK',
                'severity': meta['severity'] if not ok else 'OK',
                'desc': meta['desc'],
                'value': value[:80] + ('…' if len(value) > 80 else ''),
                'recommendation': None if ok else meta.get('recommendation')
            })
            # Deep CSP analysis
            if header_name == 'Content-Security-Policy':
                csp_issues = analyze_csp(value)

    return results, csp_issues

# ─────────────────────────────────────────────
#  COOKIE AUDIT — 2025 STANDARDS
# ─────────────────────────────────────────────

def audit_cookies(response) -> list:
    results = []
    for cookie in response.cookies:
        issues = []
        good   = []

        if not cookie.secure:
            issues.append('Missing Secure flag — cookie sent over HTTP')
        else:
            good.append('Secure flag set')

        if not cookie.has_nonstandard_attr('HttpOnly'):
            issues.append('Missing HttpOnly — accessible via JS (XSS risk)')
        else:
            good.append('HttpOnly flag set')

        samesite = cookie.get_nonstandard_attr('SameSite')
        if not samesite:
            issues.append('Missing SameSite — CSRF risk')
        elif samesite.lower() == 'none' and not cookie.secure:
            issues.append('SameSite=None without Secure flag — invalid in modern browsers')
        elif samesite.lower() == 'none':
            issues.append('SameSite=None — allows cross-site requests')
        elif samesite.lower() in ['strict', 'lax']:
            good.append(f'SameSite={samesite}')

        # __Host- and __Secure- prefix check (2025 best practice)
        if cookie.name.startswith('__Host-'):
            if not cookie.secure or cookie.path != '/' or cookie.domain:
                issues.append('__Host- prefix violated: requires Secure, path=/, no Domain')
            else:
                good.append('__Host- prefix correctly set')
        elif cookie.name.startswith('__Secure-'):
            if not cookie.secure:
                issues.append('__Secure- prefix violated: requires Secure flag')
            else:
                good.append('__Secure- prefix correctly set')

        results.append({
            'name':     cookie.name,
            'secure':   cookie.secure,
            'httponly': cookie.has_nonstandard_attr('HttpOnly'),
            'samesite': samesite,
            'issues':   issues,
            'good':     good,
        })
    return results

# ─────────────────────────────────────────────
#  CORS CHECK — 2025
# ─────────────────────────────────────────────

def check_cors(url: str, timeout: int) -> dict:
    result = {'vulnerable': False, 'value': None, 'issues': [], 'good': []}
    try:
        # Test 1: wildcard
        resp = requests.get(url, timeout=timeout, headers={
            'Origin': 'https://evil.com',
            'User-Agent': 'ShieldProbe/2.0'
        }, verify=True)
        acao  = resp.headers.get('Access-Control-Allow-Origin', '')
        acac  = resp.headers.get('Access-Control-Allow-Credentials', '')
        result['value'] = acao

        if acao == '*':
            result['vulnerable'] = True
            result['issues'].append('Wildcard CORS (*) — allows any origin')
        elif acao.lower() == 'https://evil.com':
            result['vulnerable'] = True
            result['issues'].append('Reflects arbitrary Origin — CORS misconfiguration')

        # Dangerous combo: ACAO reflects + ACAC: true
        if acac.lower() == 'true' and acao != '':
            result['vulnerable'] = True
            result['issues'].append('Access-Control-Allow-Credentials: true with non-null ACAO — credential leak risk')

        # Test 2: null origin
        resp2 = requests.get(url, timeout=timeout, headers={
            'Origin': 'null',
            'User-Agent': 'ShieldProbe/2.0'
        }, verify=True)
        acao2 = resp2.headers.get('Access-Control-Allow-Origin', '')
        if acao2 == 'null':
            result['vulnerable'] = True
            result['issues'].append("Reflects 'null' Origin — exploitable via sandboxed iframe")

        if not result['issues']:
            result['good'].append('CORS policy appears correctly configured')

    except Exception as e:
        result['issues'].append(f'CORS check error: {e}')
    return result

# ─────────────────────────────────────────────
#  FINGERPRINTING — 2025
# ─────────────────────────────────────────────

def fingerprint(headers: dict) -> list:
    findings = []
    expose_headers = {
        'Server':            'Web server & version exposed',
        'X-Powered-By':      'Backend technology exposed',
        'X-AspNet-Version':  'ASP.NET version exposed',
        'X-AspNetMvc-Version': 'ASP.NET MVC version exposed',
        'X-Generator':       'CMS/framework exposed',
        'X-Drupal-Cache':    'Drupal CMS detected',
        'X-Joomla-Cache':    'Joomla CMS detected',
        'Via':               'Proxy/CDN info exposed',
        'X-Runtime':         'Server runtime exposed (Rails?)',
        'X-Rack-Cache':      'Rack cache info exposed',
    }
    for h, msg in expose_headers.items():
        value = get_header(headers, h)
        if value:
            findings.append({'header': h, 'value': value, 'note': msg})

    # Check if server version is exposed in Server header
    server = get_header(headers, 'Server')
    if server and any(c.isdigit() for c in server):
        findings.append({'header': 'Server (version leak)', 'value': server,
                         'note': 'Exact version number in Server header — allows targeted CVE lookup'})

    return findings

# ─────────────────────────────────────────────
#  DNS / HTTP CHECK
# ─────────────────────────────────────────────

def check_http_to_https(domain: str, timeout: int) -> dict:
    result = {'redirects': False, 'issue': None}
    try:
        resp = requests.get(f'http://{domain}', timeout=timeout, allow_redirects=False,
                            headers={'User-Agent': 'ShieldProbe/2.0'})
        if resp.status_code in [301, 302, 307, 308]:
            loc = resp.headers.get('Location', '')
            if loc.startswith('https://'):
                result['redirects'] = True
            else:
                result['issue'] = f'HTTP redirects but not to HTTPS: {loc}'
        else:
            result['issue'] = f'HTTP does not redirect to HTTPS (status {resp.status_code})'
    except Exception as e:
        result['issue'] = f'Could not connect via HTTP: {e}'
    return result

# ─────────────────────────────────────────────
#  SCORING — 2025 WEIGHTED
# ─────────────────────────────────────────────

def calculate_score(header_results: list, ssl_result: dict, cors: dict, csp_issues: list) -> int:
    score = 100

    # Headers — max penalty 60 points total
    header_penalty = 0
    for h in header_results:
        if h['status'] == 'MISSING':
            header_penalty += SEVERITY_SCORE.get(h['severity'], 0)
        elif h['status'] == 'WEAK':
            header_penalty += SEVERITY_SCORE.get(h['severity'], 0) // 2
    score -= min(header_penalty, 60)

    # SSL — max penalty 20 points
    ssl_penalty = len(ssl_result.get('issues', [])) * 5
    score -= min(ssl_penalty, 20)

    # CORS — max penalty 15 points
    if cors.get('vulnerable'):
        score -= min(len(cors.get('issues', [])) * 5, 15)

    # CSP deep issues — max penalty 10 points
    score -= min(len(csp_issues) * 2, 10)

    return max(0, min(100, score))

def score_label(score: int) -> tuple:
    if score >= 85:
        return 'A — LOW RISK',      Fore.GREEN
    elif score >= 70:
        return 'B — MEDIUM RISK',   Fore.YELLOW
    elif score >= 50:
        return 'C — HIGH RISK',     Fore.RED
    else:
        return 'F — CRITICAL RISK', Fore.RED + Style.BRIGHT

# ─────────────────────────────────────────────
#  PRINT RESULTS
# ─────────────────────────────────────────────

def section(title: str):
    print(Fore.CYAN + f"\n  ┌─ {title} " + "─" * max(1, 58 - len(title)))

def print_ssl(ssl_result: dict):
    section("SSL / TLS AUDIT")
    proto = ssl_result.get('protocol', 'N/A')
    proto_color = Fore.GREEN if proto == 'TLSv1.3' else Fore.YELLOW if proto == 'TLSv1.2' else Fore.RED
    print(Fore.WHITE + f"  │  Protocol  : " + proto_color + f"{proto}")
    print(Fore.WHITE + f"  │  Issuer    : {ssl_result.get('issuer','N/A')}")
    print(Fore.WHITE + f"  │  Expiry    : {ssl_result.get('expiry','N/A')} ({ssl_result.get('days_left','?')} days left)")
    if ssl_result.get('sans'):
        sans_str = ', '.join(ssl_result['sans'][:5])
        print(Fore.WHITE + f"  │  SANs      : {sans_str}")
    if ssl_result.get('self_signed'):
        print(Fore.RED + "  │  [!] Self-signed certificate")
    for good in ssl_result.get('good', []):
        print(Fore.GREEN + f"  │  [✓] {good}")
    for issue in ssl_result.get('issues', []):
        print(Fore.YELLOW + f"  │  [!] {issue}")

def print_http_redirect(result: dict):
    section("HTTP → HTTPS REDIRECT")
    if result['redirects']:
        print(Fore.GREEN + "  │  [✓] HTTP correctly redirects to HTTPS")
    else:
        print(Fore.RED + f"  │  [✗] {result.get('issue','Unknown')}")

def print_redirects(chain: list):
    section("REDIRECT CHAIN")
    for i, r in enumerate(chain):
        arrow = "  │  └─▶" if i == len(chain) - 1 else "  │  ├─▶"
        color = Fore.GREEN if r['status'] == 200 else Fore.YELLOW
        print(color + f"{arrow} [{r['status']}] {r['url']}")

def print_headers(header_results: list):
    section("SECURITY HEADERS")
    for h in header_results:
        if h['status'] == 'GOOD':
            print(Fore.GREEN  + f"  │  [✓] {h['header']:<40} GOOD")
        elif h['status'] == 'WEAK':
            print(Fore.YELLOW + f"  │  [~] {h['header']:<40} WEAK")
            if h.get('recommendation'):
                print(Fore.WHITE + Style.DIM + f"  │       → {h['recommendation']}")
        else:
            color = SEVERITY_COLOR.get(h['severity'], Fore.WHITE)
            print(color + f"  │  [✗] {h['header']:<40} MISSING [{h['severity']}]")
            if h.get('recommendation'):
                print(Fore.WHITE + Style.DIM + f"  │       → {h['recommendation']}")

def print_csp(csp_issues: list):
    if not csp_issues:
        return
    section("CSP DEEP ANALYSIS")
    for issue in csp_issues:
        print(Fore.YELLOW + f"  │  [!] {issue}")

def print_cookies(cookie_results: list):
    section("COOKIE AUDIT")
    if not cookie_results:
        print(Fore.WHITE + "  │  No cookies found")
        return
    for c in cookie_results:
        status = Fore.GREEN + "[✓]" if not c['issues'] else Fore.RED + "[✗]"
        print(Fore.WHITE + f"  │  {status} {Fore.WHITE}{c['name']}")
        for g in c.get('good', []):
            print(Fore.GREEN + Style.DIM + f"  │       ✓ {g}")
        for issue in c['issues']:
            print(Fore.YELLOW + f"  │       → {issue}")

def print_cors(cors: dict):
    section("CORS CHECK")
    if cors.get('vulnerable'):
        for issue in cors['issues']:
            print(Fore.RED + f"  │  [✗] {issue}")
    elif cors.get('good'):
        for g in cors['good']:
            print(Fore.GREEN + f"  │  [✓] {g}")
    if cors.get('value'):
        print(Fore.WHITE + Style.DIM + f"  │      ACAO: {cors['value']}")

def print_fingerprint(fp: list):
    section("FINGERPRINTING")
    if not fp:
        print(Fore.GREEN + "  │  [✓] No sensitive server info exposed")
        return
    seen = set()
    for f in fp:
        key = f['header']
        if key not in seen:
            seen.add(key)
            print(Fore.YELLOW + f"  │  [!] {f['header']}: {f['value']}")
            print(Fore.WHITE + Style.DIM + f"  │       → {f['note']}")

def print_score(score: int):
    label, color = score_label(score)
    bar_filled = int(score / 5)
    bar = '█' * bar_filled + '░' * (20 - bar_filled)
    print()
    print(Fore.CYAN + "  " + "─" * 65)
    print(color + f"  SCORE  : {score:>3}/100  [{bar}]  {label}")
    print(Fore.CYAN + "  " + "─" * 65)
    print()

# ─────────────────────────────────────────────
#  EXPORT
# ─────────────────────────────────────────────

def export_json(data: dict, path: str):
    with open(path, 'w') as f:
        json.dump(data, f, indent=2, default=str)
    print(Fore.GREEN + f"  [✓] JSON exported: {path}")

def export_html(data: dict, path: str):
    score       = data['score']
    label, _    = score_label(score)
    score_color = '#2ecc71' if score >= 85 else '#f39c12' if score >= 70 else '#e74c3c'

    rows = ''
    for h in data['headers']:
        if h['status'] == 'GOOD':
            badge = '<span style="color:#2ecc71">✓ GOOD</span>'
        elif h['status'] == 'WEAK':
            badge = '<span style="color:#f39c12">~ WEAK</span>'
        else:
            badge = f'<span style="color:#e74c3c">✗ MISSING [{h["severity"]}]</span>'
        rec = h.get('recommendation') or '—'
        val = h.get('value') or '—'
        rows += f"<tr><td>{h['header']}</td><td>{badge}</td><td style='font-size:.8em;word-break:break-all'>{val}</td><td style='font-size:.8em'>{rec}</td></tr>"

    ssl  = data.get('ssl', {})
    cors = data.get('cors', {})
    csp  = data.get('csp_issues', [])

    html = f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>ShieldProbe Report — {data['target']}</title>
  <style>
    *{{box-sizing:border-box;margin:0;padding:0}}
    body{{font-family:monospace;background:#0d0d0d;color:#ccc;padding:2rem;line-height:1.6}}
    h1{{color:#00bcd4;margin-bottom:.5rem}}
    h2{{color:#00bcd4;border-bottom:1px solid #222;padding:.4rem 0;margin:1.5rem 0 .8rem}}
    table{{width:100%;border-collapse:collapse;margin-bottom:1.5rem}}
    th{{background:#111;color:#00bcd4;padding:.5rem;text-align:left;font-size:.85em}}
    td{{padding:.45rem .5rem;border-bottom:1px solid #1a1a1a;vertical-align:top}}
    .score{{font-size:1.8rem;color:{score_color};margin:.5rem 0}}
    .meta{{color:#555;font-size:.8rem;margin-bottom:1rem}}
    .good{{color:#2ecc71}}.warn{{color:#f39c12}}.bad{{color:#e74c3c}}
    .issue{{background:#1a0000;border-left:3px solid #e74c3c;padding:.4rem .7rem;margin:.3rem 0;font-size:.85em}}
    .ok{{background:#001a00;border-left:3px solid #2ecc71;padding:.4rem .7rem;margin:.3rem 0;font-size:.85em}}
    .badge{{display:inline-block;padding:.1rem .4rem;border-radius:3px;font-size:.75em}}
  </style>
</head>
<body>
  <h1>🛡 ShieldProbe Report</h1>
  <p class="meta">Target: {data['target']} | Scanned: {data['timestamp']} | Version: {VERSION}</p>
  <div class="score">{score}/100 — {label}</div>

  <h2>Security Headers</h2>
  <table>
    <tr><th>Header</th><th>Status</th><th>Value</th><th>Recommendation</th></tr>
    {rows}
  </table>

  <h2>SSL / TLS</h2>
  <p>Protocol: <strong>{ssl.get('protocol','N/A')}</strong> | Expiry: {ssl.get('expiry','N/A')} ({ssl.get('days_left','?')} days) | Issuer: {ssl.get('issuer','N/A')}</p>
  {''.join(f'<div class="issue">⚠ {i}</div>' for i in ssl.get('issues',[]))}
  {''.join(f'<div class="ok">✓ {g}</div>' for g in ssl.get('good',[]))}

  <h2>CSP Analysis</h2>
  {''.join(f'<div class="issue">⚠ {i}</div>' for i in csp) if csp else '<div class="ok">✓ No critical CSP issues</div>'}

  <h2>CORS</h2>
  {''.join(f'<div class="issue">⚠ {i}</div>' for i in cors.get('issues',[])) if cors.get('vulnerable') else '<div class="ok">✓ CORS appears correctly configured</div>'}

  <h2>Fingerprinting</h2>
  {''.join(f'<div class="issue">⚠ {f["header"]}: {f["value"]} — {f["note"]}</div>' for f in data.get('fingerprint',[])) or '<div class="ok">✓ No sensitive server info exposed</div>'}

  <h2>Cookies</h2>
  {''.join(f'''<div style="margin:.5rem 0"><strong>{c['name']}</strong>: {''.join(f'<div class="issue">⚠ {i}</div>' for i in c['issues']) or '<span class="good">✓ OK</span>'}</div>''' for c in data.get('cookies',[])) or 'No cookies found'}
</body>
</html>"""

    with open(path, 'w') as f:
        f.write(html)
    print(Fore.GREEN + f"  [✓] HTML exported: {path}")

# ─────────────────────────────────────────────
#  MAIN
# ─────────────────────────────────────────────

def main():
    print_banner()

    parser = argparse.ArgumentParser(
        description='ShieldProbe - HTTP Security Header Analyzer',
        formatter_class=argparse.RawTextHelpFormatter
    )
    parser.add_argument('--url',     required=True, help='Target URL or domain')
    parser.add_argument('--timeout', type=int, default=10, help='Timeout in seconds (default: 10)')
    parser.add_argument('--output',  choices=['json', 'html'], help='Export report (json or html)')
    parser.add_argument('--no-ssl',  action='store_true', help='Skip SSL/TLS audit')
    args = parser.parse_args()

    url    = normalize_url(args.url)
    domain = get_domain(url)

    print(Fore.CYAN + f"  [*] Target  : {url}")
    print(Fore.CYAN + f"  [*] Domain  : {domain}")
    print(Fore.CYAN + f"  [*] Timeout : {args.timeout}s")
    print()

    # Fetch
    try:
        print(Fore.CYAN + "  [*] Fetching target...")
        response = requests.get(url, timeout=args.timeout, allow_redirects=True,
                                headers={'User-Agent': 'ShieldProbe/2.0'}, verify=True)
        headers  = dict(response.headers)
        print(Fore.GREEN + f"  [✓] Response : {response.status_code} {response.reason}")
        print(Fore.CYAN  + f"  [*] Running checks...")
    except requests.exceptions.SSLError as e:
        print(Fore.RED + f"  [!] SSL Error: {e}")
        sys.exit(1)
    except requests.exceptions.ConnectionError:
        print(Fore.RED + f"  [!] Cannot connect to {url}")
        sys.exit(1)
    except requests.exceptions.Timeout:
        print(Fore.RED + "  [!] Connection timed out")
        sys.exit(1)
    except Exception as e:
        print(Fore.RED + f"  [!] Error: {e}")
        sys.exit(1)

    # Run all checks
    redirect_chain = get_redirect_chain(url, args.timeout)
    ssl_result     = audit_ssl(domain) if not args.no_ssl else {'valid': False, 'issues': ['SSL audit skipped'], 'good': []}
    header_results, csp_issues = analyze_headers(headers)
    cookie_results = audit_cookies(response)
    cors_result    = check_cors(url, args.timeout)
    fp_result      = fingerprint(headers)
    http_redirect  = check_http_to_https(domain, args.timeout)
    score          = calculate_score(header_results, ssl_result, cors_result, csp_issues)

    # Print
    print_redirects(redirect_chain)
    print_http_redirect(http_redirect)
    print_ssl(ssl_result)
    print_headers(header_results)
    print_csp(csp_issues)
    print_cookies(cookie_results)
    print_cors(cors_result)
    print_fingerprint(fp_result)
    print_score(score)

    # Export
    if args.output:
        timestamp   = datetime.datetime.now().strftime('%Y%m%d_%H%M%S')
        export_data = {
            'target':      url,
            'timestamp':   datetime.datetime.now().isoformat(),
            'score':       score,
            'ssl':         ssl_result,
            'headers':     header_results,
            'csp_issues':  csp_issues,
            'cookies':     cookie_results,
            'cors':        cors_result,
            'fingerprint': fp_result,
            'redirects':   redirect_chain,
        }
        outfile = f"shieldprobe_{timestamp}.{args.output}"
        if args.output == 'json':
            export_json(export_data, outfile)
        elif args.output == 'html':
            export_html(export_data, outfile)

if __name__ == '__main__':
    main()
