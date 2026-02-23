"""
Session Domain Learner
----------------------
Passively watches all browser HTTPS (TCP:443) connections and records
the domains they touch. After a week of normal browsing, run:

    ./sovereign sessions

to see a ranked list of candidates to add to PROTECTED_SESSION_DOMAINS.

Data is saved to data/session_domains_learned.json — no external calls.
"""

import os
import json
import socket
import subprocess
import logging
from datetime import datetime

import path_utils

# ── Noise filter ──────────────────────────────────────────────────────────────
# Domains that are CDNs, analytics, or ad infrastructure — not session-bearing.
NOISE_DOMAINS = {
    # Analytics / tracking
    'google-analytics.com', 'googletagmanager.com', 'doubleclick.net',
    'googlesyndication.com', 'hotjar.com', 'segment.com', 'amplitude.com',
    'mixpanel.com', 'heap.io', 'fullstory.com', 'mouseflow.com',
    # Error monitoring
    'sentry.io', 'datadoghq.com', 'newrelic.com', 'nr-data.net', 'bugsnag.com',
    # CDNs / asset hosts
    'cloudflare.com', 'cloudflareinsights.com', 'fastly.com', 'akamai.com',
    'akamaiedge.net', 'akamaized.net', 'edgekey.net', 'edgesuite.net',
    'cloudfront.net', 'amazonaws.com', 'azureedge.net',
    'jsdelivr.net', 'unpkg.com', 'cdnjs.cloudflare.com',
    # Google infrastructure
    'gstatic.com', 'googleapis.com', 'google.com', 'ggpht.com',
    # Apple
    'apple.com', 'icloud.com', 'mzstatic.com',
    # Generic telemetry
    'telemetry.mozilla.org', 'firefox.com',
}

BROWSER_NAMES = ['chrome', 'brave', 'edge', 'arc', 'safari', 'firefox', 'opera', 'vivaldi']

# ── IP resolution cache (in-memory, resets per daemon run) ────────────────────
_ip_cache: dict = {}

_learned_path: str | None = None


def _get_learned_path() -> str:
    global _learned_path
    if _learned_path is None:
        _learned_path = path_utils.get_config_file('session_domains_learned.json')
    return _learned_path


def _load() -> dict:
    p = _get_learned_path()
    if os.path.exists(p):
        try:
            with open(p, 'r') as f:
                return json.load(f)
        except Exception:
            pass
    return {}


def _save(data: dict) -> None:
    try:
        with open(_get_learned_path(), 'w') as f:
            json.dump(data, f, indent=2, sort_keys=True)
    except Exception as e:
        logging.error(f"Session learner save failed: {e}")


def _resolve(ip: str) -> str | None:
    if ip in _ip_cache:
        return _ip_cache[ip]
    try:
        hostname = socket.gethostbyaddr(ip)[0]
        _ip_cache[ip] = hostname
        return hostname
    except (socket.herror, socket.gaierror, OSError):
        _ip_cache[ip] = None
        return None


def _root_domain(hostname: str) -> str | None:
    """'cdn.api.linkedin.com' → 'linkedin.com'"""
    if not hostname:
        return None
    parts = hostname.rstrip('.').split('.')
    return '.'.join(parts[-2:]) if len(parts) >= 2 else hostname


def _is_noise(domain: str) -> bool:
    return not domain or any(noise in domain for noise in NOISE_DOMAINS)


# ── Main learning function ────────────────────────────────────────────────────

def scan_browser_session_domains() -> None:
    """
    Called every 30s from guard_monitor. Checks all browser HTTPS connections,
    resolves remote IPs to hostnames, and records non-noise domains.
    Silent on any error — never interrupts the guard loop.
    """
    try:
        result = subprocess.run(
            ['lsof', '-iTCP:443', '-sTCP:ESTABLISHED', '-n', '-P'],
            capture_output=True, text=True, timeout=5
        )
        if result.returncode != 0 or not result.stdout.strip():
            return

        learned = _load()
        changed = False

        for line in result.stdout.strip().splitlines():
            if 'COMMAND' in line:
                continue
            parts = line.split()
            if len(parts) < 9:
                continue
            proc_name = parts[0]
            name_field = parts[8]

            # Only learn from browser connections
            if not any(b in proc_name.lower() for b in BROWSER_NAMES):
                continue

            if '->' not in name_field:
                continue

            remote_ip = name_field.split('->')[1].rsplit(':', 1)[0]
            hostname = _resolve(remote_ip)
            root = _root_domain(hostname)

            if _is_noise(root):
                continue

            now = datetime.now().isoformat()

            if root not in learned:
                learned[root] = {
                    'count': 0,
                    'first_seen': now,
                    'last_seen': now,
                    'example_hostname': hostname,
                }
                changed = True

            learned[root]['count'] += 1
            learned[root]['last_seen'] = now
            if hostname and hostname != learned[root].get('example_hostname'):
                learned[root]['example_hostname'] = hostname
            changed = True

        if changed:
            _save(learned)

    except Exception as e:
        logging.debug(f"Session domain learner error: {e}")


# ── Review / reporting ────────────────────────────────────────────────────────

def get_top_domains(min_count: int = 3, top_n: int = 50) -> list[tuple[str, dict]]:
    """Returns domains ranked by connection count, filtered by minimum hits."""
    learned = _load()
    candidates = [
        (domain, meta)
        for domain, meta in learned.items()
        if meta.get('count', 0) >= min_count
    ]
    return sorted(candidates, key=lambda x: x[1]['count'], reverse=True)[:top_n]


def print_session_review() -> None:
    """Prints a human-readable candidate list for PROTECTED_SESSION_DOMAINS."""
    from sovereign_engine import patterns as p

    already_protected = set(p.PROTECTED_SESSION_DOMAINS)
    candidates = get_top_domains()

    if not candidates:
        print("  [i] No session domains recorded yet. Let the guard run for a few days.")
        return

    print(f"\n{'─'*60}")
    print(f"  SESSION DOMAIN CANDIDATES  ({len(candidates)} found)")
    print(f"{'─'*60}")
    print(f"  {'DOMAIN':<35} {'HITS':>6}  STATUS")
    print(f"  {'─'*35}  {'─'*6}  {'─'*12}")

    new_count = 0
    for domain, meta in candidates:
        status = '✅ protected' if domain in already_protected else '⬜ candidate'
        if domain not in already_protected:
            new_count += 1
        print(f"  {domain:<35} {meta['count']:>6}  {status}")

    print(f"{'─'*60}")
    print(f"  {new_count} new candidates not yet in PROTECTED_SESSION_DOMAINS")
    print(f"  To protect a domain: add it to patterns.py → PROTECTED_SESSION_DOMAINS")
    print(f"  Data file: {_get_learned_path()}\n")
