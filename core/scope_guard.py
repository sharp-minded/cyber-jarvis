"""
core/scope_guard.py - ROBUST scope validator

FIX: Substring bypass closed.
  example.com in example.com.evil.net  →  REJECTED

Supports:
- Exact match
- Proper subdomain (www.example.com matches example.com)
- CIDR (192.168.1.0/24)
- Wildcard (*.example.com)
- Auto-allow: localhost, 127.0.0.1, private IPs, *.local/.lan/.test
"""

import ipaddress
from pathlib import Path
from typing import Tuple

from core.config import CONFIG


def validate_scope(target: str) -> Tuple[bool, str]:
    """
    Check if target is in scope.txt.
    Returns (allowed: bool, reason: str).
    """
    if not target or not target.strip():
        return False, "empty target"

    target = target.strip()
    host = target.split(":")[0].split("/")[0].lower()

    # ─── Auto-allow localhost & private ────────────────────
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_private or ip.is_loopback:
            return True, "private/local IP"
    except ValueError:
        if host == "localhost" or host.endswith((".local", ".lan", ".test", ".lab", ".htb")):
            return True, "local hostname"

    # ─── Read scope.txt ────────────────────────────────────
    scope_file = CONFIG["workspace"] / CONFIG["scope_file"]

    if not scope_file.exists():
        return False, "scope.txt not found — DENY public targets by default"

    entries = []
    for line in scope_file.read_text().splitlines():
        line = line.strip()
        if line and not line.startswith("#"):
            entries.append(line.lower())

    target_lower = target.lower()

    # ─── Match against each entry ──────────────────────────
    for entry in entries:

        # Exact match (host only or full)
        if target_lower == entry or host == entry:
            return True, f"exact match: {entry}"

        # CIDR block match
        if "/" in entry:
            try:
                net = ipaddress.ip_network(entry, strict=False)
                t_ip = ipaddress.ip_address(host)
                if t_ip in net:
                    return True, f"CIDR match: {entry}"
            except ValueError:
                pass

        # Wildcard: *.example.com
        if entry.startswith("*."):
            base = entry[2:]
            # base itself OR proper subdomain only
            if host == base or host.endswith("." + base):
                return True, f"wildcard match: {entry}"
            continue

        # Proper subdomain ONLY — CLOSES SUBSTRING BYPASS
        # www.example.com matches example.com
        # example.com.evil.net does NOT match example.com  ← KEY FIX
        if host.endswith("." + entry):
            return True, f"subdomain of {entry}"

    return False, f"target '{target}' not in scope.txt"


def require_scope(target: str, silent: bool = False) -> bool:
    """Validate + print message. Return True if allowed."""
    allowed, reason = validate_scope(target)
    if not allowed and not silent:
        from rich.console import Console
        Console().print(f"[red][!] SCOPE DENIED: {target} — {reason}[/red]")
    return allowed


# ═══════════════════════════════════════════════════════════════
#  SELF-TEST
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    # Setup temp scope for tests
    test_scope = CONFIG["workspace"] / "scope.txt"
    original = test_scope.read_text() if test_scope.exists() else None
    test_scope.write_text(
        "example.com\n"
        "192.168.1.0/24\n"
        "*.test.lab\n"
        "mycompany.io\n"
    )

    tests = [
        # (target, should_be_allowed)
        ("example.com", True),
        ("www.example.com", True),
        ("api.example.com", True),
        ("example.com.evil.net", False),     # ← BYPASS PREVENTED
        ("evilexample.com", False),
        ("notexample.com", False),
        ("example.company.com", False),
        ("192.168.1.5", True),
        ("192.168.1.255", True),
        ("192.168.2.5", False),
        ("foo.test.lab", True),
        ("bar.test.lab", True),
        ("test.lab", True),
        ("evil.com", False),
        ("localhost", True),
        ("127.0.0.1", True),
        ("10.0.0.5", True),
        ("192.168.100.50", True),
        ("", False),
        ("google.com", False),
        ("mycompany.io", True),
        ("www.mycompany.io", True),
        ("mycompany.io.attacker.com", False),  # ← BYPASS PREVENTED
    ]

    passed = 0
    failed = []
    print("=" * 70)
    print("SCOPE GUARD — SELF TEST")
    print("=" * 70)

    for tgt, expected in tests:
        allowed, reason = validate_scope(tgt)
        ok = allowed == expected
        if ok:
            passed += 1
            print(f"  ✓ {tgt:35} → {str(allowed):5} ({reason})")
        else:
            failed.append((tgt, expected, allowed, reason))
            print(f"  ✗ {tgt:35} → {str(allowed):5} EXPECTED {expected} ({reason})")

    print("-" * 70)
    print(f"RESULT: {passed}/{len(tests)} tests passed")

    if failed:
        print(f"\nFAILED TESTS ({len(failed)}):")
        for tgt, exp, got, r in failed:
            print(f"  - {tgt}: expected {exp}, got {got} — {r}")

    # Restore original scope
    if original is not None:
        test_scope.write_text(original)
    else:
        test_scope.unlink(missing_ok=True)