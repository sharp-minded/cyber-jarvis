"""
intelligence/report_generator.py - Professional pentest report generator

FORMAT (STRICT - English only):
  1. Title
  2. Description
  3. Severity (with CVSS + CVSS vector + CWE)
  4. Proof of Concept (screenshots + curl command)
  5. Steps to Reproduce
  6. Business Impact
  7. Recommendation

FIX: Playwright screenshots + auto curl generation + proper English output.
"""

import time
from pathlib import Path
from typing import Dict, List, Optional

from rich.console import Console
from rich.panel import Panel

from core.config import CONFIG
from core.agents import BaseAgent

console = Console()


# ═══════════════════════════════════════════════════════════════
#  SCREENSHOT CAPTURE (Playwright)
# ═══════════════════════════════════════════════════════════════

class ScreenshotCapture:
    """Auto-capture PoC screenshots via Playwright."""

    def __init__(self):
        self.enabled = CONFIG.get("capture_screenshots", True)
        self.screenshots_dir = CONFIG["screenshots_dir"]
        self.screenshots_dir.mkdir(parents=True, exist_ok=True)
        self.timeout = 15000  # 15s

    def capture_url(self, url: str, name: str = None) -> Optional[str]:
        """Capture a URL screenshot."""
        if not self.enabled:
            return None
        if not url or not url.startswith(("http://", "https://")):
            return None

        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            console.print("[yellow][!] playwright not installed[/yellow]")
            return None

        # Sanitize filename
        safe_name = (name or f"poc_{int(time.time())}").replace(" ", "_")
        safe_name = "".join(c for c in safe_name if c.isalnum() or c in "._-")[:60]
        out_path = self.screenshots_dir / f"{safe_name}.png"

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                ctx = browser.new_context(viewport={"width": 1366, "height": 768})
                page = ctx.new_page()
                page.goto(url, timeout=self.timeout, wait_until="domcontentloaded")
                time.sleep(1)  # let JS settle
                page.screenshot(path=str(out_path), full_page=False)
                browser.close()

            console.print(f"[green][+] Screenshot: {out_path.name}[/green]")
            return str(out_path)
        except Exception as e:
            console.print(f"[yellow]Screenshot failed: {e}[/yellow]")
            return None

    def capture_html(self, html: str, name: str = None) -> Optional[str]:
        """Render custom HTML to screenshot."""
        if not self.enabled:
            return None
        try:
            from playwright.sync_api import sync_playwright
        except ImportError:
            return None

        safe_name = (name or f"poc_html_{int(time.time())}").replace(" ", "_")
        out_path = self.screenshots_dir / f"{safe_name}.png"

        try:
            with sync_playwright() as p:
                browser = p.chromium.launch(headless=True)
                page = browser.new_page(viewport={"width": 1366, "height": 768})
                page.set_content(html, wait_until="networkidle")
                page.screenshot(path=str(out_path), full_page=True)
                browser.close()
            return str(out_path)
        except Exception:
            return None


# ═══════════════════════════════════════════════════════════════
#  CURL COMMAND GENERATOR
# ═══════════════════════════════════════════════════════════════

class CurlGenerator:
    """Generate reproduction curl commands from finding type."""

    @staticmethod
    def generate(finding: Dict) -> Optional[str]:
        title = (finding.get("finding") or finding.get("title") or "").lower()
        target = finding.get("target") or finding.get("url") or ""

        if not target:
            return None

        # Sanitize target
        target = target.strip()

        # SQL Injection
        if any(k in title for k in ["sql", "sqli", "sql injection"]):
            return (
                f"# SQL Injection reproduction\n"
                f"curl -X GET '{target}?id=1%27%20OR%20%271%27%3D%271' \\\n"
                f"  -H 'User-Agent: Mozilla/5.0' \\\n"
                f"  -H 'Accept: */*' \\\n"
                f"  -v"
            )

        # XSS
        if any(k in title for k in ["xss", "cross-site", "cross site"]):
            return (
                f"# Reflected XSS reproduction\n"
                f"curl -X GET '{target}?q=<script>alert(1)</script>' \\\n"
                f"  -H 'User-Agent: Mozilla/5.0' \\\n"
                f"  -v"
            )

        # SSRF
        if "ssrf" in title or "server-side request" in title:
            return (
                f"# SSRF reproduction (AWS metadata endpoint)\n"
                f"curl -X GET '{target}?url=http://169.254.169.254/latest/meta-data/' \\\n"
                f"  -H 'User-Agent: Mozilla/5.0' \\\n"
                f"  -v"
            )

        # LFI / Path Traversal
        if any(k in title for k in ["lfi", "traversal", "file inclusion", "path traversal"]):
            return (
                f"# LFI / Path Traversal reproduction\n"
                f"curl -X GET '{target}?file=../../../../etc/passwd' \\\n"
                f"  -H 'User-Agent: Mozilla/5.0' \\\n"
                f"  -v"
            )

        # RCE / Command Injection
        if any(k in title for k in ["rce", "command injection", "remote code"]):
            return (
                f"# RCE / Command Injection reproduction\n"
                f"curl -X POST '{target}' \\\n"
                f"  -H 'User-Agent: Mozilla/5.0' \\\n"
                f"  -H 'Content-Type: application/x-www-form-urlencoded' \\\n"
                f"  -d 'cmd=;id;' \\\n"
                f"  -v"
            )

        # XXE
        if "xxe" in title or "xml external" in title:
            return (
                f"# XXE reproduction\n"
                f"curl -X POST '{target}' \\\n"
                f"  -H 'Content-Type: application/xml' \\\n"
                f"  -d '<?xml version=\"1.0\"?>"
                f"<!DOCTYPE foo [<!ENTITY xxe SYSTEM \"file:///etc/passwd\">]>"
                f"<foo>&xxe;</foo>' \\\n"
                f"  -v"
            )

        # CSRF
        if "csrf" in title:
            return (
                f"# CSRF PoC — save as csrf.html and open in browser\n"
                f"cat > csrf.html <<'EOF'\n"
                f"<html><body onload=\"document.forms[0].submit()\">\n"
                f"<form action='{target}' method='POST'>\n"
                f"<input name='email' value='attacker@evil.com'>\n"
                f"</form></body></html>\n"
                f"EOF"
            )

        # Open Redirect
        if "open redirect" in title or "redirect" in title:
            return (
                f"# Open Redirect reproduction\n"
                f"curl -X GET '{target}?url=https://evil.com' -v -L"
            )

        # Info Disclosure
        if any(k in title for k in ["disclosure", "information leak", "exposed"]):
            return f"# Information Disclosure\ncurl -X GET '{target}' -v"

        # Generic GET
        if target.startswith(("http://", "https://")):
            return f"# Generic reproduction\ncurl -X GET '{target}' -v"

        return None


# ═══════════════════════════════════════════════════════════════
#  REPORT GENERATOR
# ═══════════════════════════════════════════════════════════════

class ReportGenerator:
    """Generate professional pentest reports (English only)."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, "_initialized"):
            return
        self._initialized = True

        self.screenshots = ScreenshotCapture()
        self.curl_gen = CurlGenerator()

    # ─── Enrichment ───────────────────────────────────────

    def enrich_finding(self, finding: Dict, target: str = "") -> Dict:
        """Add screenshot + curl to a finding."""
        console.print(
            f"[cyan][*] Enriching: "
            f"{(finding.get('finding') or finding.get('title') or '?')[:50]}[/cyan]"
        )

        finding["target"] = target or finding.get("target", "")

        # Screenshot
        if target and target.startswith(("http://", "https://")):
            name = (finding.get("finding") or "poc").replace(" ", "_")[:40]
            shot = self.screenshots.capture_url(target, name=f"poc_{name}")
            finding["screenshot"] = shot

        # Curl command
        curl = self.curl_gen.generate(finding)
        finding["curl"] = curl

        return finding

    # ─── Helpers ──────────────────────────────────────────

    @staticmethod
    def _severity_to_cvss(severity: str) -> float:
        return {
            "critical": 9.5,
            "high": 8.0,
            "medium": 5.5,
            "low": 2.5,
            "info": 0.0,
        }.get(severity.lower(), 5.0)

    @staticmethod
    def _guess_vector(finding: Dict) -> str:
        title = (finding.get("finding") or "").lower()
        if any(k in title for k in ["sql", "sqli"]):
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H"
        if "xss" in title:
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:R/S:C/C:L/I:L/A:N"
        if "rce" in title or "command" in title:
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:H/A:H"
        if "ssrf" in title:
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:C/C:H/I:L/A:N"
        if "lfi" in title or "traversal" in title:
            return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N"
        return "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:L/I:L/A:N"

    @staticmethod
    def _guess_cwe(finding: Dict) -> str:
        title = (finding.get("finding") or "").lower()
        if any(k in title for k in ["sql", "sqli"]):
            return "CWE-89 (SQL Injection)"
        if "xss" in title:
            return "CWE-79 (Cross-site Scripting)"
        if "rce" in title or "command" in title:
            return "CWE-78 (OS Command Injection)"
        if "ssrf" in title:
            return "CWE-918 (Server-Side Request Forgery)"
        if "lfi" in title or "traversal" in title:
            return "CWE-22 (Path Traversal)"
        if "csrf" in title:
            return "CWE-352 (CSRF)"
        if "auth" in title:
            return "CWE-287 (Improper Authentication)"
        if "xxe" in title:
            return "CWE-611 (XML External Entity)"
        return "CWE-20 (Improper Input Validation)"

    @staticmethod
    def _business_impact(severity: str, title: str) -> str:
        t = title.lower()
        if "sql" in t:
            return (
                "An attacker could extract sensitive data from the database, "
                "including customer records, credentials, and business-critical "
                "information. Potential consequences include:\n\n"
                "- Regulatory fines (GDPR, PCI-DSS, HIPAA)\n"
                "- Data breach notification costs (avg $4.5M USD)\n"
                "- Reputation damage and customer attrition\n"
                "- Legal liability and class-action lawsuits\n"
                "- Business continuity disruption"
            )
        if "rce" in t or "command" in t:
            return (
                "Remote Code Execution allows an attacker to fully compromise "
                "the server. Business impact:\n\n"
                "- Complete server takeover\n"
                "- Theft or destruction of sensitive data\n"
                "- Ransomware deployment potential\n"
                "- Lateral movement into internal network\n"
                "- Full compromise of the organization's perimeter"
            )
        if "xss" in t:
            return (
                "Cross-site scripting enables attackers to hijack user sessions, "
                "steal credentials, and perform actions as the victim. Impact:\n\n"
                "- Account takeover for customers and admins\n"
                "- Session hijacking\n"
                "- Phishing attacks within trusted domain\n"
                "- Brand reputation damage"
            )
        if "ssrf" in t:
            return (
                "SSRF allows attackers to access internal services and cloud "
                "metadata. Impact:\n\n"
                "- Cloud credential theft (AWS/Azure/GCP)\n"
                "- Internal network reconnaissance\n"
                "- Unauthorized access to internal APIs\n"
                "- Potential full cloud account takeover"
            )
        if "lfi" in t or "traversal" in t:
            return (
                "Path traversal allows access to files outside the intended "
                "directory. Impact:\n\n"
                "- Exposure of sensitive configuration files\n"
                "- Credential and secret disclosure\n"
                "- Access to source code\n"
                "- Information gathering for further attacks"
            )
        if severity.lower() == "critical":
            return "Critical business impact requiring immediate remediation."
        if severity.lower() == "high":
            return "Significant business impact requiring urgent remediation."
        if severity.lower() == "medium":
            return "Moderate business impact requiring scheduled remediation."
        return "Minor business impact. Address during regular maintenance cycle."

    @staticmethod
    def _generate_steps(finding: Dict) -> str:
        title = (finding.get("finding") or "").lower()
        target = finding.get("target", "TARGET_URL")

        if "sql" in title:
            return f"""1. Identify an input parameter that interacts with the database.
2. Inject a single quote (`'`) as the parameter value.
3. Observe SQL error messages or altered application behavior.
4. Refine payloads to extract data (UNION-based, error-based, or blind).
5. Confirm data extraction by observing database responses.
6. Reproduce using the curl command in the PoC section."""

        if "xss" in title:
            return f"""1. Navigate to the vulnerable endpoint: `{target}`
2. Insert `<script>alert(1)</script>` in the vulnerable parameter.
3. Observe JavaScript execution in the browser (alert popup).
4. Replace payload with session-stealing script for full exploitation.
5. Reproduce using the curl command in the PoC section."""

        if "rce" in title or "command" in title:
            return f"""1. Identify the vulnerable input field or parameter.
2. Inject the test payload: `;id;` or `|id|`.
3. Observe command output reflected in the response.
4. Confirm RCE by checking the user context (e.g., `www-data`, `root`).
5. Escalate to reverse shell for persistent access.
6. Reproduce using the curl command in the PoC section."""

        if "ssrf" in title:
            return f"""1. Locate an endpoint that accepts a URL parameter.
2. Submit `http://169.254.169.254/latest/meta-data/` as input.
3. Observe cloud metadata response.
4. Enumerate internal services (e.g., `http://localhost:8080`).
5. Extract sensitive credentials or configuration.
6. Reproduce using the curl command in the PoC section."""

        if "lfi" in title or "traversal" in title:
            return f"""1. Identify a parameter that accepts a file path.
2. Submit `../../../../etc/passwd` as the parameter value.
3. Observe contents of `/etc/passwd` in the response.
4. Enumerate additional sensitive files (e.g., SSH keys, config).
5. Reproduce using the curl command in the PoC section."""

        # Generic
        return f"""1. Identify the vulnerable parameter or endpoint: `{target}`
2. Craft a malicious payload relevant to the vulnerability type.
3. Submit the payload to the application.
4. Observe the unexpected behavior.
5. Capture evidence (screenshot + response).
6. Reproduce using the curl command in the PoC section."""

    # ─── Format Single Finding ────────────────────────────

    def format_finding(self, finding: Dict, index: int) -> str:
        """Format single finding in strict English format."""
        title = (
            finding.get("finding")
            or finding.get("title")
            or f"Finding #{index}"
        )
        description = (
            finding.get("description")
            or finding.get("evidence", "")[:500]
            or "See evidence below."
        )
        severity = finding.get("severity", "Medium")
        cvss = finding.get("cvss") or self._severity_to_cvss(severity)
        evidence = finding.get("evidence", "")[:1500]
        remediation = finding.get("remediation", "")
        screenshot = finding.get("screenshot", "")
        curl = finding.get("curl", "")

        cvss_vector = self._guess_vector(finding)
        cwe = self._guess_cwe(finding)
        impact = self._business_impact(severity, title)
        steps = self._generate_steps(finding)

        # PoC section
        poc_parts = []
        if screenshot:
            poc_parts.append(
                f"### Screenshot\n\n"
                f"![Proof of Concept]({screenshot})\n"
            )
        if curl:
            poc_parts.append(
                f"### Reproducer (curl)\n\n"
                f"```bash\n{curl}\n```\n"
            )
        if evidence:
            poc_parts.append(
                f"### Raw Evidence\n\n"
                f"```\n{evidence}\n```\n"
            )

        poc_section = "\n".join(poc_parts) if poc_parts else "See raw evidence below."

        report = f"""# {index}. {title}

## Description

{description}

## Severity

| Field | Value |
|-------|-------|
| **Rating** | {severity} |
| **CVSS Score** | {cvss} |
| **CVSS Vector** | `{cvss_vector}` |
| **CWE** | {cwe} |

## Proof of Concept

{poc_section}

## Steps to Reproduce

{steps}

## Business Impact

{impact}

## Recommendation

{remediation if remediation else "Implement standard secure coding practices, enforce input validation, and follow OWASP guidelines. Review the affected code path and apply the principle of least privilege."}

---

"""
        return report

    # ─── Full Report ──────────────────────────────────────

    def generate_full_report(
        self,
        target: str,
        findings: List[Dict],
        mission_summary: str = "",
    ) -> str:
        """Generate complete pentest report in English."""
        console.print(Panel(
            f"[bold green]Generating report: {target}[/bold green]\n"
            f"Findings: {len(findings)}",
            border_style="green",
        ))

        # Enrich all findings
        enriched = [self.enrich_finding(f, target) for f in findings]

        # Severity counts
        sev_counts = {}
        for f in findings:
            sev = f.get("severity", "Info")
            sev_counts[sev] = sev_counts.get(sev, 0) + 1

        # Header
        timestamp = time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime())
        report_id = f"JARVIS-{int(time.time())}"

        report = f"""# Penetration Test Report

| Field | Value |
|-------|-------|
| **Target** | `{target}` |
| **Date** | {timestamp} |
| **Report ID** | {report_id} |
| **Classification** | Confidential |
| **Report Language** | English |

---

## Executive Summary

A comprehensive security assessment was performed on `{target}`.
The assessment identified **{len(findings)}** security findings.

### Severity Breakdown

| Severity | Count |
|----------|-------|
| Critical | {sev_counts.get('Critical', 0)} |
| High | {sev_counts.get('High', 0)} |
| Medium | {sev_counts.get('Medium', 0)} |
| Low | {sev_counts.get('Low', 0)} |
| Info | {sev_counts.get('Info', 0)} |

### Overall Risk Rating

{self._overall_risk(findings)}

---

## Scope & Methodology

| Field | Value |
|-------|-------|
| **Target** | `{target}` |
| **Methodology** | OWASP Testing Guide v4, PTES, MITRE ATT&CK |
| **Tools Used** | Nmap, Metasploit, Burp Suite, Nuclei, SQLMap, custom scripts |

{mission_summary if mission_summary else ""}

---

## Findings

"""
        # Add all findings
        for i, f in enumerate(enriched, 1):
            report += self.format_finding(f, i)

        # Appendix
        report += f"""---

## Appendix A: Risk Rating Definitions

| Rating | CVSS Range | Description |
|--------|------------|-------------|
| Critical | 9.0 – 10.0 | Immediate threat, actively exploited |
| High | 7.0 – 8.9 | Serious, exploitation likely |
| Medium | 4.0 – 6.9 | Moderate, exploitation possible |
| Low | 0.1 – 3.9 | Minor, exploitation unlikely |
| Info | 0.0 | Informational only |

## Appendix B: CVSS v3.1 Base Metrics

- **AV** Attack Vector (N=Network, A=Adjacent, L=Local, P=Physical)
- **AC** Attack Complexity (L=Low, H=High)
- **PR** Privileges Required (N=None, L=Low, H=High)
- **UI** User Interaction (N=None, R=Required)
- **S** Scope (U=Unchanged, C=Changed)
- **C/I/A** Confidentiality/Integrity/Availability Impact (N=None, L=Low, H=High)

---

## Disclaimer

This report is confidential and intended solely for authorized recipients.
Testing was performed with explicit written permission from the target owner.
Unauthorized distribution or reproduction is prohibited.

---

*Generated by Cyber Jarvis v6.0*
*Report format: Title > Description > Severity > PoC > Steps > Impact > Recommendation*
"""

        # Save
        report_file = CONFIG["reports_dir"] / f"report_{int(time.time())}.md"
        try:
            report_file.write_text(report, encoding="utf-8")
            console.print(f"[bold green][+] Report saved: {report_file}[/bold green]")
        except Exception as e:
            console.print(f"[red]Save failed: {e}[/red]")

        return str(report_file)

    @staticmethod
    def _overall_risk(findings: List[Dict]) -> str:
        sevs = [f.get("severity", "").lower() for f in findings]
        if "critical" in sevs:
            return "**CRITICAL** — Immediate remediation required (24 hours)."
        if "high" in sevs:
            return "**HIGH** — Urgent remediation recommended (7 days)."
        if "medium" in sevs:
            return "**MEDIUM** — Scheduled remediation recommended (30 days)."
        if "low" in sevs:
            return "**LOW** — Standard remediation cycle (90 days)."
        return "**INFORMATIONAL** — No significant issues identified."


# ─── Singleton accessor ───────────────────────────────────

def get_reporter() -> ReportGenerator:
    return ReportGenerator()