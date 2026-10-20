"""
tools_integration/burp_api.py - Burp Suite Pro REST API

Burp: Settings → Suite → REST API → Enable, port 1337, generate API key.
"""

import time
from typing import Dict, List, Optional
import requests
from rich.console import Console
from rich.panel import Panel

from core.config import CONFIG

console = Console()


class BurpAPI:
    """Burp Suite Pro REST API client."""

    def __init__(self):
        self.base_url = CONFIG["burp_api_url"].rstrip("/")
        self.api_key = CONFIG["burp_api_key"]
        self.available = self._check_available()

    def _check_available(self) -> bool:
        try:
            r = requests.get(f"{self.base_url}/v0.1/scan", timeout=3)
            if r.status_code in [200, 401]:
                console.print("[green][+] Burp REST API reachable[/green]")
                return True
        except requests.exceptions.ConnectionError:
            console.print(f"[yellow][!] Burp not reachable at {self.base_url}[/yellow]")
            console.print("[yellow][!] Enable in Burp Pro: Settings → Suite → REST API[/yellow]")
        except Exception as e:
            console.print(f"[yellow][!] Burp check error: {e}[/yellow]")
        return False

    def _headers(self) -> Dict:
        return {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.api_key}",
        }

    def is_ready(self) -> bool:
        return self.available and bool(self.api_key)

    # ─── Scan ─────────────────────────────────────────────

    def start_scan(self, urls: List[str], scan_config: Optional[Dict] = None) -> Optional[str]:
        if not self.is_ready():
            console.print("[red]Burp API not ready[/red]")
            return None

        payload = {"urls": urls}
        if scan_config:
            payload["scan_configurations"] = scan_config
        else:
            payload["scan_configurations"] = [
                {"name": "Crawl", "type": "NamedConfiguration"},
                {"name": "Audit", "type": "NamedConfiguration"},
            ]

        try:
            r = requests.post(
                f"{self.base_url}/v0.1/scan",
                headers=self._headers(),
                json=payload,
                timeout=30,
            )
            if r.status_code in [200, 201]:
                task_id = r.headers.get("Location", "").split("/")[-1]
                console.print(Panel(
                    f"[bold green]Burp scan started[/bold green]\n"
                    f"Task ID: {task_id}\n"
                    f"URLs: {urls}",
                    border_style="green",
                ))
                return task_id
            else:
                console.print(f"[red]Start failed: {r.status_code} {r.text[:200]}[/red]")
        except Exception as e:
            console.print(f"[red]Burp start error: {e}[/red]")
        return None

    def get_scan_status(self, task_id: str) -> Dict:
        try:
            r = requests.get(
                f"{self.base_url}/v0.1/scan/{task_id}",
                headers=self._headers(),
                timeout=15,
            )
            return r.json() if r.status_code == 200 else {}
        except Exception:
            return {}

    def wait_for_scan(self, task_id: str, timeout: int = 1800) -> Dict:
        console.print(f"[cyan][*] Waiting for Burp scan {task_id}...[/cyan]")
        start = time.time()
        while time.time() - start < timeout:
            status = self.get_scan_status(task_id)
            scan_status = status.get("scan_status", "unknown")
            console.print(f"[dim]Status: {scan_status} ({int(time.time()-start)}s)[/dim]")

            if scan_status in ["succeeded", "failed", "cancelled"]:
                return status
            time.sleep(10)
        return {"scan_status": "timeout"}

    def get_scan_issues(self, task_id: str) -> List[Dict]:
        try:
            r = requests.get(
                f"{self.base_url}/v0.1/scan/{task_id}/issues",
                headers=self._headers(),
                timeout=30,
            )
            return r.json().get("issues", []) if r.status_code == 200 else []
        except Exception:
            return []

    def get_scan_report(self, task_id: str, report_type: str = "HTML") -> Optional[str]:
        try:
            r = requests.post(
                f"{self.base_url}/v0.1/scan/{task_id}/report",
                headers=self._headers(),
                json={"report_type": report_type},
                timeout=120,
            )
            if r.status_code == 200:
                ext = "html" if report_type == "HTML" else "xml"
                f = CONFIG["reports_dir"] / f"burp_{task_id}.{ext}"
                f.write_bytes(r.content)
                console.print(f"[green][+] Burp report saved: {f}[/green]")
                return str(f)
        except Exception as e:
            console.print(f"[red]Report error: {e}[/red]")
        return None

    def cancel_scan(self, task_id: str) -> bool:
        try:
            r = requests.delete(
                f"{self.base_url}/v0.1/scan/{task_id}",
                headers=self._headers(),
                timeout=15,
            )
            return r.status_code == 200
        except Exception:
            return False

    def list_scans(self) -> List[Dict]:
        try:
            r = requests.get(
                f"{self.base_url}/v0.1/scan",
                headers=self._headers(),
                timeout=15,
            )
            return r.json().get("scans", []) if r.status_code == 200 else []
        except Exception:
            return []

    # ─── High-level ───────────────────────────────────────

    def full_scan(self, target_url: str) -> Dict:
        if not self.is_ready():
            return {"success": False, "error": "Burp API not ready"}

        console.print(Panel(
            f"[bold magenta]Burp Full Scan: {target_url}[/bold magenta]",
            border_style="magenta",
        ))

        task_id = self.start_scan([target_url])
        if not task_id:
            return {"success": False, "error": "Start failed"}

        self.wait_for_scan(task_id)
        issues = self.get_scan_issues(task_id)
        report = self.get_scan_report(task_id, "HTML")

        severity_count = {}
        for issue in issues:
            sev = issue.get("severity", "unknown")
            severity_count[sev] = severity_count.get(sev, 0) + 1

        return {
            "success": True,
            "task_id": task_id,
            "total_issues": len(issues),
            "severity_breakdown": severity_count,
            "issues": issues[:50],
            "report_file": report,
        }