"""
tools_integration/nuclei_manager.py - Nuclei templates

FIX: Removed duplicate dict key issue (verified clean).
FIX: Scope hook on scan().
"""

import json
from pathlib import Path
from typing import Dict, List, Optional
from rich.console import Console
from rich.panel import Panel

from core.config import CONFIG
from core.tools_engine import get_kali
from core.scope_guard import validate_scope

console = Console()


class NucleiManager:
    """Nuclei template manager + scan."""

    def __init__(self):
        self.templates_dir = CONFIG["nuclei_templates_dir"]
        self.templates_dir.mkdir(parents=True, exist_ok=True)

    def is_ready(self) -> bool:
        kali = get_kali()
        if not kali.is_ready():
            return False
        return bool(kali.run("command -v nuclei").strip())

    # ─── Template Creation ────────────────────────────────

    def create_template(
        self,
        template_id: str,
        name: str,
        severity: str,
        path: str,
        matchers: List[Dict] = None,
        tags: List[str] = None,
    ) -> Optional[str]:
        """Create a custom Nuclei template (YAML)."""
        template = {
            "id": template_id,
            "info": {
                "name": name,
                "author": "CyberJarvis",
                "severity": severity,
                "tags": ",".join(tags or []),
            },
            "http": [
                {
                    "method": "GET",
                    "path": [path],
                    "matchers": matchers or [{"type": "status", "status": [200]}],
                }
            ],
        }

        file = self.templates_dir / f"{template_id}.yaml"
        try:
            import yaml
            file.write_text(yaml.dump(template, default_flow_style=False))
        except ImportError:
            file.write_text(json.dumps(template, indent=2))

        return str(file)

    def create_all_common_templates(self) -> List[str]:
        """Generate common vuln templates (SQLi, XSS, LFI, SSRF)."""
        templates = []

        # SQL Injection
        templates.append(self.create_template(
            "custom-sqli",
            "SQL Injection Detection",
            "high",
            "{{BaseURL}}/?id=1'",
            [{
                "type": "regex",
                "regex": [
                    "(?i)sql syntax",
                    "Warning.*mysql_",
                    "ORA-[0-9]{5}",
                    "PostgreSQL.*ERROR",
                ],
                "part": "body",
                "condition": "or",
            }],
            ["sqli", "custom"],
        ))

        # Reflected XSS
        templates.append(self.create_template(
            "custom-xss",
            "Reflected XSS Detection",
            "medium",
            "{{BaseURL}}/?q=<script>alert(1)</script>",
            [{
                "type": "word",
                "words": ["<script>alert(1)</script>"],
                "part": "body",
            }],
            ["xss", "custom"],
        ))

        # LFI
        templates.append(self.create_template(
            "custom-lfi",
            "Local File Inclusion",
            "high",
            "{{BaseURL}}/?file=../../../../etc/passwd",
            [{
                "type": "word",
                "words": ["root:x:0:0"],
                "part": "body",
            }],
            ["lfi", "custom"],
        ))

        # SSRF
        templates.append(self.create_template(
            "custom-ssrf",
            "SSRF (Cloud Metadata)",
            "high",
            "{{BaseURL}}/?url=http://169.254.169.254/latest/meta-data/",
            [{
                "type": "word",
                "words": ["ami-id", "instance-id"],
                "part": "body",
                "condition": "or",
            }],
            ["ssrf", "custom"],
        ))

        console.print(f"[green][+] Created {len(templates)} templates[/green]")
        return templates

    # ─── Scan ─────────────────────────────────────────────

    def scan(self, target: str, severity: str = "") -> Dict:
        """Run Nuclei scan. SCOPE ENFORCED."""

        # FIX: scope hook
        allowed, reason = validate_scope(target)
        if not allowed:
            console.print(f"[red][!] SCOPE DENIED: {target} — {reason}[/red]")
            return {"success": False, "error": f"SCOPE DENIED: {reason}"}

        kali = get_kali()
        if not kali.is_ready():
            return {"success": False, "error": "Kali not connected"}

        # Upload custom templates to Kali
        remote_dir = "/tmp/jarvis_nuclei_templates"
        kali.run(f"mkdir -p {remote_dir}")
        for f in self.templates_dir.glob("*.yaml"):
            kali.upload_file(str(f), remote_dir)

        cmd = f"nuclei -u {target} -jsonl -silent -no-color -t {remote_dir}"
        if severity:
            cmd += f" -severity {severity}"

        console.print(Panel(
            f"[cyan]nuclei -u {target}[/cyan]",
            border_style="yellow",
        ))

        result = kali.run(cmd, timeout=900)

        # Parse JSONL
        findings = []
        for line in result.splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                findings.append(json.loads(line))
            except json.JSONDecodeError:
                continue

        return {
            "success": True,
            "target": target,
            "total_findings": len(findings),
            "findings": findings,
        }

    def update_templates(self) -> bool:
        """Update official nuclei templates."""
        kali = get_kali()
        if not kali.is_ready():
            return False
        try:
            kali.run("nuclei -update-templates", timeout=300)
            console.print("[green][+] Templates updated[/green]")
            return True
        except Exception:
            return False

    def list_custom_templates(self) -> List[str]:
        return [str(f) for f in self.templates_dir.glob("*.yaml")]