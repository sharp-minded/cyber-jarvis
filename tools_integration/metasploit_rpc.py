"""
tools_integration/metasploit_rpc.py - Metasploit RPC

FIX: Default password REMOVED. Uses CONFIG["msf_rpc_password"] (random if not set).
FIX: shlex.quote for password argument (injection-proof).
"""

import time
import subprocess
import shlex
from typing import Dict, List, Optional
from rich.console import Console
from rich.panel import Panel

from core.config import CONFIG

console = Console()

try:
    from pymetasploit3.msfrpc import MsfRpcClient
    MSF_AVAILABLE = True
except ImportError:
    MSF_AVAILABLE = False
    console.print("[yellow][!] pymetasploit3 missing: pip install pymetasploit3[/yellow]")


class MetasploitRPC:
    """Metasploit RPC client via pymetasploit3."""

    def __init__(self):
        self.client = None
        self.rpc_running = False
        self._start_rpc()
        if self.rpc_running:
            self._connect()

    def _start_rpc(self):
        """Ensure msfrpcd is running."""
        if not MSF_AVAILABLE:
            return

        # Check if already running
        try:
            result = subprocess.run(
                ["ss", "-tlnp"],
                capture_output=True,
                text=True,
                timeout=5,
            )
            if str(CONFIG["msf_rpc_port"]) in result.stdout:
                self.rpc_running = True
                console.print("[green][+] msfrpcd already running[/green]")
                return
        except Exception:
            pass

        console.print("[yellow][*] Starting msfrpcd...[/yellow]")

        # FIX: quote password with shlex
        password = shlex.quote(CONFIG["msf_rpc_password"])
        port = str(CONFIG["msf_rpc_port"])

        try:
            subprocess.Popen(
                ["msfrpcd", "-P", CONFIG["msf_rpc_password"],
                 "-p", port, "-S", "-f"],
                stdout=subprocess.DEVNULL,
                stderr=subprocess.DEVNULL,
            )
            time.sleep(8)
            self.rpc_running = True
        except FileNotFoundError:
            console.print("[red]msfrpcd not found — Metasploit installed?[/red]")

    def _connect(self):
        try:
            self.client = MsfRpcClient(
                CONFIG["msf_rpc_password"],
                port=CONFIG["msf_rpc_port"],
                ssl=CONFIG["msf_rpc_ssl"],
            )
            console.print("[green][+] Metasploit RPC connected[/green]")
        except Exception as e:
            console.print(f"[red]MSF connect failed: {e}[/red]")
            self.client = None

    def is_ready(self) -> bool:
        return self.client is not None

    # ─── Exploits ─────────────────────────────────────────

    def list_exploits(self, search: str = "") -> List[str]:
        if not self.is_ready():
            return []
        try:
            all_e = self.client.modules.exploits
            if search:
                return [e for e in all_e if search.lower() in e.lower()][:50]
            return all_e[:50]
        except Exception:
            return []

    def run_exploit(
        self,
        module_path: str,
        options: Dict,
        payload: str = "cmd/unix/reverse_bash",
        payload_options: Optional[Dict] = None,
        wait_timeout: int = 30,
    ) -> Dict:
        if not self.is_ready():
            return {"success": False, "error": "RPC not connected"}

        console.print(Panel(
            f"[bold red]Exploit: {module_path}[/bold red]\n"
            f"Options: {options}\n"
            f"Payload: {payload}",
            border_style="red",
        ))

        try:
            exploit = self.client.modules.use("exploit", module_path)

            for k, v in options.items():
                try:
                    exploit[k] = v
                except Exception:
                    pass

            if payload:
                try:
                    exploit.payload = payload
                except Exception:
                    pass

            if payload_options:
                for k, v in payload_options.items():
                    try:
                        exploit[k] = v
                    except Exception:
                        pass

            result = exploit.execute()
            job_id = result.get("job_id")

            # Wait for session
            session_id = None
            for _ in range(wait_timeout):
                time.sleep(1)
                sessions = self.client.sessions.list
                if sessions:
                    session_id = list(sessions.keys())[0]
                    break

            return {
                "success": bool(session_id),
                "session_id": session_id,
                "job_id": job_id,
                "sessions": self.client.sessions.list,
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ─── Auxiliary ────────────────────────────────────────

    def run_auxiliary(
        self,
        module_path: str,
        options: Dict,
        wait_timeout: int = 60,
    ) -> Dict:
        if not self.is_ready():
            return {"success": False, "error": "RPC not connected"}
        try:
            aux = self.client.modules.use("auxiliary", module_path)
            for k, v in options.items():
                try:
                    aux[k] = v
                except Exception:
                    pass
            result = aux.execute()
            job_id = result.get("job_id")
            time.sleep(min(wait_timeout, 30))
            return {"success": True, "job_id": job_id}
        except Exception as e:
            return {"success": False, "error": str(e)}

    # ─── Sessions ─────────────────────────────────────────

    def session_command(self, session_id: str, command: str) -> str:
        if not self.is_ready():
            return "RPC not connected"
        try:
            session = self.client.sessions.session(session_id)
            return session.run_with_output(command, timeout=30)
        except Exception as e:
            return f"Error: {e}"

    def list_sessions(self) -> Dict:
        return self.client.sessions.list if self.is_ready() else {}

    def kill_session(self, session_id: str) -> bool:
        if not self.is_ready():
            return False
        try:
            self.client.sessions.session(session_id).stop()
            return True
        except Exception:
            return False

    def search_cve(self, cve_id: str) -> List[str]:
        if not self.is_ready():
            return []
        try:
            return self.client.modules.search(cve_id)
        except Exception:
            return []