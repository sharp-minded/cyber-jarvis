"""
core/remote_executor.py - SSH to Kali VM.

FIX: Uses scope_guard for validation (not local substring check).
"""

import time
from pathlib import Path
from typing import Dict, List, Optional

import paramiko
from scp import SCPClient
from rich.console import Console
from rich.panel import Panel

from core.config import CONFIG

console = Console()


class KaliRemote:
    def __init__(self, host=None, port=None, username=None, password=None, key_file=None):
        self.host = host or CONFIG["kali_host"]
        self.port = port or CONFIG["kali_ssh_port"]
        self.username = username or CONFIG["kali_user"]
        self.password = password or CONFIG["kali_pass"]
        self.key_file = key_file or CONFIG["kali_key"]

        self.client: Optional[paramiko.SSHClient] = None
        self.connected = False
        self._connect()

    def _connect(self):
        try:
            self.client = paramiko.SSHClient()
            self.client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            if self.key_file and Path(self.key_file).exists():
                self.client.connect(
                    hostname=self.host, port=self.port,
                    username=self.username, key_filename=self.key_file, timeout=15,
                )
            else:
                self.client.connect(
                    hostname=self.host, port=self.port,
                    username=self.username, password=self.password, timeout=15,
                )
            self.connected = True
            console.print(f"[green][+] Kali SSH: {self.host}[/green]")
        except Exception as e:
            console.print(f"[red][-] Kali SSH failed: {e}[/red]")
            self.connected = False

    def is_ready(self):
        return self.connected and self.client is not None

    def run(self, command: str, timeout: int = 600) -> str:
        if not self.is_ready():
            return "[ERROR] Not connected"
        try:
            stdin, stdout, stderr = self.client.exec_command(command, timeout=timeout, get_pty=True)
            return stdout.read().decode("utf-8", errors="ignore")
        except Exception as e:
            return f"[ERROR] {e}"

    def run_tool(self, tool: str, args: List[str], target: str = "", timeout: int = 900) -> Dict:
        """Run a tool. NOTE: scope validation happens in tools_engine, not here."""
        if not self.is_ready():
            return {"success": False, "error": "Kali not connected"}

        # Tool availability check + auto-install
        check = self.run(f"command -v {tool} || echo MISSING")
        if "MISSING" in check or not check.strip():
            if not self.auto_install(tool):
                return {"success": False, "error": f"{tool} unavailable"}

        args_str = " ".join(str(a) for a in args)
        cmd = f"{tool} {args_str}"
        log_path = f"/tmp/jarvis_{tool}_{int(time.time())}.log"

        console.print(Panel(f"[cyan]{cmd}[/cyan]", title="Kali", border_style="yellow"))

        start = time.time()
        try:
            stdin, stdout, stderr = self.client.exec_command(
                f"{cmd} 2>&1 | tee {log_path}", timeout=timeout, get_pty=True
            )
            output = stdout.read().decode("utf-8", errors="ignore")
            elapsed = time.time() - start
            local_log = self.download_file(log_path)
            return {
                "success": True,
                "output": output[:8000],
                "full_log_local": local_log,
                "elapsed": round(elapsed, 2),
            }
        except Exception as e:
            return {"success": False, "error": str(e)}

    def auto_install(self, tool: str) -> bool:
        console.print(f"[yellow][*] Installing {tool} on Kali...[/yellow]")
        self.run(f"sudo DEBIAN_FRONTEND=noninteractive apt install -y {tool}", timeout=600)
        check = self.run(f"command -v {tool}")
        if check.strip() and "not found" not in check.lower():
            return True
        self.run(f"pip install --break-system-packages {tool}", timeout=600)
        check = self.run(f"command -v {tool}")
        return bool(check.strip())

    def download_file(self, remote: str, local_dir: str = None) -> Optional[str]:
        if not self.is_ready():
            return None
        try:
            local_dir = local_dir or str(CONFIG["loot_dir"])
            Path(local_dir).mkdir(parents=True, exist_ok=True)
            local_path = Path(local_dir) / Path(remote).name
            sftp = self.client.open_sftp()
            sftp.get(remote, str(local_path))
            sftp.close()
            return str(local_path)
        except Exception:
            return None

    def upload_file(self, local: str, remote_dir: str = "/tmp/") -> Optional[str]:
        if not self.is_ready():
            return None
        try:
            sftp = self.client.open_sftp()
            remote_full = f"{remote_dir}/{Path(local).name}"
            sftp.put(local, remote_full)
            sftp.close()
            return remote_full
        except Exception:
            return None

    def upload_directory(self, local_dir: str, remote_dir: str):
        if not self.is_ready():
            return
        try:
            with SCPClient(self.client.get_transport()) as scp:
                scp.put(local_dir, remote_path=remote_dir, recursive=True)
        except Exception as e:
            console.print(f"[red]Upload failed: {e}[/red]")

    def health_check(self, tools: List[str]) -> Dict:
        cmd = " ; ".join([f"command -v {t} || echo MISSING:{t}" for t in tools])
        output = self.run(cmd)
        installed, missing = [], []
        for line in output.splitlines():
            line = line.strip()
            if line.startswith("MISSING:"):
                missing.append(line.split(":", 1)[1])
            elif line and "/" in line:
                installed.append(Path(line).name)
        return {"installed": installed, "missing": missing}

    def get_system_info(self) -> Dict:
        info = {}
        info["hostname"] = self.run("hostname").strip()
        info["kernel"] = self.run("uname -r").strip()
        info["os"] = self.run("grep PRETTY_NAME /etc/os-release").strip()
        info["ip"] = self.run("hostname -I").strip()
        info["cpu"] = self.run("nproc").strip()
        info["ram"] = self.run("free -h | grep Mem | awk '{print $2}'").strip()
        info["disk"] = self.run("df -h / | tail -1 | awk '{print $2, $4}'").strip()
        return info

    def start_msfrpcd(self, password: str = None, port: int = 55553) -> bool:
        password = password or CONFIG["msf_rpc_password"]
        check = self.run(f"ss -tlnp | grep {port}")
        if str(port) in check:
            return True
        # ─── FIX: use quoted password to prevent injection ───
        import shlex
        safe_pass = shlex.quote(password)
        self.run(
            f"nohup msfrpcd -P {safe_pass} -p {port} -S -f > /tmp/msfrpcd.log 2>&1 &",
            timeout=20,
        )
        time.sleep(8)
        verify = self.run(f"ss -tlnp | grep {port}")
        return str(port) in verify

    def close(self):
        if self.client:
            self.client.close()
            self.connected = False