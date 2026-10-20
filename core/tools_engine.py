"""
core/tools_engine.py - Tool execution wrapper.

FIX: Uses robust scope_guard (not substring check).
"""

import re
from typing import Dict, List
from rich.console import Console
from rich.panel import Panel

from core.config import CONFIG
from core.remote_executor import KaliRemote
from core.scope_guard import validate_scope

console = Console()

_kali: KaliRemote = None


def get_kali() -> KaliRemote:
    global _kali
    if _kali is None or not _kali.is_ready():
        _kali = KaliRemote()
    return _kali


class RemoteToolExecutor:
    """Executes tools on Kali VM with scope validation."""

    DANGEROUS_PATTERNS = [
        r"rm\s+-rf\s+/(?!tmp)",
        r"mkfs\.",
        r"dd\s+if=/dev/(zero|random|urandom)",
        r":\(\)\s*\{",           # fork bomb
        r"shutdown|reboot|halt|poweroff",
        r"init\s+0",
        r"kill\s+-9\s+1",
        r">\s*/dev/sd[a-z]",
        r"chmod\s+-R\s+777\s+/",
    ]

    @classmethod
    def _is_dangerous(cls, cmd: str) -> bool:
        for pat in cls.DANGEROUS_PATTERNS:
            if re.search(pat, cmd, re.IGNORECASE):
                return True
        return False

    @classmethod
    def execute(cls, tool: str, args: List[str], target: str = "",
                timeout: int = 900) -> Dict:
        """
        Execute tool with safety checks.

        Order:
          1. Dangerous command check
          2. SCOPE validation (robust)
          3. Kali connection check
          4. Execute
        """
        cmd_str = f"{tool} " + " ".join(str(a) for a in args)

        # 1. Dangerous
        if cls._is_dangerous(cmd_str):
            return {"success": False, "error": "Dangerous command blocked"}

        # 2. SCOPE — CRITICAL FIX
        if target:
            allowed, reason = validate_scope(target)
            if not allowed:
                console.print(f"[red][!] SCOPE DENIED: {target} — {reason}[/red]")
                return {"success": False, "error": f"SCOPE DENIED: {reason}"}

        # 3. Kali check
        kali = get_kali()
        if not kali.is_ready():
            return {"success": False, "error": "Kali SSH not connected"}

        # 4. Execute
        return kali.run_tool(tool, args, target, timeout)


# Backward compatibility alias
ToolExecutor = RemoteToolExecutor


def health_check(verbose: bool = False) -> Dict:
    from core.config import ALL_TOOLS, CRITICAL_TOOLS
    kali = get_kali()
    if not kali.is_ready():
        return {"installed": [], "missing": ALL_TOOLS, "critical_missing": CRITICAL_TOOLS}

    result = kali.health_check(ALL_TOOLS)
    crit_missing = [t for t in result["missing"] if t in CRITICAL_TOOLS]

    if verbose:
        console.print(f"[green]Installed: {len(result['installed'])}[/green]")
        console.print(f"[yellow]Missing: {len(result['missing'])}[/yellow]")
        console.print(f"[red]Critical missing: {crit_missing}[/red]")

    return {
        "installed": result["installed"],
        "missing": result["missing"],
        "critical_missing": crit_missing,
    }


def install_critical():
    from core.config import CRITICAL_TOOLS
    kali = get_kali()
    for tool in CRITICAL_TOOLS:
        kali.auto_install(tool)