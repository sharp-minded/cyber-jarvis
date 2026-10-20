"""
interface/autostart.py - Windows boot auto-launch

Uses Windows registry + optional Startup folder shortcut.
"""

import os
import sys
import subprocess
import winreg
from pathlib import Path
from rich.console import Console

console = Console()

# Resolve main_v5.py from parent dir
JARVIS_MAIN = Path(__file__).parent.parent / "main_v5.py"


class AutoStart:
    """Manage Windows auto-start entries."""

    REG_PATH = r"Software\Microsoft\Windows\CurrentVersion\Run"
    APP_NAME = "CyberJarvis"

    @staticmethod
    def enable() -> bool:
        """Add to Windows registry Run key."""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                AutoStart.REG_PATH,
                0,
                winreg.KEY_SET_VALUE,
            )
            cmd = f'"{sys.executable}" "{JARVIS_MAIN}" --autostart'
            winreg.SetValueEx(key, AutoStart.APP_NAME, 0, winreg.REG_SZ, cmd)
            winreg.CloseKey(key)
            console.print("[green][+] Auto-start enabled[/green]")
            console.print(f"[dim]Command: {cmd}[/dim]")
            return True
        except Exception as e:
            console.print(f"[red]Enable failed: {e}[/red]")
            return False

    @staticmethod
    def disable() -> bool:
        """Remove from Windows registry."""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                AutoStart.REG_PATH,
                0,
                winreg.KEY_SET_VALUE,
            )
            winreg.DeleteValue(key, AutoStart.APP_NAME)
            winreg.CloseKey(key)
            console.print("[green][+] Auto-start disabled[/green]")
            return True
        except FileNotFoundError:
            console.print("[yellow]Auto-start was not enabled[/yellow]")
            return False
        except Exception as e:
            console.print(f"[red]{e}[/red]")
            return False

    @staticmethod
    def is_enabled() -> bool:
        """Check registry."""
        try:
            key = winreg.OpenKey(
                winreg.HKEY_CURRENT_USER,
                AutoStart.REG_PATH,
                0,
                winreg.KEY_READ,
            )
            try:
                winreg.QueryValueEx(key, AutoStart.APP_NAME)
                return True
            except FileNotFoundError:
                return False
            finally:
                winreg.CloseKey(key)
        except Exception:
            return False

    @staticmethod
    def create_startup_shortcut() -> bool:
        """Alternative: VBS launcher in Startup folder (runs hidden)."""
        try:
            startup = (
                Path(os.getenv("APPDATA"))
                / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            )
            startup.mkdir(parents=True, exist_ok=True)

            vbs = startup / "CyberJarvis.vbs"
            vbs.write_text(
                'Set WshShell = CreateObject("WScript.Shell")\n'
                f'WshShell.Run """{sys.executable}"" ""{JARVIS_MAIN}"" --autostart", 0, False\n'
            )
            console.print(f"[green][+] Startup shortcut created: {vbs}[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Shortcut failed: {e}[/red]")
            return False

    @staticmethod
    def remove_startup_shortcut() -> bool:
        """Remove VBS launcher."""
        try:
            startup = (
                Path(os.getenv("APPDATA"))
                / "Microsoft" / "Windows" / "Start Menu" / "Programs" / "Startup"
            )
            vbs = startup / "CyberJarvis.vbs"
            if vbs.exists():
                vbs.unlink()
                console.print("[green][+] Startup shortcut removed[/green]")
            return True
        except Exception as e:
            console.print(f"[red]{e}[/red]")
            return False


# ─── CLI entry for standalone test ─────────────────────────
if __name__ == "__main__":
    import argparse
    p = argparse.ArgumentParser()
    p.add_argument("action", choices=["enable", "disable", "status", "shortcut", "remove-shortcut"])
    args = p.parse_args()

    if args.action == "enable":
        AutoStart.enable()
    elif args.action == "disable":
        AutoStart.disable()
    elif args.action == "status":
        print(f"Enabled: {AutoStart.is_enabled()}")
    elif args.action == "shortcut":
        AutoStart.create_startup_shortcut()
    elif args.action == "remove-shortcut":
        AutoStart.remove_startup_shortcut()