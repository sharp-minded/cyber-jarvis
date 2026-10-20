"""
intelligence/knowledge_ingest.py - Auto-ingest security KBs

FIX: Handles git clone timeout + size checks.
"""

import subprocess
import shutil
from pathlib import Path
from typing import Dict, Tuple
from rich.console import Console

from core.config import CONFIG
from intelligence.rag_knowledge import get_rag

console = Console()


# ─── Knowledge base sources ───────────────────────────────
SOURCES: Dict[str, Tuple[str, list]] = {
    "hacktricks": (
        "https://github.com/HackTricks-wiki/hacktricks.git",
        [".md"],
    ),
    "payloads": (
        "https://github.com/swisskyrepo/PayloadsAllTheThings.git",
        [".md"],
    ),
    "gtfobins": (
        "https://github.com/GTFOBins/GTFOBins.github.io.git",
        [".md"],
    ),
    "lolbas": (
        "https://github.com/LOLBAS-Project/LOLBAS.git",
        [".yml", ".yaml", ".md"],
    ),
    "nuclei_templates": (
        "https://github.com/projectdiscovery/nuclei-templates.git",
        [".yaml"],
    ),
}


class KnowledgeIngestor:
    """Clone or update security knowledge repos and ingest."""

    def __init__(self):
        self.cache = CONFIG["kb_cache_dir"]
        self.cache.mkdir(parents=True, exist_ok=True)
        self.rag = get_rag()

    # ─── Git helpers ──────────────────────────────────────

    def _clone_or_update(self, name: str, url: str) -> Path:
        repo = self.cache / name

        if repo.exists():
            console.print(f"[cyan][*] Updating {name}...[/cyan]")
            try:
                subprocess.run(
                    ["git", "-C", str(repo), "pull", "--quiet"],
                    capture_output=True,
                    timeout=120,
                    check=False,
                )
            except subprocess.TimeoutExpired:
                console.print(f"[yellow][!] Update timeout for {name}[/yellow]")
            except Exception as e:
                console.print(f"[yellow][!] Update failed: {e}[/yellow]")
        else:
            console.print(f"[cyan][*] Cloning {name} (shallow)...[/cyan]")
            try:
                subprocess.run(
                    ["git", "clone", "--depth", "1", url, str(repo)],
                    capture_output=True,
                    timeout=600,
                    check=True,
                )
            except subprocess.TimeoutExpired:
                console.print(f"[red][-] Clone timeout: {name}[/red]")
                return None
            except subprocess.CalledProcessError as e:
                console.print(f"[red][-] Clone failed: {name} — {e}[/red]")
                return None

        return repo

    # ─── Ingestion ────────────────────────────────────────

    def ingest_source(self, name: str, url: str, exts: list) -> int:
        """Ingest one repo."""
        repo = self._clone_or_update(name, url)
        if not repo:
            return 0

        total = 0
        skipped = 0

        for f in repo.rglob("*"):
            if not f.is_file() or f.suffix not in exts:
                continue

            # Skip large files (>500 KB)
            try:
                if f.stat().st_size > 500_000:
                    skipped += 1
                    continue
            except Exception:
                continue

            try:
                total += self.rag.ingest_file(f, source=f"{name}:{f.name}")
            except Exception:
                pass

        console.print(
            f"[green][+] {name}: {total} chunks ingested"
            + (f" ({skipped} large files skipped)" if skipped else "")
            + "[/green]"
        )
        return total

    def ingest_all(self) -> int:
        """Ingest all configured sources."""
        console.print("[bold yellow][*] Ingesting all knowledge bases...[/bold yellow]")
        console.print(f"[dim]Cache dir: {self.cache}[/dim]")

        total = 0
        failed = []

        for name, (url, exts) in SOURCES.items():
            try:
                chunks = self.ingest_source(name, url, exts)
                total += chunks
                if chunks == 0:
                    failed.append(name)
            except Exception as e:
                console.print(f"[red][-] {name} failed: {e}[/red]")
                failed.append(name)

        console.print(f"\n[bold green][+] Total chunks ingested: {total}[/bold green]")
        if failed:
            console.print(f"[yellow][!] Failed sources: {', '.join(failed)}[/yellow]")
        console.print(f"[cyan][*] RAG store now has {self.rag.count()} docs[/cyan]")

        return total

    def clear_cache(self) -> bool:
        """Delete cloned repos (force re-clone next time)."""
        try:
            if self.cache.exists():
                shutil.rmtree(self.cache)
                self.cache.mkdir(parents=True, exist_ok=True)
            console.print("[green][+] Cache cleared[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Clear failed: {e}[/red]")
            return False


# ─── CLI entry ────────────────────────────────────────────

if __name__ == "__main__":
    import argparse

    p = argparse.ArgumentParser()
    p.add_argument("action", nargs="?", default="ingest",
                   choices=["ingest", "clear"])
    args = p.parse_args()

    ing = KnowledgeIngestor()

    if args.action == "clear":
        ing.clear_cache()
    else:
        ing.ingest_all()