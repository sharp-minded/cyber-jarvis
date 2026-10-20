"""
main_v5.py - CYBER JARVIS v6.0 FINAL ENTRY POINT

All features:
- Multi-language (English / Hinglish / Roman Urdu)
- Report: Title > Desc > Severity > PoC > Steps > Impact > Recommendation
- WhatsApp notifications ONLY → +92 3132985274
- Scope-enforced (scope.txt + smart local allow)
- Teacher, RAG, Attack Graph, MITRE, Scoring, Reports
- Voice + Wake word + Proactive reminders + Auto-start
"""

import os
import sys
import re
import ipaddress
import argparse
import time
from pathlib import Path

# Ensure project root on path
ROOT = Path(__file__).parent.resolve()
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from dotenv import load_dotenv
load_dotenv()

from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table
from rich.prompt import Confirm

# ─── Core ─────────────────────────────────────────────────
from core.config import (
    CONFIG, get_tool_count, KALI_TOOLS, CRITICAL_TOOLS, get_language
)
from core.tools_engine import health_check, install_critical, RemoteToolExecutor
from core.agents import JarvisOrchestrator
from core.remote_executor import KaliRemote
from core.scope_guard import validate_scope, require_scope

# ─── Interface ────────────────────────────────────────────
from interface.voice_interface import VoiceInterface
from interface.wake_word import WakeWordDetector
from interface.proactive_jarvis import ProactiveJarvis
from interface.autostart import AutoStart

# ─── Tools ────────────────────────────────────────────────
from tools_integration.metasploit_rpc import MetasploitRPC
from tools_integration.burp_api import BurpAPI
from tools_integration.nuclei_manager import NucleiManager
from tools_integration.sliver_c2 import SliverC2
from tools_integration.auto_pivot import AutoPivot

# ─── Intelligence ─────────────────────────────────────────
from intelligence.rag_knowledge import get_rag
from intelligence.attack_graph import get_attack_graph
from intelligence.mitre_mapper import MITREMapper
from intelligence.scoring import VulnerabilityScorer
from intelligence.debate_agents import DebateOrchestrator, ReflexionAgent
from intelligence.cve_feed import CVEFeed
from intelligence.report_generator import get_reporter

# ─── Notifications (WhatsApp ONLY) ────────────────────────
from notifications.whatsapp_notifier import (
    get_whatsapp, send_whatsapp, send_finding_alert, send_critical_cve_alert,
)

# ─── Security ─────────────────────────────────────────────
from security.security_vault import SecurityVault

# ─── Scale ────────────────────────────────────────────────
from scale.distributed_scan import DistributedScanner

# ─── Teacher ──────────────────────────────────────────────
from teacher.hacking_teacher import get_teacher

console = Console()


BANNER = r"""
╔══════════════════════════════════════════════════════════════╗
║                                                              ║
║     CYBER JARVIS  v6.0                                       ║
║                                                              ║
║     Multi-Language | WhatsApp Alerts | Pro Reports          ║
║     Teacher + Attack + CVE + Auto-Start + Scope Guard       ║
║                                                              ║
╚══════════════════════════════════════════════════════════════╝
"""


# ═══════════════════════════════════════════════════════════════
#  SMART SCOPE (local allow + scope.txt + user confirm)
# ═══════════════════════════════════════════════════════════════

class SmartScope:
    """
    Combines:
      1. Local/private always allowed
      2. scope.txt strict check
      3. One-time user confirmation for public targets
    """

    def __init__(self):
        self.confirmed_targets = set()

    def is_local(self, target: str) -> bool:
        if target in ("127.0.0.1", "localhost", "::1"):
            return True
        host = target.split(":")[0].split("/")[0]
        try:
            ip = ipaddress.ip_address(host)
            return ip.is_private or ip.is_loopback
        except ValueError:
            return host.endswith((".local", ".lan", ".test", ".lab", ".htb"))

    def check(self, target: str):
        if not target:
            return True, "no target"

        # 1. Local — always allow
        if self.is_local(target):
            return True, "local/private target"

        # 2. Session-confirmed
        if target in self.confirmed_targets:
            return True, "already confirmed this session"

        # 3. scope.txt
        allowed, reason = validate_scope(target)
        if allowed:
            return True, reason

        # 4. Ask user (once per session)
        console.print(Panel(
            f"[bold yellow]⚠️  PUBLIC TARGET DETECTED[/bold yellow]\n\n"
            f"Target: [bold red]{target}[/bold red]\n\n"
            f"Written permission required.\n"
            f"Unauthorized access is CRIME:\n"
            f"  - Pakistan: PECA 2016\n"
            f"  - India: IT Act 2000\n"
            f"  - US: CFAA",
            border_style="red",
        ))

        try:
            if Confirm.ask("Do you have written permission?", default=False):
                self.confirmed_targets.add(target)
                return True, "user confirmed permission"
            return False, "user denied"
        except Exception:
            return False, "confirmation failed"


smart_scope = SmartScope()


# ═══════════════════════════════════════════════════════════════
#  JARVIS V6
# ═══════════════════════════════════════════════════════════════

class JarvisV6:
    def __init__(self, autostart_mode: bool = False):
        self.autostart_mode = autostart_mode
        self.tools_used = []
        self.last_state = None
        self.lang = get_language()

        # Vault (must be first — loads secrets into env)
        console.print("[cyan][*] Loading security vault...[/cyan]")
        self.vault = SecurityVault()
        if self.vault.is_ready():
            self.vault.load_all_env()

        # Kali
        console.print("[cyan][*] Connecting to Kali VM...[/cyan]")
        self.kali = KaliRemote()

        # RAG
        console.print("[cyan][*] Loading RAG...[/cyan]")
        self.rag = get_rag()

        # Graph
        console.print("[cyan][*] Attack graph...[/cyan]")
        self.graph = get_attack_graph()

        # Agents
        console.print("[cyan][*] Agents...[/cyan]")
        self.jarvis = JarvisOrchestrator()
        self.voice = VoiceInterface()
        self.debate = DebateOrchestrator()
        self.reflexion = ReflexionAgent()

        # Tools
        console.print("[cyan][*] Tools integration...[/cyan]")
        self.burp = BurpAPI()
        self.nuclei = NucleiManager()
        self.cve = CVEFeed()
        self.msf = MetasploitRPC()

        # Intelligence
        self.scorer = VulnerabilityScorer()
        self.mitre = MITREMapper()
        self.reporter = get_reporter()

        # C2 + Pivot
        self.sliver = SliverC2(kali=self.kali)
        self.pivot = AutoPivot(kali=self.kali)
        self.distributed = DistributedScanner()

        # WhatsApp
        console.print("[cyan][*] WhatsApp notifier...[/cyan]")
        self.whatsapp = get_whatsapp()

        # Teacher
        console.print("[cyan][*] Teacher...[/cyan]")
        self.teacher = get_teacher()

        # Wake word
        console.print("[cyan][*] Wake word...[/cyan]")
        self.wake = WakeWordDetector(on_wake=self._on_wake)

        # Proactive reminders
        self.proactive = ProactiveJarvis(
            voice_speak=lambda m: self.voice.speak(m) if self.voice else None
        )

    def _on_wake(self):
        """Wake word → listen for command."""
        self.voice.speak("Yes boss?")
        self.proactive.user_interacted()
        cmd = self.voice.listen_once()
        if cmd:
            self.handle_command(cmd)

    # ═══════════════════════════════════════════════════════
    #  COMMAND HANDLER
    # ═══════════════════════════════════════════════════════

    def handle_command(self, user: str):
        if not user or not user.strip():
            return

        low = user.lower().strip()
        self.proactive.user_interacted()

        # ── Exit ──
        if low in ("exit", "quit", "bye", "band karo", "sojao"):
            self.shutdown()
            return

        if low == "help":
            console.print(Panel(HELP_TEXT, border_style="cyan"))
            return

        if low in ("voice", "sunno", "bolo"):
            cmd = self.voice.listen_once()
            if cmd:
                self.handle_command(cmd)
            return

        # ── TEACHER ──
        if low.startswith(("teach", "sikhao", "seekh")):
            parts = user.split(maxsplit=1)
            if len(parts) < 2:
                self.teacher.show_curriculum()
                return
            self.teacher.interactive_lesson(parts[1].strip(), voice=self.voice)
            return

        if low in ("curriculum", "syllabus"):
            self.teacher.show_curriculum()
            return

        if low in ("progress", "meri progress"):
            self.teacher.progress_report()
            return

        if low.startswith("quiz "):
            topic = user[5:].strip()
            console.print(Panel(
                Markdown(self.teacher.quiz(topic)),
                title=f"Quiz: {topic}", border_style="yellow",
            ))
            return

        if low.startswith("lab "):
            topic = user[4:].strip()
            console.print(Panel(
                Markdown(self.teacher.build_lab(topic)),
                title=f"Lab: {topic}", border_style="cyan",
            ))
            return

        if low.startswith("path ") or low == "learning path":
            level = user.replace("path", "").replace("learning path", "").strip() or "beginner"
            console.print(Panel(
                Markdown(self.teacher.learning_path(level)),
                border_style="green",
            ))
            return

        if low.startswith("eli5 "):
            console.print(Panel(
                Markdown(self.teacher.explain_like_im_5(user[5:].strip())),
                border_style="cyan",
            ))
            return

        # ── LANGUAGE SWITCH ──
        if low in ("lang english", "language english"):
            CONFIG["language"] = "english"
            self.lang = "english"
            console.print("[green][+] Language: English[/green]")
            return

        if low in ("lang hinglish", "language hinglish"):
            CONFIG["language"] = "hinglish"
            self.lang = "hinglish"
            console.print("[green][+] Language: Hinglish[/green]")
            return

        if low in ("lang roman_urdu", "language roman_urdu", "lang urdu"):
            CONFIG["language"] = "roman_urdu"
            self.lang = "roman_urdu"
            console.print("[green][+] Language: Roman Urdu[/green]")
            return

        # ── AUTOSTART ──
        if low in ("autostart on", "auto on"):
            AutoStart.enable()
            return
        if low in ("autostart off", "auto off"):
            AutoStart.disable()
            return
        if low == "autostart status":
            console.print(
                f"Auto-start: {'✅ ON' if AutoStart.is_enabled() else '❌ OFF'}"
            )
            return

        # ── WHATSAPP ──
        if low == "whatsapp test":
            ok = self.whatsapp.test()
            console.print(
                f"[{'green' if ok else 'red'}]"
                f"WhatsApp test {'sent' if ok else 'failed'} "
                f"→ {CONFIG['whatsapp_number']}[/]"
            )
            return

        if low.startswith("whatsapp "):
            send_whatsapp(user[9:].strip())
            console.print("[green][+] WhatsApp sent[/green]")
            return

        # ── KALI ──
        if low.startswith("kali"):
            self._kali_cmd(user)
            return

        # ── SCAN / ATTACK (SCOPE ENFORCED) ──
        if low.startswith(("scan ", "hack ", "attack ", "test ")):
            parts = user.split(maxsplit=1)
            if len(parts) < 2:
                console.print("[yellow]Usage: scan <target>[/yellow]")
                return
            target = parts[1].strip()

            allowed, reason = smart_scope.check(target)
            if not allowed:
                console.print(f"[red]❌ Blocked: {reason}[/red]")
                return

            console.print(f"[green]✅ Scope OK: {reason}[/green]")
            self.run_full_attack(target)
            return

        if low.startswith("nmap "):
            target = user[5:].strip()
            allowed, reason = smart_scope.check(target)
            if not allowed:
                console.print(f"[red]❌ Blocked: {reason}[/red]")
                return
            self.tools_used.append("nmap")
            result = RemoteToolExecutor.execute(
                "nmap", ["-sV", "-T4", target], target
            )
            console.print(Panel(
                result.get("output", "")[:3000],
                border_style="cyan",
            ))
            return

        if low.startswith("nuclei "):
            target = user[7:].strip()
            allowed, reason = smart_scope.check(target)
            if not allowed:
                console.print(f"[red]❌ Blocked: {reason}[/red]")
                return
            self.tools_used.append("nuclei")
            result = self.nuclei.scan(target)
            console.print(f"[green]Findings: {result.get('total_findings', 0)}[/green]")
            return

        if low.startswith("burp "):
            target = user[5:].strip()
            allowed, reason = smart_scope.check(target)
            if not allowed:
                console.print(f"[red]❌ Blocked: {reason}[/red]")
                return
            self.tools_used.append("burpsuite")
            if not self.burp.is_ready():
                console.print("[red]Burp not ready[/red]")
                return
            result = self.burp.full_scan(target)
            console.print(f"[green]Issues: {result.get('total_issues', 0)}[/green]")
            return

        if low.startswith("msf "):
            self._msf_cmd(user)
            return

        # ── ANALYZE ──
        if low.startswith(("analyze ", "analyse ", "check code ")):
            path = user.split(maxsplit=1)[1].strip()
            result = self.jarvis.analyze_source(path)
            reflection = self.reflexion.reflect(
                task=f"Analyze {path}", output=result,
            )
            if reflection["needs_improvement"]:
                result = reflection["improved"]
            console.print(Panel(Markdown(result[:5000]), border_style="yellow"))
            return

        # ── CVE / NEWS ──
        if low.startswith("cve"):
            if "critical" in low:
                cves = self.cve.fetch_critical_cves(days=7)
                for c in cves[:5]:
                    send_critical_cve_alert(c)
            elif "search" in low:
                kw = user.replace("cve search", "").strip()
                cves = self.cve.search_cve(kw)
            else:
                cves = self.cve.fetch_recent_cves(days=7)
            self.cve.display_cves(cves)
            return

        if low in ("news", "khabar"):
            self.cve.display_news(self.cve.fetch_rss_news())
            return

        # ── GRAPH / MITRE / SCORING ──
        if low == "graph stats":
            console.print(self.graph.get_graph_stats())
            return

        if low == "mitre":
            if self.tools_used:
                self.mitre.print_heatmap(self.tools_used)
            else:
                console.print("[yellow]No tools used yet[/yellow]")
            return

        if low.startswith("score cve "):
            cve_id = user.replace("score cve", "").strip()
            console.print(self.scorer.prioritize(cve_id))
            return

        # ── RAG ──
        if low.startswith("rag "):
            console.print(Markdown(
                self.rag.build_context(user[4:].strip())[:3000]
            ))
            return

        if low == "rag ingest":
            from intelligence.knowledge_ingest import KnowledgeIngestor
            KnowledgeIngestor().ingest_all()
            return

        if low == "rag count":
            console.print(f"RAG docs: {self.rag.count()}")
            return

        # ── REPORT REGENERATE ──
        if low == "report":
            if not self.last_state:
                console.print("[yellow]No findings yet[/yellow]")
                return
            findings = self.last_state.get("findings", [])
            target = self.last_state.get("target", "")
            report_file = self.reporter.generate_full_report(target, findings)
            console.print(f"[green]Report: {report_file}[/green]")
            return

        # ── MISC ──
        if low == "findings":
            self._show_findings()
            return
        if low == "tools":
            self._show_tools()
            return
        if low == "health":
            health_check(verbose=True)
            return
        if low == "install-critical":
            install_critical()
            return
        if low == "dashboard":
            import subprocess
            subprocess.Popen([
                "streamlit", "run",
                str(ROOT / "interface" / "streamlit_dashboard.py"),
            ])
            console.print("[green]Dashboard: http://localhost:8501[/green]")
            return
        if low == "agents":
            console.print(Panel(
                "AgentZero · Hermes · XBow · OpenClaw — active",
                border_style="green",
            ))
            return

        if low.startswith("debate "):
            q = user[7:].strip()
            options = [o.strip() for o in q.split("|") if o.strip()]
            if len(options) >= 2:
                result = self.debate.debate("Which is best?", options)
                console.print(Panel(
                    f"Winner: {result['winner'][:150]}",
                    border_style="green",
                ))
            else:
                console.print("[yellow]Usage: debate opt1 | opt2 | opt3[/yellow]")
            return

        # ── CHAT FALLBACK ──
        rag_ctx = self.rag.build_context(user, k=3)
        learning_kw = (
            "kya", "kaise", "how", "what", "why", "explain",
            "samjhao", "sikhao", "batao", "difference",
        )
        is_learning = any(k in low for k in learning_kw)

        if is_learning:
            response = self.teacher.think(
                f"Student question: {user}\n\n"
                f"Reference: {rag_ctx[:2000]}\n\n"
                f"Answer in teaching style in {self.lang}."
            )
        else:
            response = self.jarvis.openclaw.think(user, extra_context=rag_ctx)

        console.print(Panel(Markdown(response), border_style="green"))
        self.voice.speak(response[:200])

    # ═══════════════════════════════════════════════════════
    #  FULL ATTACK
    # ═══════════════════════════════════════════════════════

    def run_full_attack(self, target: str):
        console.print(Panel(
            f"[bold red]🎯 FULL ATTACK: {target}[/bold red]\n"
            f"Phases: Recon → Scan → Exploit → Post → Report",
            border_style="red",
        ))

        self.graph.add_host(ip=target)

        # Run Jarvis agents
        self.last_state = self.jarvis.run_mission(target)
        findings = self.last_state.get("findings", [])

        # Score
        enriched = self.scorer.score_findings(findings)

        # WhatsApp notify
        for f in enriched:
            sev = (f.get("severity") or "").lower()
            if sev in ("critical", "high"):
                send_finding_alert(f, target)

        # Report
        if findings:
            report_file = self.reporter.generate_full_report(target, findings)
            console.print(f"[green]Report: {report_file}[/green]")

            critical_count = sum(
                1 for f in findings
                if (f.get("severity") or "").lower() == "critical"
            )
            self.whatsapp.send_mission_summary(
                target, len(findings), critical_count
            )

        console.print(f"\n[green]✅ Mission complete: {len(findings)} findings[/green]")
        self.voice.speak(f"Mission complete. {len(findings)} findings.")

    # ═══════════════════════════════════════════════════════
    #  SUB-COMMANDS
    # ═══════════════════════════════════════════════════════

    def _kali_cmd(self, user: str):
        low = user.lower()
        parts = user.split()
        if len(parts) == 1 or "status" in low:
            info = self.kali.get_system_info()
            console.print(Panel(
                "\n".join(f"{k}: {v}" for k, v in info.items()),
                title="Kali VM", border_style="green",
            ))
        elif "install" in low:
            self.kali.auto_install(parts[-1])
        elif "start-msf" in low:
            self.kali.start_msfrpcd()

    def _msf_cmd(self, user: str):
        parts = user.split()
        if len(parts) >= 3 and parts[1] == "search":
            self.tools_used.append("metasploit")
            console.print(self.msf.list_exploits(parts[2])[:20])
        elif len(parts) >= 3 and parts[1] == "exploit":
            module = parts[2]
            rhosts = parts[3] if len(parts) > 3 else ""
            allowed, reason = smart_scope.check(rhosts)
            if not allowed:
                console.print(f"[red]Blocked: {reason}[/red]")
                return
            result = self.msf.run_exploit(module, {"RHOSTS": rhosts})
            console.print(result)
        elif len(parts) >= 2 and parts[1] == "sessions":
            console.print(self.msf.list_sessions())
        else:
            console.print("[yellow]Usage: msf search/exploit/sessions[/yellow]")

    def _show_findings(self):
        if not self.last_state:
            console.print("[yellow]No findings[/yellow]")
            return
        findings = self.last_state.get("findings", [])
        if not findings:
            console.print("[yellow]No findings[/yellow]")
            return
        t = Table(title="Findings")
        t.add_column("Severity")
        t.add_column("Finding")
        for f in findings:
            t.add_row(
                f.get("severity", "?"),
                (f.get("finding") or "?")[:60],
            )
        console.print(t)

    def _show_tools(self):
        t = Table(title=f"Kali Tools Database ({get_tool_count()})")
        t.add_column("Category")
        t.add_column("Count")
        for cat, tools in KALI_TOOLS.items():
            t.add_row(cat, str(len(tools)))
        console.print(t)

    # ═══════════════════════════════════════════════════════
    #  RUN
    # ═══════════════════════════════════════════════════════

    def run(self):
        console.print(Panel(BANNER, border_style="red"))
        console.print(f"[bold]Language: {self.lang}[/bold]")
        console.print(f"[bold]WhatsApp: {CONFIG['whatsapp_number']}[/bold]")

        status = {
            "Kali SSH": self.kali.is_ready(),
            "RAG": self.rag.count() > 0,
            "Neo4j": self.graph.is_ready(),
            "Burp": self.burp.is_ready(),
            "Metasploit": self.msf.is_ready(),
            "WhatsApp": self.whatsapp.is_available(),
            "Voice": bool(self.voice.tts_engine) if self.voice else False,
            "Wake Word": self.wake.is_available(),
            "Auto-Start": AutoStart.is_enabled(),
        }

        t = Table(title="System Status")
        t.add_column("Service")
        t.add_column("Status")
        for k, v in status.items():
            t.add_row(k, "[green]✅ Ready[/green]" if v else "[red]❌ Off[/red]")
        console.print(t)

        self.wake.start()
        self.proactive.start()

        if not self.autostart_mode:
            self.proactive.greet_on_start()
        else:
            self.voice.speak("Jarvis online. Aaj kya karna hai?")

        console.print(Panel(HELP_TEXT, title="Commands", border_style="cyan"))

        while True:
            try:
                console.print("\n[bold cyan]You:[/bold cyan] ", end="")
                user = input().strip()
                self.handle_command(user)
            except KeyboardInterrupt:
                console.print("\n[yellow]Ctrl+C — type 'exit' to quit[/yellow]")
            except EOFError:
                break
            except Exception as e:
                console.print(f"[red]Error: {e}[/red]")

    def shutdown(self):
        self.voice.speak("Goodbye boss!")
        self.proactive.stop()
        self.wake.stop()
        if self.kali:
            self.kali.close()
        console.print("[yellow]👋 Jarvis signing off...[/yellow]")
        sys.exit(0)


HELP_TEXT = """
## 🎓 LEARN
`teach <topic>`       Lesson + quiz
`curriculum`          Full syllabus
`progress`            Your progress
`quiz <topic>`        Practice quiz
`lab <topic>`         Lab setup
`path beginner`       30-day plan
`eli5 <topic>`        Explain simply

## 🎯 ATTACK
`scan <target>`       Full autonomous attack
`nmap <target>`       Port scan
`nuclei <target>`     Vuln scan
`burp <target>`       Burp scan
`msf search <kw>`     Metasploit search
`analyze <path>`      Code analysis
`report`              Regenerate report

## 🌐 LANGUAGE
`lang english`        Switch to English
`lang hinglish`       Switch to Hinglish
`lang roman_urdu`     Switch to Roman Urdu

## 📱 WHATSAPP (only)
`whatsapp test`       Send test message
`whatsapp <msg>`      Custom message

## 📰 NEWS & INTEL
`cve` `cve critical` `cve search <kw>` `news`
`mitre` `graph stats` `score cve <id>`

## ⚙️ SYSTEM
`autostart on/off`    Boot auto-launch
`voice` `kali status` `kali install <tool>`
`findings` `tools` `health` `dashboard`
`rag <query>` `rag ingest` `rag count`
`agents` `exit`

## 📊 REPORT FORMAT (English only)
Title → Description → Severity → PoC (screenshots + curl)
→ Steps to Reproduce → Business Impact → Recommendation
"""


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("--autostart", action="store_true")
    parser.add_argument("--companion", action="store_true")
    args = parser.parse_args()

    if not CONFIG["deepseek_api_key"]:
        console.print(Panel(
            "[red]DEEPSEEK_API_KEY missing![/red]\n"
            "PowerShell: $env:DEEPSEEK_API_KEY='sk-...'",
            border_style="red",
        ))
        return

    jarvis = JarvisV6(autostart_mode=args.autostart or args.companion)

    if args.companion:
        while True:
            try:
                jarvis.run()
            except SystemExit:
                break
            except Exception as e:
                console.print(f"[red]Crash: {e}[/red]")
                time.sleep(10)
                jarvis = JarvisV6(autostart_mode=True)
    else:
        jarvis.run()


if __name__ == "__main__":
    main()