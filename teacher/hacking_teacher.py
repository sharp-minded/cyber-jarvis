"""
teacher/hacking_teacher.py - Complete hacking course (multi-language)

FIX: Language-aware responses. Progress file handle corrupt-safe.
"""

import json
from pathlib import Path
from typing import Dict, Optional
from rich.console import Console
from rich.panel import Panel
from rich.markdown import Markdown
from rich.table import Table

from core.config import CONFIG, get_language
from core.agents import BaseAgent
from intelligence.rag_knowledge import get_rag

console = Console()


class HackingTeacher(BaseAgent):
    """Ethical hacking teacher with curriculum + labs + quizzes."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, "_initialized"):
            return
        self._initialized = True

        super().__init__(
            "Teacher",
            """You are an expert ethical hacking teacher.
Teach from absolute beginner to advanced level.

Style:
- Simple language with real examples
- Explain WHY before HOW
- Give hands-on commands (LAB ONLY!)
- Warn about legal boundaries
- Use analogies
- Quiz at end of each lesson
- Recommend labs (DVWA, HTB, TryHackMe, PortSwigger)

Format for lessons:
## Concept
## Why It Matters
## How It Works
## Hands-On (lab only)
## Practice Lab
## Quiz
## Next Steps

IMPORTANT: Respond in the user's configured language
(English / Hinglish / Roman Urdu).
""",
        )

        self.rag = get_rag()
        self.progress_file = CONFIG["workspace"] / "learning_progress.json"
        self.progress = self._load_progress()

    def _load_progress(self) -> Dict:
        """Safe progress load (corrupt-file resistant)."""
        if not self.progress_file.exists():
            return {"completed_lessons": [], "current_topic": "", "quiz_scores": {}}
        try:
            data = json.loads(self.progress_file.read_text())
            # Validate schema
            data.setdefault("completed_lessons", [])
            data.setdefault("current_topic", "")
            data.setdefault("quiz_scores", {})
            return data
        except Exception:
            console.print("[yellow][!] Progress file corrupt — resetting[/yellow]")
            return {"completed_lessons": [], "current_topic": "", "quiz_scores": {}}

    def _save_progress(self):
        try:
            self.progress_file.write_text(
                json.dumps(self.progress, indent=2, ensure_ascii=False)
            )
        except Exception as e:
            console.print(f"[yellow]Progress save failed: {e}[/yellow]")

    # ─── Curriculum ───────────────────────────────────────

    CURRICULUM = {
        "Level 1: Foundations": [
            "networking", "linux", "windows", "python",
            "web-basics", "crypto-basics", "http-https",
        ],
        "Level 2: Reconnaissance": [
            "osint", "dns-recon", "subdomain-enum",
            "port-scanning", "service-enum", "google-dorking",
        ],
        "Level 3: Web Hacking": [
            "burp", "sqli", "xss", "csrf", "ssrf",
            "lfi", "rfi", "idor", "xxe", "ssti", "jwt",
        ],
        "Level 4: System Hacking": [
            "metasploit", "exploit-dev", "buffer-overflow",
            "privesc-linux", "privesc-windows",
        ],
        "Level 5: Network Attacks": [
            "arp-spoofing", "mitm", "dns-spoofing",
            "wifi-hacking", "wireshark", "responder", "pivot",
        ],
        "Level 6: Active Directory": [
            "ad-basics", "kerberos", "bloodhound", "mimikatz",
            "crackmapexec", "lateral-movement",
        ],
        "Level 7: Cloud & Container": [
            "aws-security", "azure-security", "k8s-security", "docker-escape",
        ],
        "Level 8: Advanced": [
            "reverse-engineering", "malware-analysis",
            "fuzzing", "red-team-ops", "c2-frameworks",
        ],
    }

    # ─── Teaching Methods ─────────────────────────────────

    def teach(self, topic: str) -> str:
        """Full lesson on a topic."""
        console.print(f"[cyan][*] Preparing lesson: {topic}[/cyan]")

        rag_ctx = self.rag.build_context(f"{topic} tutorial hacking", k=5)

        prompt = f"""
Teach me: {topic}

Reference material from knowledge base:
{rag_ctx[:4000]}

Provide a complete lesson with:
1. Concept (simple explanation)
2. Real-world example
3. Technical deep-dive
4. Hands-on commands (LAB only!)
5. Practice lab recommendation
6. Quiz (3 questions)
7. Next topic recommendation
"""
        response = self.think(prompt)

        # Track progress
        if topic not in self.progress["completed_lessons"]:
            self.progress["completed_lessons"].append(topic)
        self.progress["current_topic"] = topic
        self._save_progress()

        return response

    def quiz(self, topic: str, num_questions: int = 5) -> str:
        return self.think(
            f"Generate a {num_questions}-question multiple-choice quiz on: {topic}\n"
            f"Format each question as:\n"
            f"Q1. <question>\n"
            f"  a) ...\n  b) ...\n  c) ...\n  d) ...\n\n"
            f"Provide answers at the end in a separate section."
        )

    def explain_like_im_5(self, topic: str) -> str:
        return self.think(f"Explain {topic} to a 5-year-old. Use simple analogies.")

    def build_lab(self, topic: str) -> str:
        return self.think(
            f"Create a safe practice lab for learning: {topic}\n\n"
            f"Include:\n"
            f"1. Required tools\n"
            f"2. Vulnerable VM to download (DVWA, Metasploitable2, etc.)\n"
            f"3. Setup steps\n"
            f"4. Exercises with increasing difficulty\n"
            f"5. Success criteria\n\n"
            f"IMPORTANT: Emphasize ISOLATED VM environment only."
        )

    def learning_path(self, level: str = "beginner") -> str:
        return self.think(
            f"I am a {level} in ethical hacking.\n\n"
            f"Create a 30-day learning plan covering:\n"
            f"- Daily topics\n"
            f"- Time commitment (2 hours/day)\n"
            f"- Milestones\n"
            f"- Recommended labs\n"
            f"- Resources\n\n"
            f"Make it practical and hands-on."
        )

    # ─── Display ──────────────────────────────────────────

    def show_curriculum(self):
        table = Table(title="🎓 Ethical Hacking Curriculum")
        table.add_column("Level", style="cyan", no_wrap=True)
        table.add_column("Topics", style="yellow")

        for level, topics in self.CURRICULUM.items():
            table.add_row(level, ", ".join(topics))

        console.print(table)
        completed = len(self.progress.get("completed_lessons", []))
        total = sum(len(t) for t in self.CURRICULUM.values())
        console.print(
            f"\n[green]Completed: {completed}/{total} topics[/green]"
        )
        console.print(
            f"[cyan]Current focus: "
            f"{self.progress.get('current_topic', 'None')}[/cyan]"
        )

    def progress_report(self):
        completed = self.progress.get("completed_lessons", [])
        total = sum(len(t) for t in self.CURRICULUM.values())
        pct = (len(completed) / total * 100) if total else 0

        recent = completed[-10:] if completed else []

        console.print(Panel(
            f"Topics completed: {len(completed)}/{total}\n"
            f"Progress: {pct:.1f}%\n"
            f"Current focus: {self.progress.get('current_topic', 'None')}\n\n"
            + (
                "Recent topics:\n" + "\n".join(f"  ✓ {t}" for t in recent)
                if recent else "No topics completed yet."
            ),
            title="📊 Your Learning Progress",
            border_style="green",
        ))

    # ─── Interactive ──────────────────────────────────────

    def interactive_lesson(self, topic: str, voice=None):
        """Interactive lesson with Q&A and quiz."""
        lesson = self.teach(topic)
        console.print(Panel(
            Markdown(lesson),
            title=f"📚 Lesson: {topic}",
            border_style="cyan",
        ))

        if voice:
            voice.speak(f"Lesson on {topic} ready.")

        # Q&A loop
        console.print("\n[cyan]Koi sawaal hai? ('next' for quiz, 'skip' to exit)[/cyan]")
        while True:
            try:
                q = input("> ").strip()
                if not q:
                    continue
                if q.lower() in ["next", "quiz"]:
                    break
                if q.lower() in ["skip", "exit", "done", "quit"]:
                    return

                # Answer using RAG
                rag_ctx = self.rag.build_context(q, k=3)
                answer = self.think(
                    f"Student question about {topic}: {q}\n\n"
                    f"Context: {rag_ctx[:2000]}\n\n"
                    f"Answer clearly and simply in the configured language."
                )
                console.print(Panel(Markdown(answer), border_style="green"))

            except (KeyboardInterrupt, EOFError):
                return

        # Quiz
        console.print("\n[cyan]📝 Quiz time![/cyan]")
        quiz = self.quiz(topic)
        console.print(Panel(Markdown(quiz), title="Quiz", border_style="yellow"))


# ─── Singleton ────────────────────────────────────────────

def get_teacher() -> HackingTeacher:
    return HackingTeacher()