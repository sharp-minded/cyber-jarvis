"""
interface/proactive_jarvis.py - Auto reminders (language-aware)

FIX: Quiet hours logic corrected. Thread-safe singleton.
"""

import time
import threading
import random
from datetime import datetime
from typing import Callable
from rich.console import Console
from rich.panel import Panel

from core.config import get_language

console = Console()


# ─── Multi-language prompts ────────────────────────────────
PROMPTS = {
    "english": [
        "Boss, what should we learn today?",
        "Any new target to test?",
        "Should I check CVE news?",
        "Which tool do you want to learn?",
        "Ready! What's the plan?",
        "Should we practice a lab today?",
    ],
    "hinglish": [
        "Boss, aaj kya seekhna hai?",
        "Aaj koi target test karna hai?",
        "CVE news check karun?",
        "Konsa tool seekhna hai aaj?",
        "Ready hoon! Kya karna hai?",
        "Aaj koi lab practice karni hai?",
    ],
    "roman_urdu": [
        "Boss, aaj kya seekhna hai?",
        "Aaj koi target test karna hai?",
        "CVE news check karun?",
        "Kaunsa tool seekhna hai?",
        "Tayyar hoon! Kya karna hai?",
        "Aaj koi lab practice karni hai?",
    ],
}

MOTIVATION = {
    "english": [
        "Recon is 90% of the work.",
        "Understanding > Exploitation.",
        "Failing in lab is fine.",
        "First rule of ethical hacking: permission.",
        "Practice daily, it's a marathon.",
        "Automate the boring, master the complex.",
    ],
    "hinglish": [
        "Recon 90% kaam hai. Skip mat karo.",
        "Understanding > Exploitation.",
        "Lab mein fail hona theek hai.",
        "Ethical hacking ka pehla rule: Permission.",
        "Roz practice karo, marathon hai.",
        "Boring kaam automate karo, mushkil khud karo.",
    ],
    "roman_urdu": [
        "Recon 90% kaam hai.",
        "Samajhna zyada zaroori hai.",
        "Lab mein fail hona theek hai.",
        "Pehla rule: Permission.",
        "Roz practice karo.",
        "Boring kaam automate karo.",
    ],
}


class ProactiveJarvis:
    """Background thread that reminds user periodically."""

    def __init__(self, voice_speak: Callable[[str], None] = None):
        self.voice_speak = voice_speak
        self.running = False
        self.thread = None
        self.last_interaction = time.time()
        self.reminder_interval = 1800  # 30 min
        self.check_interval = 60       # check every 1 min
        self.quiet_start = 23          # 11 PM
        self.quiet_end = 7             # 7 AM
        self.lang = get_language()

        # FIX: proper lock for thread safety
        self._lock = threading.Lock()

    def start(self):
        if self.running:
            return
        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        console.print("[green][+] Proactive Jarvis active[/green]")

    def stop(self):
        self.running = False
        if self.thread:
            self.thread.join(timeout=3)

    def _is_quiet_hours(self) -> bool:
        """FIXED quiet hours logic."""
        h = datetime.now().hour
        # Quiet: 23:00 → 07:00 (crosses midnight)
        if self.quiet_start < self.quiet_end:
            return self.quiet_start <= h < self.quiet_end
        else:
            # Crosses midnight (e.g., 23 → 7)
            return h >= self.quiet_start or h < self.quiet_end

    def _loop(self):
        while self.running:
            try:
                time.sleep(self.check_interval)

                if self._is_quiet_hours():
                    continue

                with self._lock:
                    elapsed = time.time() - self.last_interaction

                if elapsed >= self.reminder_interval:
                    self._send_reminder()
                    with self._lock:
                        self.last_interaction = time.time()

            except Exception as e:
                console.print(f"[red]Proactive error: {e}[/red]")
                time.sleep(60)

    def _send_reminder(self):
        prompts = PROMPTS.get(self.lang, PROMPTS["english"])
        prompt = random.choice(prompts)

        console.print(Panel(
            f"[bold yellow]{prompt}[/bold yellow]",
            title="🤖 Jarvis",
            border_style="yellow",
        ))

        if self.voice_speak:
            try:
                self.voice_speak(prompt)
            except Exception:
                pass

    def user_interacted(self):
        """Reset reminder timer."""
        with self._lock:
            self.last_interaction = time.time()

    def greet_on_start(self):
        """Greeting at startup (language-aware)."""
        h = datetime.now().hour

        if self.lang == "english":
            if h < 12:
                t = "Good morning"
            elif h < 17:
                t = "Good afternoon"
            else:
                t = "Good evening"
            greet = f"{t} boss! Jarvis ready. What's the plan?"
        elif self.lang == "hinglish":
            if h < 12:
                t = "Good morning"
            elif h < 17:
                t = "Good afternoon"
            else:
                t = "Good evening"
            greet = f"{t} boss! Jarvis ready. Aaj kya karna hai?"
        else:  # roman_urdu
            greet = "Assalam o alaikum boss! Jarvis tayyar hai. Aaj kya karna hai?"

        motivation = random.choice(MOTIVATION.get(self.lang, MOTIVATION["english"]))

        console.print(Panel(
            f"[bold green]{greet}[/bold green]\n\n"
            f"[cyan]💡 {motivation}[/cyan]",
            title="🤖 Jarvis Online",
            border_style="green",
        ))

        if self.voice_speak:
            try:
                self.voice_speak(greet)
            except Exception:
                pass