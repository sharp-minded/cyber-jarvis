"""
notifications/whatsapp_notifier.py - WhatsApp notifications ONLY

Target: +92 3132985274 (from .env WHATSAPP_NUMBER)

Methods:
  1. pywhatkit  — free, requires WhatsApp Web logged in browser
  2. twilio     — paid, reliable (WhatsApp Business API)

FIX: Removed Telegram/Slack/Discord. WhatsApp is single channel.
"""

import os
import time
import threading
from typing import Dict, Optional

from rich.console import Console

from core.config import CONFIG

console = Console()

# ─── Backends ─────────────────────────────────────────────
try:
    import pywhatkit
    PYWHATKIT_AVAILABLE = True
except ImportError:
    PYWHATKIT_AVAILABLE = False

try:
    from twilio.rest import Client as TwilioClient
    TWILIO_AVAILABLE = True
except ImportError:
    TWILIO_AVAILABLE = False


class WhatsAppNotifier:
    """Send WhatsApp messages to configured number."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, "_initialized"):
            return
        self._initialized = True

        self.number = CONFIG["whatsapp_number"]
        self.method = CONFIG["whatsapp_method"].lower()
        self.twilio_sid = CONFIG["twilio_account_sid"]
        self.twilio_token = CONFIG["twilio_auth_token"]
        self.twilio_from = CONFIG["twilio_whatsapp_from"]

        # Lock for thread-safe sends
        self._lock = threading.Lock()

        console.print(
            f"[cyan][*] WhatsApp notifier initialized → "
            f"{self.number} (method: {self.method})[/cyan]"
        )

    def is_available(self) -> bool:
        if self.method == "pywhatkit":
            return PYWHATKIT_AVAILABLE
        if self.method == "twilio":
            return (
                TWILIO_AVAILABLE
                and bool(self.twilio_sid)
                and bool(self.twilio_token)
            )
        return False

    # ─── Public Send ──────────────────────────────────────

    def send(self, message: str) -> bool:
        """Send a WhatsApp message."""
        if not message or not message.strip():
            return False

        if not self.is_available():
            console.print(
                f"[yellow][!] WhatsApp not available "
                f"(method={self.method})[/yellow]"
            )
            return False

        with self._lock:
            if self.method == "twilio":
                return self._send_twilio(message)
            return self._send_pywhatkit(message)

    # ─── Backends ─────────────────────────────────────────

    def _send_pywhatkit(self, message: str) -> bool:
        """Send via pywhatkit (opens WhatsApp Web)."""
        try:
            import datetime
            now = datetime.datetime.now()
            send_time = now + datetime.timedelta(minutes=2)

            # pywhatkit wants number WITHOUT + but WITH country code
            raw = self.number.replace("+", "").replace(" ", "").replace("-", "")

            console.print(
                f"[cyan][*] WhatsApp via pywhatkit → +{raw} "
                f"at {send_time.strftime('%H:%M:%S')}[/cyan]"
            )

            pywhatkit.sendwhatmsg(
                f"+{raw}",
                message[:1500],
                send_time.hour,
                send_time.minute,
                wait_time=20,
                tab_close=True,
            )
            console.print("[green][+] WhatsApp sent (pywhatkit)[/green]")
            return True
        except Exception as e:
            console.print(f"[red]pywhatkit failed: {e}[/red]")
            return False

    def _send_twilio(self, message: str) -> bool:
        """Send via Twilio WhatsApp Business API."""
        try:
            client = TwilioClient(self.twilio_sid, self.twilio_token)

            # Format: whatsapp:+923132985274
            to_number = self.number
            if not to_number.startswith("whatsapp:"):
                to_number = f"whatsapp:{to_number}"

            msg = client.messages.create(
                from_=self.twilio_from,
                body=message[:1600],
                to=to_number,
            )
            console.print(f"[green][+] WhatsApp sent (Twilio SID: {msg.sid})[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Twilio failed: {e}[/red]")
            return False

    # ─── High-level Helpers ───────────────────────────────

    def send_finding(self, finding: Dict, target: str = "") -> bool:
        """Send finding alert."""
        severity = (finding.get("severity") or "Info").upper()
        title = finding.get("finding") or finding.get("title") or "Unknown"

        emoji = {
            "CRITICAL": "🔴",
            "HIGH": "🟠",
            "MEDIUM": "🟡",
            "LOW": "🟢",
            "INFO": "🔵",
        }.get(severity, "⚪")

        message = f"""{emoji} *CYBER JARVIS ALERT* {emoji}

*Finding*: {title}
*Severity*: {severity}
*Target*: {target or finding.get('target', 'N/A')}

*Evidence*:
{(finding.get('evidence') or '')[:400]}

*Recommendation*:
{(finding.get('remediation') or 'Review and patch immediately.')[:300]}

_Report generated in workspace/reports/_
"""
        return self.send(message)

    def send_critical_cve(self, cve: Dict) -> bool:
        """Send critical CVE alert."""
        refs = "\n".join(cve.get("references", [])[:3])

        message = f"""🔴 *CRITICAL CVE ALERT* 🔴

*CVE ID*: {cve.get('id', 'N/A')}
*CVSS*: {cve.get('cvss_score', 'N/A')}
*Severity*: {cve.get('severity', 'CRITICAL')}

*Description*:
{cve.get('description', '')[:500]}

*References*:
{refs}

_Patch immediately if applicable._
"""
        return self.send(message)

    def send_mission_summary(
        self,
        target: str,
        findings_count: int,
        critical: int = 0,
    ) -> bool:
        """Send mission completion summary."""
        message = f"""✅ *MISSION COMPLETE*

*Target*: {target}
*Total Findings*: {findings_count}
*Critical*: {critical}

_Report available in workspace/reports/_

Stay secure! 🛡️
"""
        return self.send(message)

    def send_custom(self, title: str, body: str) -> bool:
        """Send custom message."""
        return self.send(f"*{title}*\n\n{body}")

    def send_daily_digest(self, cve_count: int, news_count: int) -> bool:
        """Send daily digest."""
        message = f"""📰 *DAILY SECURITY DIGEST*

🔴 Critical CVEs: {cve_count}
📡 News Articles: {news_count}

_Ask Jarvis for details._
"""
        return self.send(message)

    def test(self) -> bool:
        """Send test message."""
        msg = (
            f"🔔 *Cyber Jarvis Test*\n\n"
            f"Time: {time.strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"Backend: {self.method}\n"
            f"Status: Working ✅"
        )
        return self.send(msg)


# ─── Module-level helpers ─────────────────────────────────

def get_whatsapp() -> WhatsAppNotifier:
    return WhatsAppNotifier()


def send_whatsapp(message: str) -> bool:
    """Quick send."""
    return WhatsAppNotifier().send(message)


def send_finding_alert(finding: Dict, target: str = "") -> bool:
    return WhatsAppNotifier().send_finding(finding, target)


def send_critical_cve_alert(cve: Dict) -> bool:
    return WhatsAppNotifier().send_critical_cve(cve)


# ─── CLI test ─────────────────────────────────────────────

if __name__ == "__main__":
    notifier = WhatsAppNotifier()
    console.print(f"Available: {notifier.is_available()}")
    console.print(f"Number: {notifier.number}")
    console.print(f"Method: {notifier.method}")
    notifier.test()