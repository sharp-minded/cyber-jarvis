"""
interface/voice_interface.py - Voice I/O for Windows

FIX: voicepipe (hallucinated) → SpeechRecognition + pyttsx3
FIX: Mic enumeration safe + NoneType.close() bug fix
Multi-language STT support.
"""

import threading
from typing import Optional
from rich.console import Console
from core.config import CONFIG, get_language

console = Console()

# ─── Real voice libraries ──────────────────────────────────
try:
    import pyttsx3
    TTS_AVAILABLE = True
except ImportError:
    TTS_AVAILABLE = False

try:
    import speech_recognition as sr
    STT_AVAILABLE = True
except ImportError:
    STT_AVAILABLE = False


# Language code mapping for Google STT
STT_LANG_MAP = {
    "english": "en-US",
    "hinglish": "en-IN",
    "roman_urdu": "en-IN",
}


class VoiceInterface:
    """Windows-native voice interface (TTS + STT)."""

    def __init__(self):
        self.tts_engine = None
        self.recognizer = None
        self.mic = None
        self.lang = get_language()

        # ─── TTS init ──────────────────────────────────────
        if TTS_AVAILABLE:
            try:
                self.tts_engine = pyttsx3.init()
                self.tts_engine.setProperty("rate", CONFIG["voice_tts_rate"])

                # Pick English voice
                for v in self.tts_engine.getProperty("voices"):
                    if "english" in v.name.lower():
                        self.tts_engine.setProperty("voice", v.id)
                        break

                console.print("[green][+] TTS ready[/green]")
            except Exception as e:
                console.print(f"[yellow][!] TTS init failed: {e}[/yellow]")
                self.tts_engine = None
        else:
            console.print("[yellow][!] pyttsx3 not installed — TTS disabled[/yellow]")

        # ─── STT init ──────────────────────────────────────
        if STT_AVAILABLE:
            try:
                self.recognizer = sr.Recognizer()

                # Safe mic enumeration
                try:
                    mic_list = sr.Microphone.list_microphone_names()
                except Exception:
                    mic_list = []

                if not mic_list:
                    console.print("[yellow][!] No microphone detected — STT disabled[/yellow]")
                    self.recognizer = None
                    self.mic = None
                else:
                    # Pick first available mic
                    try:
                        self.mic = sr.Microphone(device_index=0)
                        with self.mic as source:
                            self.recognizer.adjust_for_ambient_noise(source, duration=1)
                        console.print(
                            f"[green][+] STT ready (mic: {mic_list[0]})[/green]"
                        )
                    except Exception as e:
                        console.print(f"[yellow][!] Mic calibration failed: {e}[/yellow]")
                        self.recognizer = None
                        self.mic = None

            except Exception as e:
                console.print(f"[yellow][!] STT init failed: {e}[/yellow]")
                self.recognizer = None
                self.mic = None
        else:
            console.print("[yellow][!] SpeechRecognition not installed — STT disabled[/yellow]")

    # ─── TTS ───────────────────────────────────────────────

    def speak(self, text: str):
        """Speak in background thread (non-blocking)."""
        if not self.tts_engine:
            return

        def _speak():
            try:
                self.tts_engine.say(text[:400])
                self.tts_engine.runAndWait()
            except Exception as e:
                console.print(f"[yellow]TTS error: {e}[/yellow]")

        threading.Thread(target=_speak, daemon=True).start()

    # ─── STT ───────────────────────────────────────────────

    def listen_once(self, timeout: int = 8) -> Optional[str]:
        """Listen once and return recognized text."""
        if not self.recognizer or not self.mic:
            return None

        try:
            console.print("[cyan]🎤 Listening...[/cyan]")
            with self.mic as source:
                audio = self.recognizer.listen(
                    source,
                    timeout=timeout,
                    phrase_time_limit=15,
                )

            lang_code = STT_LANG_MAP.get(self.lang, "en-US")
            console.print("[yellow]Recognizing...[/yellow]")
            text = self.recognizer.recognize_google(audio, language=lang_code)
            console.print(f"[green]You (voice): {text}[/green]")
            return text

        except sr.WaitTimeoutError:
            console.print("[dim]No speech detected[/dim]")
            return None
        except sr.UnknownValueError:
            console.print("[dim]Could not understand audio[/dim]")
            return None
        except Exception as e:
            console.print(f"[red]Voice error: {e}[/red]")
            return None

    def is_available(self) -> bool:
        return bool(self.tts_engine) or bool(self.recognizer)