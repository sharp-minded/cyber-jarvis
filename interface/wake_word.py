"""
interface/wake_word.py - 'Hey Jarvis' wake word via Porcupine

Uses pvporcupine (Picovoice). Free key: https://console.picovoice.ai/
"""

import os
import threading
import time
from typing import Callable
from rich.console import Console

console = Console()

try:
    import pvporcupine
    import pyaudio
    import struct
    PORCUPINE_AVAILABLE = True
except ImportError:
    PORCUPINE_AVAILABLE = False
    console.print("[yellow][!] pvporcupine not installed — wake word disabled[/yellow]")


class WakeWordDetector:
    """Background wake word detection thread."""

    def __init__(self, on_wake: Callable[[], None]):
        self.on_wake = on_wake
        self.access_key = os.getenv("PORCUPINE_ACCESS_KEY", "").strip()
        self.running = False
        self.thread = None

        # Resources (cleaned on stop)
        self._porcupine = None
        self._pa = None
        self._stream = None

    def is_available(self) -> bool:
        return PORCUPINE_AVAILABLE and bool(self.access_key)

    def start(self):
        """Start background thread."""
        if not self.is_available():
            console.print("[yellow][!] Wake word disabled "
                          "(set PORCUPINE_ACCESS_KEY)[/yellow]")
            return
        if self.running:
            return

        self.running = True
        self.thread = threading.Thread(target=self._loop, daemon=True)
        self.thread.start()
        console.print("[green][+] Wake word 'Hey Jarvis' active[/green]")

    def _loop(self):
        try:
            self._porcupine = pvporcupine.create(
                access_key=self.access_key,
                keywords=["jarvis"],
                sensitivities=[0.5],
            )

            self._pa = pyaudio.PyAudio()
            self._stream = self._pa.open(
                rate=self._porcupine.sample_rate,
                channels=1,
                format=pyaudio.paInt16,
                input=True,
                frames_per_buffer=self._porcupine.frame_length,
            )

            while self.running:
                try:
                    pcm = self._stream.read(
                        self._porcupine.frame_length,
                        exception_on_overflow=False,
                    )
                    pcm = struct.unpack_from(
                        "h" * self._porcupine.frame_length, pcm
                    )

                    keyword_index = self._porcupine.process(pcm)
                    if keyword_index >= 0:
                        console.print("[bold green]🎯 Wake word detected![/bold green]")
                        try:
                            self.on_wake()
                        except Exception as e:
                            console.print(f"[red]Wake handler error: {e}[/red]")
                except Exception as e:
                    console.print(f"[yellow]Frame read error: {e}[/yellow]")
                    time.sleep(0.5)

        except Exception as e:
            console.print(f"[red]Wake word init error: {e}[/red]")
        finally:
            self._cleanup()

    def _cleanup(self):
        try:
            if self._stream:
                self._stream.close()
            if self._pa:
                self._pa.terminate()
            if self._porcupine:
                self._porcupine.delete()
        except Exception:
            pass

    def stop(self):
        """Stop wake word detection."""
        self.running = False
        if self.thread:
            self.thread.join(timeout=2)