"""
security/security_vault.py - Encrypted secrets vault

Uses Fernet (AES-128-CBC + HMAC) with PBKDF2HMAC key derivation.
Stores secrets in workspace/.vault.enc (encrypted JSON).
"""

import os
import json
import base64
from typing import Dict, Optional
from rich.console import Console

from core.config import CONFIG

console = Console()

try:
    from cryptography.fernet import Fernet
    from cryptography.hazmat.primitives import hashes
    from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
    CRYPTO_AVAILABLE = True
except ImportError:
    CRYPTO_AVAILABLE = False
    console.print("[yellow][!] cryptography not installed[/yellow]")


class SecurityVault:
    """Encrypted key-value vault."""

    _instance = None

    def __new__(cls, *args, **kwargs):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self, master_key: Optional[str] = None):
        if hasattr(self, "_initialized"):
            return
        self._initialized = True

        self.vault_file = CONFIG["workspace"] / ".vault.enc"
        self.master_key = master_key or os.getenv("JARVIS_MASTER_KEY", "").strip()
        self._fernet = None

        if CRYPTO_AVAILABLE and self.master_key:
            try:
                self._fernet = self._derive_key(self.master_key)
            except Exception as e:
                console.print(f"[red]Vault key derivation failed: {e}[/red]")
                self._fernet = None

    def _derive_key(self, password: str) -> "Fernet":
        """Derive Fernet key from password."""
        salt = b"cyber_jarvis_salt_v1"
        kdf = PBKDF2HMAC(
            algorithm=hashes.SHA256(),
            length=32,
            salt=salt,
            iterations=480_000,
        )
        key = base64.urlsafe_b64encode(kdf.derive(password.encode()))
        return Fernet(key)

    def is_ready(self) -> bool:
        return self._fernet is not None

    # ─── Load/Save ────────────────────────────────────────

    def _load(self) -> Dict:
        if not self.vault_file.exists():
            return {}
        try:
            encrypted = self.vault_file.read_bytes()
            decrypted = self._fernet.decrypt(encrypted)
            return json.loads(decrypted)
        except Exception as e:
            console.print(f"[red]Vault decrypt failed: {e}[/red]")
            return {}

    def _save(self, data: Dict):
        try:
            encrypted = self._fernet.encrypt(json.dumps(data).encode())
            self.vault_file.write_bytes(encrypted)
            try:
                self.vault_file.chmod(0o600)
            except Exception:
                pass  # Windows may not support chmod
        except Exception as e:
            console.print(f"[red]Vault save failed: {e}[/red]")

    # ─── Public API ───────────────────────────────────────

    def set(self, key: str, value: str):
        if not self.is_ready():
            console.print("[red]Vault not ready (JARVIS_MASTER_KEY missing)[/red]")
            return
        data = self._load()
        data[key] = value
        self._save(data)

    def get(self, key: str, default: str = "") -> str:
        if not self.is_ready():
            return default
        return self._load().get(key, default)

    def delete(self, key: str):
        if not self.is_ready():
            return
        data = self._load()
        data.pop(key, None)
        self._save(data)

    def list_keys(self) -> list:
        if not self.is_ready():
            return []
        return list(self._load().keys())

    def load_all_env(self):
        """Load all secrets into os.environ (if not already set)."""
        if not self.is_ready():
            return
        for k, v in self._load().items():
            if k not in os.environ:
                os.environ[k] = v
        console.print("[green][+] Vault secrets loaded into env[/green]")

    def clear(self):
        """Delete vault file."""
        if self.vault_file.exists():
            try:
                self.vault_file.unlink()
                console.print("[yellow][!] Vault cleared[/yellow]")
            except Exception as e:
                console.print(f"[red]Clear failed: {e}[/red]")