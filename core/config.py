"""
core/config.py - Cyber Jarvis Config
600+ Kali tools DB + multi-language + WhatsApp notifications.

FIX: MSF password NO DEFAULT (env-required, random fallback).
"""

import os
import secrets
from pathlib import Path

# ═══════════════════════════════════════════════════════════════
#  PATHS
# ═══════════════════════════════════════════════════════════════

DRIVE = os.getenv("JARVIS_HOME", "E:/cyber-jarvis")
WORKSPACE = Path(f"{DRIVE}/workspace").resolve()

for sub in ["loot", "reports", "screenshots", "nuclei_templates",
            "rag_db", "kb_cache", "custom_tools"]:
    (WORKSPACE / sub).mkdir(parents=True, exist_ok=True)

# ═══════════════════════════════════════════════════════════════
#  METASPLOIT PASSWORD — NO DEFAULT
#  Agar env me nahi diya, random generate karo (per-session)
# ═══════════════════════════════════════════════════════════════

_MSF_RPC_PASSWORD = os.getenv("MSF_RPC_PASSWORD", "").strip()

if not _MSF_RPC_PASSWORD or _MSF_RPC_PASSWORD == "CHANGE_ME_TO_STRONG_PASSWORD":
    _MSF_RPC_PASSWORD = secrets.token_urlsafe(24)
    print("[!] MSF_RPC_PASSWORD not set in .env — generated random for this session.")
    print(f"[!] Save this to .env for consistency: MSF_RPC_PASSWORD={_MSF_RPC_PASSWORD}")

# ═══════════════════════════════════════════════════════════════
#  MAIN CONFIG
# ═══════════════════════════════════════════════════════════════

CONFIG = {
    # ─── LLM ──────────────────────────────────────────────
    "deepseek_api_key": os.getenv("DEEPSEEK_API_KEY", ""),
    "deepseek_base_url": "https://api.deepseek.com/v1",
    "model": os.getenv("JARVIS_MODEL", "deepseek-chat"),
    "temperature": 0.1,
    "max_iterations": 60,

    # ─── LANGUAGE ─────────────────────────────────────────
    "language": os.getenv("JARVIS_LANGUAGE", "hinglish").lower(),

    # ─── Kali VM ──────────────────────────────────────────
    "kali_host": os.getenv("KALI_HOST", "192.168.56.101"),
    "kali_ssh_port": int(os.getenv("KALI_SSH_PORT", "22")),
    "kali_user": os.getenv("KALI_USER", "root"),
    "kali_pass": os.getenv("KALI_PASS", ""),
    "kali_key": os.getenv("KALI_KEY", ""),

    # ─── Burp Pro ─────────────────────────────────────────
    "burp_api_url": os.getenv("BURP_API_URL", "http://127.0.0.1:1337"),
    "burp_api_key": os.getenv("BURP_API_KEY", ""),

    # ─── Metasploit RPC (FIXED) ───────────────────────────
    "msf_rpc_password": _MSF_RPC_PASSWORD,
    "msf_rpc_port": 55553,
    "msf_rpc_ssl": False,

    # ─── NVD ──────────────────────────────────────────────
    "nvd_api_key": os.getenv("NVD_API_KEY", ""),
    "nvd_sleep": 0.6 if os.getenv("NVD_API_KEY") else 6,

    # ─── Paths ────────────────────────────────────────────
    "workspace": WORKSPACE,
    "loot_dir": WORKSPACE / "loot",
    "reports_dir": WORKSPACE / "reports",
    "screenshots_dir": WORKSPACE / "screenshots",
    "nuclei_templates_dir": WORKSPACE / "nuclei_templates",
    "rag_db_dir": WORKSPACE / "rag_db",
    "kb_cache_dir": WORKSPACE / "kb_cache",
    "custom_tools_dir": WORKSPACE / "custom_tools",
    "cve_cache_file": WORKSPACE / "cve_cache.json",
    "scope_file": "scope.txt",

    # ─── Behavior ─────────────────────────────────────────
    "auto_install": True,
    "voice_enabled": True,
    "safe_mode": True,
    "voice_tts_rate": 180,
    "allow_custom_tools": False,  # FIX: LLM code quarantine by default

    # ─── WhatsApp ─────────────────────────────────────────
    "whatsapp_number": os.getenv("WHATSAPP_NUMBER", "+923132985274"),
    "whatsapp_method": os.getenv("WHATSAPP_METHOD", "pywhatkit"),
    "twilio_account_sid": os.getenv("TWILIO_ACCOUNT_SID", ""),
    "twilio_auth_token": os.getenv("TWILIO_AUTH_TOKEN", ""),
    "twilio_whatsapp_from": os.getenv("TWILIO_WHATSAPP_FROM",
                                       "whatsapp:+14155238886"),

    # ─── Report ───────────────────────────────────────────
    "report_language": "english",
    "report_format": "professional",
    "capture_screenshots": True,
    "max_screenshots_per_finding": 3,

    # ─── Network Safety ───────────────────────────────────
    "rss_timeout": 10,      # FIX: RSS hang prevention
    "http_timeout": 30,
}

# ═══════════════════════════════════════════════════════════════
#  LANGUAGE PROMPTS
# ═══════════════════════════════════════════════════════════════

LANGUAGE_PROMPTS = {
    "english": (
        "Respond in clear, professional English. "
        "Use simple sentences and avoid jargon unless explaining it."
    ),
    "hinglish": (
        "Respond in Hinglish (Hindi + English mix written in Roman script). "
        "Example: 'Bhai ye vulnerability bahut critical hai. Isko exploit karne ke liye...'. "
        "Technical terms English mein rakho, baaki Hinglish mein."
    ),
    "roman_urdu": (
        "Respond in Roman Urdu (Urdu written in English letters). "
        "Example: 'Bhai ye bug bohat khatarnak hai. Isko theek karne ke liye...'. "
        "Technical terms English mein rakho, baaki Urdu mein."
    ),
}


def get_language_prompt() -> str:
    return LANGUAGE_PROMPTS.get(CONFIG["language"], LANGUAGE_PROMPTS["english"])


def get_language() -> str:
    return CONFIG["language"]


# ═══════════════════════════════════════════════════════════════
#  600+ KALI TOOLS DB
# ═══════════════════════════════════════════════════════════════

KALI_TOOLS = {
    "information_gathering": [
        "nmap", "masscan", "rustscan", "unicornscan", "zmap", "dmitry",
        "dnsenum", "dnsrecon", "dnsutils", "fierce", "whois", "dig",
        "host", "nslookup", "amass", "subfinder", "assetfinder",
        "findomain", "sublist3r", "theHarvester", "recon-ng", "maltego",
        "spiderfoot", "shodan", "censys", "netdiscover", "arp-scan",
        "fping", "hping3", "traceroute", "tcptraceroute", "enum4linux",
        "smbclient", "nbtscan", "snmpwalk", "snmp-check", "onesixtyone",
        "ldapsearch", "rpcclient", "gobuster", "feroxbuster", "dirsearch",
        "ffuf", "wfuzz", "dirb", "dirbuster", "nikto", "whatweb",
        "wafw00f", "wpscan", "joomscan", "droopescan", "cmseek",
        "eyewitness", "aquatone", "httpx", "katana", "hakrawler",
        "gau", "waybackurls", "gospider", "linkfinder", "arjun",
        "paramspider", "dalfox", "xsstrike", "knockpy",
    ],
    "vulnerability_analysis": [
        "nuclei", "nikto", "openvas", "gvm", "searchsploit",
        "exploitdb", "sqlmap", "nosqlmap", "jsql-injection", "xsser",
        "xsstrike", "dalfox", "w3af", "skipfish", "grabber", "wapiti",
        "zaproxy", "burpsuite", "beef-xss", "commix", "tplmap",
        "ysoserial", "ssrfmap", "gopherus", "liffy", "semgrep",
        "bandit", "gitleaks", "trufflehog", "trivy", "grype",
        "checksec", "readelf", "objdump", "strings", "exiftool",
        "binwalk", "foremost", "testssl.sh", "sslscan", "sslyze",
        "ike-scan", "yersinia", "thc-ipv6", "sipvicious", "driftnet",
        "dsniff", "urlsnarf",
    ],
    "exploitation": [
        "metasploit-framework", "msfconsole", "msfvenom",
        "searchsploit", "routersploit", "set", "setoolkit",
        "beef-xss", "sqlmap", "commix", "tplmap", "ysoserial",
        "crackmapexec", "impacket-scripts", "impacket",
        "powershell-empire", "empire", "pupy", "merlin", "sliver",
        "mythic", "havoc", "venom", "shellter", "veil",
        "thefatrat", "unicorn", "pwncat", "nishang", "powersploit",
        "mimikatz", "rubeus", "certipy", "bloodhound", "sharphound",
        "azurehound", "responder", "mitm6", "ntlmrelayx",
        "petitpotam", "printerbug", "zerologon", "printnightmare",
        "krbrelayx", "kerbrute", "hashcat", "john",
    ],
    "password_attacks": [
        "hashcat", "john", "johnny", "ophcrack", "rainbowcrack",
        "hydra", "medusa", "ncrack", "patator", "crackmapexec",
        "crunch", "cewl", "cupp", "maskprocessor", "hash-identifier",
        "hashid", "haiti", "seclists", "rockyou", "wfuzz",
        "brutespray", "crowbar", "kerbrute", "chntpw", "samdump2",
        "pwdump", "creddump7", "mimipenguin", "lazagne",
        "secretsdump", "hashcat-utils", "princeprocessor",
        "combinator",
    ],
    "wireless_attacks": [
        "aircrack-ng", "airodump-ng", "aireplay-ng", "airbase-ng",
        "kismet", "wifite", "reaver", "bully", "pixiewps", "mdk3",
        "mdk4", "hostapd", "eapmd5pass", "asleap", "cowpatty",
        "pyrit", "fern-wifi-cracker", "wifiphisher", "wifi-pumpkin",
        "bettercap", "eaphammer", "mana-toolkit", "bluetoothctl",
        "bluesnarfer", "btscanner", "crackle", "gatttool",
        "killerbee", "rfidiot", "mfcuk", "mfoc", "mfterm", "libnfc",
    ],
    "sniffing_spoofing": [
        "wireshark", "tshark", "tcpdump", "dumpcap", "ettercap",
        "ettercap-graphical", "bettercap", "mitmproxy", "mitmweb",
        "mitmdump", "dsniff", "arpspoof", "dnsspoof", "macof",
        "tcpkill", "tcpnice", "urlsnarf", "msgsnarf", "filesnarf",
        "mailsnarf", "webspy", "sslsniff", "sslstrip", "responder",
        "mitm6", "inveigh", "netsniff-ng", "ifpps", "trafgen",
        "scapy", "p0f", "passivedns", "ngrep", "netsed", "socat",
        "netcat", "ncat", "dnschef", "dnscat2", "iodine", "dns2tcp",
    ],
    "web_application": [
        "burpsuite", "zaproxy", "nikto", "skipfish", "w3af",
        "wapiti", "grabber", "sqlmap", "nosqlmap", "jsql-injection",
        "sqlsus", "xsser", "xsstrike", "dalfox", "commix",
        "tplmap", "ysoserial", "gobuster", "feroxbuster",
        "dirsearch", "ffuf", "wfuzz", "dirb", "dirbuster", "arjun",
        "paramspider", "subfinder", "assetfinder", "amass",
        "findomain", "httpx", "httprobe", "katana", "hakrawler",
        "gau", "waybackurls", "gospider", "linkfinder", "nuclei",
        "jaeles", "wpscan", "joomscan", "droopescan", "cmseek",
        "whatweb", "wafw00f", "wappalyzer", "testssl.sh",
        "sslscan", "sslyze", "jwt-tool", "jwt-cracker", "httpie",
        "curl", "wget", "graphql-cop", "inql", "graphqlmap",
    ],
    "database_attacks": [
        "sqlmap", "sqlninja", "sqlsus", "jsql-injection", "odat",
        "mongoaudit", "nosqlmap", "redis-cli", "redis-rogue-server",
        "mysql", "mysqldump", "mariadb", "psql", "sqlite3",
        "mssql-cli", "impacket-mssqlclient", "sqsh", "oracle",
        "oscanner", "tnscmd10g", "sidguess", "db2", "couchdb",
        "cassandra", "elasticsearch", "kibana",
    ],
    "reverse_engineering": [
        "ghidra", "radare2", "rizin", "cutter", "iaito",
        "ida-free", "gdb", "pwndbg", "gef", "lldb", "ltrace",
        "strace", "objdump", "readelf", "nm", "strings", "file",
        "hexdump", "xxd", "od", "binwalk", "foremost", "upx",
        "dnspy", "ilspy", "de4dot", "jadx", "apktool", "dex2jar",
        "jd-gui", "bytecode-viewer", "frida", "frida-tools",
        "objection", "mobsf", "angr", "z3", "capstone", "keystone",
        "unicorn", "ropper", "ropgadget", "one_gadget", "checksec",
        "pwntools", "pwninit",
    ],
    "forensics": [
        "autopsy", "sleuthkit", "tsk_recover", "fls", "icat",
        "volatility", "volatility3", "bulk_extractor", "foremost",
        "scalpel", "guymager", "dc3dd", "dcfldd", "ddrescue",
        "testdisk", "photorec", "safecopy", "extundelete",
        "ext4magic", "ntfs-3g", "reglookup", "regripper",
        "chntpw", "samdump2", "pwdump", "creddump7", "mimipenguin",
        "lazagne", "secretsdump", "exiftool", "metagoofil", "mat2",
        "pdf-parser", "pdfid", "peepdf", "oledump", "oletools",
        "floss", "yara", "clamav", "chkrootkit", "rkhunter",
        "lynis", "aide", "tripwire", "suricata", "snort", "zeek",
        "ntopng",
    ],
    "social_engineering": [
        "set", "setoolkit", "gophish", "evilginx2", "king-phisher",
        "modlishka", "muraena", "blackeye", "hiddeneye", "zphisher",
        "socialfish", "shellphish", "advphishing", "pyphisher",
    ],
    "cloud_container": [
        "pacu", "cloudfox", "scoutsuite", "prowler", "cloudsploit",
        "trivy", "grype", "kube-hunter", "kube-bench", "kubeaudit",
        "kubesec", "kubectl", "k9s", "helm", "aws-cli", "azure-cli",
        "gcloud", "terraform", "terrascan", "checkov", "tfsec",
        "tflint", "docker", "podman", "falco", "sysdig",
        "s3scanner", "cloud_enum", "cloudbrute",
    ],
    "post_exploitation": [
        "mimikatz", "rubeus", "certipy", "bloodhound",
        "sharphound", "azurehound", "ldapdomaindump",
        "windapsearch", "responder", "mitm6", "ntlmrelayx",
        "petitpotam", "impacket", "crackmapexec", "netexec",
        "psexec", "smbexec", "wmiexec", "atexec", "smbclient",
        "linpeas", "winpeas", "pspy", "linux-exploit-suggester",
        "windows-exploit-suggester", "seatbelt", "sharpup",
        "powerup", "privesccheck", "gtfobins", "lolbas",
        "ligolo-ng", "chisel", "socat", "empire", "starkiller",
        "sliver", "meterpreter", "veil",
    ],
    "reporting": [
        "dradis", "serpico", "faraday", "magictree", "pwndoc",
        "ghostwriter", "cherrytree", "pandoc", "wkhtmltopdf",
        "weasyprint",
    ],
    "utilities": [
        "netcat", "ncat", "socat", "openssl", "gnutls-cli", "curl",
        "wget", "httpie", "aria2", "rsync", "ssh", "scp", "sftp",
        "sshfs", "sshuttle", "proxychains", "tor", "torsocks",
        "openvpn", "wireguard", "iptables", "nftables", "ufw",
        "ip", "netstat", "ss", "lsof", "ps", "tmux", "screen",
        "git", "vim", "nano",
    ],
}

ALL_TOOLS = []
for cat, tools in KALI_TOOLS.items():
    for t in tools:
        if t not in ALL_TOOLS:
            ALL_TOOLS.append(t)

CRITICAL_TOOLS = [
    "nmap", "metasploit-framework", "msfconsole", "msfvenom",
    "burpsuite", "hashcat", "john", "hydra", "sqlmap",
    "gobuster", "nikto", "wireshark", "aircrack-ng",
    "searchsploit", "nuclei", "ffuf", "wpscan", "commix",
]


def get_tool_count():
    return len(ALL_TOOLS)


if __name__ == "__main__":
    print(f"[+] Tools: {get_tool_count()}")
    print(f"[+] Language: {get_language()}")
    print(f"[+] Workspace: {WORKSPACE}")