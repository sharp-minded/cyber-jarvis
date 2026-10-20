"""
intelligence/mitre_mapper.py - MITRE ATT&CK technique mapping

Maps pentesting tools/actions to ATT&CK techniques.
"""

from typing import Dict, List
from rich.console import Console
from rich.table import Table

console = Console()


# ─── Tool → ATT&CK mapping ────────────────────────────────
TOOL_TO_MITRE = {
    # Reconnaissance
    "nmap": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "masscan": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "rustscan": {"id": "T1046", "name": "Network Service Discovery", "tactic": "Discovery"},
    "amass": {"id": "T1590", "name": "Gather Victim Network Info", "tactic": "Recon"},
    "subfinder": {"id": "T1590", "name": "Gather Victim Network Info", "tactic": "Recon"},
    "assetfinder": {"id": "T1590", "name": "Gather Victim Network Info", "tactic": "Recon"},
    "theHarvester": {"id": "T1589", "name": "Gather Victim Identity Info", "tactic": "Recon"},
    "shodan": {"id": "T1596", "name": "Search Open Technical DBs", "tactic": "Recon"},
    "httpx": {"id": "T1595", "name": "Active Scanning", "tactic": "Recon"},
    "gobuster": {"id": "T1595", "name": "Active Scanning", "tactic": "Recon"},
    "ffuf": {"id": "T1595", "name": "Active Scanning", "tactic": "Recon"},
    "wfuzz": {"id": "T1595", "name": "Active Scanning", "tactic": "Recon"},
    "dirb": {"id": "T1595", "name": "Active Scanning", "tactic": "Recon"},
    "nuclei": {"id": "T1595", "name": "Active Scanning", "tactic": "Recon"},

    # Initial Access
    "metasploit": {"id": "T1190", "name": "Exploit Public-Facing App", "tactic": "Initial Access"},
    "metasploit-framework": {"id": "T1190", "name": "Exploit Public-Facing App", "tactic": "Initial Access"},
    "msfconsole": {"id": "T1190", "name": "Exploit Public-Facing App", "tactic": "Initial Access"},
    "sqlmap": {"id": "T1190", "name": "Exploit Public-Facing App", "tactic": "Initial Access"},
    "commix": {"id": "T1190", "name": "Exploit Public-Facing App", "tactic": "Initial Access"},
    "searchsploit": {"id": "T1588.005", "name": "Obtain Exploits", "tactic": "Resource Dev"},

    # Credential Access
    "hydra": {"id": "T1110.001", "name": "Brute Force: Password Guessing", "tactic": "Credential Access"},
    "hashcat": {"id": "T1110.002", "name": "Brute Force: Password Cracking", "tactic": "Credential Access"},
    "john": {"id": "T1110.002", "name": "Brute Force: Password Cracking", "tactic": "Credential Access"},
    "responder": {"id": "T1557.001", "name": "LLMNR/NBT-NS Poisoning", "tactic": "Credential Access"},
    "mimikatz": {"id": "T1003.001", "name": "LSASS Memory", "tactic": "Credential Access"},
    "kerbrute": {"id": "T1110.003", "name": "Password Spraying", "tactic": "Credential Access"},

    # Discovery
    "bloodhound": {"id": "T1087.002", "name": "Domain Account Discovery", "tactic": "Discovery"},
    "sharphound": {"id": "T1087.002", "name": "Domain Account Discovery", "tactic": "Discovery"},
    "linpeas": {"id": "T1082", "name": "System Info Discovery", "tactic": "Discovery"},
    "winpeas": {"id": "T1082", "name": "System Info Discovery", "tactic": "Discovery"},
    "pspy": {"id": "T1057", "name": "Process Discovery", "tactic": "Discovery"},

    # Lateral Movement
    "crackmapexec": {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "cme": {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "netexec": {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "nxc": {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "psexec": {"id": "T1021.002", "name": "SMB/Windows Admin Shares", "tactic": "Lateral Movement"},
    "wmiexec": {"id": "T1047", "name": "Windows Management Instrumentation", "tactic": "Execution"},
    "atexec": {"id": "T1053.005", "name": "Scheduled Task", "tactic": "Execution"},

    # Privilege Escalation
    "gtfobins": {"id": "T1548", "name": "Abuse Elevation Control", "tactic": "Privilege Escalation"},
    "lolbas": {"id": "T1218", "name": "System Binary Proxy Exec", "tactic": "Defense Evasion"},

    # Command & Control
    "sliver": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},
    "msfvenom": {"id": "T1587.001", "name": "Develop Capabilities: Malware", "tactic": "Resource Dev"},
    "meterpreter": {"id": "T1071", "name": "Application Layer Protocol", "tactic": "Command and Control"},

    # Collection / Exfil
    "nc": {"id": "T1041", "name": "Exfiltration Over C2", "tactic": "Exfiltration"},
    "netcat": {"id": "T1041", "name": "Exfiltration Over C2", "tactic": "Exfiltration"},
    "scp": {"id": "T1041", "name": "Exfiltration Over C2", "tactic": "Exfiltration"},

    # Web-specific
    "burpsuite": {"id": "T1190", "name": "Exploit Public-Facing App", "tactic": "Initial Access"},
    "zaproxy": {"id": "T1190", "name": "Exploit Public-Facing App", "tactic": "Initial Access"},
    "wpscan": {"id": "T1595.002", "name": "Vulnerability Scanning", "tactic": "Recon"},
    "nikto": {"id": "T1595.002", "name": "Vulnerability Scanning", "tactic": "Recon"},

    # Wireless
    "aircrack-ng": {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access"},
    "wifite": {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access"},
    "reaver": {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access"},

    # Sniffing
    "wireshark": {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access"},
    "tcpdump": {"id": "T1040", "name": "Network Sniffing", "tactic": "Credential Access"},
    "ettercap": {"id": "T1557.002", "name": "ARP Cache Poisoning", "tactic": "Credential Access"},
    "bettercap": {"id": "T1557.002", "name": "ARP Cache Poisoning", "tactic": "Credential Access"},
}


class MITREMapper:
    """Map tools to ATT&CK techniques."""

    # ATT&CK tactics in kill-chain order
    TACTICS_ORDER = [
        "Recon",
        "Resource Dev",
        "Initial Access",
        "Execution",
        "Persistence",
        "Privilege Escalation",
        "Defense Evasion",
        "Credential Access",
        "Discovery",
        "Lateral Movement",
        "Collection",
        "Command and Control",
        "Exfiltration",
        "Impact",
    ]

    def map_tool(self, tool: str) -> Dict:
        """Find technique for a tool."""
        base = tool.split("/")[-1].split()[0].lower()

        # Exact match
        if base in TOOL_TO_MITRE:
            return TOOL_TO_MITRE[base]

        # Substring match
        for key, tech in TOOL_TO_MITRE.items():
            if key in base or base in key:
                return tech

        return {"id": "T0000", "name": "Unknown", "tactic": "Unknown"}

    def map_tools(self, tools: List[str]) -> List[Dict]:
        return [{"tool": t, **self.map_tool(t)} for t in tools]

    def coverage_report(self, tools_used: List[str]) -> Dict:
        """Generate coverage statistics."""
        tactics = {}
        techniques = set()

        for t in tools_used:
            tech = self.map_tool(t)
            tactic = tech["tactic"]
            if tactic == "Unknown":
                continue
            tactics.setdefault(tactic, []).append({
                "tool": t,
                "technique": tech["name"],
                "id": tech["id"],
            })
            techniques.add(tech["id"])

        total_tactics = len(self.TACTICS_ORDER)
        covered = len(tactics)

        return {
            "tactics_covered": tactics,
            "total_tactics": total_tactics,
            "coverage_percent": round((covered / total_tactics) * 100, 1),
            "techniques": sorted(techniques),
            "total_techniques": len(techniques),
        }

    def print_heatmap(self, tools_used: List[str]):
        """Print coverage heatmap."""
        report = self.coverage_report(tools_used)

        table = Table(title="MITRE ATT&CK Coverage")
        table.add_column("Tactic", style="cyan", no_wrap=True)
        table.add_column("Status", style="yellow")
        table.add_column("Tools Used", style="green")

        for tactic in self.TACTICS_ORDER:
            if tactic in report["tactics_covered"]:
                tools = ", ".join(
                    t["tool"] for t in report["tactics_covered"][tactic]
                )
                table.add_row(f"✓ {tactic}", "COVERED", tools[:80])
            else:
                table.add_row(f"✗ {tactic}", "[dim]—[/dim]", "[dim]none[/dim]")

        console.print(table)
        console.print(
            f"\n[bold]Coverage: {report['coverage_percent']}% "
            f"({report['total_techniques']} techniques across "
            f"{report['total_tactics']} tactics)[/bold]"
        )

    def export_attack_layer(self, tools_used: List[str], output_path: str):
        """Export as ATT&CK Navigator JSON layer."""
        import json

        report = self.coverage_report(tools_used)
        techniques = report["techniques"]

        layer = {
            "name": "Cyber Jarvis Coverage",
            "versions": {"attack": "14", "navigator": "4.9", "layer": "4.5"},
            "domain": "enterprise-attack",
            "description": "Tools used by Cyber Jarvis mapped to ATT&CK",
            "techniques": [
                {"techniqueID": tid, "color": "#ff2b2b"} for tid in techniques
            ],
            "gradient": {
                "colors": ["#44dd44", "#ff2b2b"],
                "minValue": 0,
                "maxValue": 1,
            },
        }

        try:
            with open(output_path, "w") as f:
                json.dump(layer, f, indent=2)
            console.print(f"[green][+] ATT&CK layer: {output_path}[/green]")
        except Exception as e:
            console.print(f"[red]Export failed: {e}[/red]")