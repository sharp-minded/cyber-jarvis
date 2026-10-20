"""
intelligence/attack_graph.py - Neo4j-based attack graph

Stores hosts, services, vulnerabilities, sessions, attack paths.
"""

import os
from typing import Dict, List, Optional
from rich.console import Console

console = Console()

try:
    from neo4j import GraphDatabase
    NEO4J_AVAILABLE = True
except ImportError:
    NEO4J_AVAILABLE = False
    console.print("[yellow][!] neo4j driver not installed[/yellow]")


class AttackGraph:
    """Neo4j attack graph client."""

    _instance = None

    def __new__(cls):
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __init__(self):
        if hasattr(self, "_initialized"):
            return
        self._initialized = True

        self.uri = os.getenv("NEO4J_URI", "bolt://localhost:7687")
        self.user = os.getenv("NEO4J_USER", "neo4j")
        self.password = os.getenv("NEO4J_PASS", "jarvis_neo4j_pass")
        self.driver = None
        self._connect()

    def _connect(self):
        if not NEO4J_AVAILABLE:
            return
        try:
            self.driver = GraphDatabase.driver(
                self.uri,
                auth=(self.user, self.password),
            )
            self.driver.verify_connectivity()
            console.print("[green][+] Neo4j attack graph connected[/green]")
        except Exception as e:
            console.print(f"[yellow][!] Neo4j unavailable: {e}[/yellow]")
            self.driver = None

    def is_ready(self) -> bool:
        return self.driver is not None

    def _run(self, query: str, **kwargs):
        if not self.is_ready():
            return []
        try:
            with self.driver.session() as session:
                return list(session.run(query, **kwargs))
        except Exception as e:
            console.print(f"[red]Neo4j query error: {e}[/red]")
            return []

    # ─── Write Operations ─────────────────────────────────

    def add_host(self, ip: str, hostname: str = "", os_name: str = "",
                 tags: List[str] = None):
        """Create or update a host node."""
        self._run("""
            MERGE (h:Host {ip: $ip})
            SET h.hostname = $hostname,
                h.os = $os_name,
                h.tags = $tags,
                h.updated = datetime()
        """, ip=ip, hostname=hostname, os_name=os_name, tags=tags or [])

    def add_service(self, ip: str, port: int, service: str,
                    version: str = "", banner: str = ""):
        """Create service node linked to host."""
        self._run("""
            MATCH (h:Host {ip: $ip})
            MERGE (s:Service {host_ip: $ip, port: $port})
            SET s.service = $service, s.version = $version, s.banner = $banner
            MERGE (h)-[:RUNS]->(s)
        """, ip=ip, port=port, service=service, version=version, banner=banner)

    def add_vulnerability(self, ip: str, cve: str, title: str,
                          severity: str, cvss: float = 0.0,
                          evidence: str = ""):
        """Create vulnerability node linked to host."""
        self._run("""
            MATCH (h:Host {ip: $ip})
            MERGE (v:Vulnerability {cve: $cve, host_ip: $ip})
            SET v.title = $title,
                v.severity = $severity,
                v.cvss = $cvss,
                v.evidence = $evidence
            MERGE (h)-[:HAS_VULN]->(v)
        """, ip=ip, cve=cve, title=title,
            severity=severity, cvss=cvss, evidence=evidence[:500])

    def add_session(self, host_ip: str, session_type: str,
                    user: str = "", privileged: bool = False):
        """Record an active session."""
        self._run("""
            MATCH (h:Host {ip: $host_ip})
            MERGE (s:Session {host_ip: $host_ip, type: $session_type})
            SET s.user = $user,
                s.privileged = $privileged,
                s.timestamp = datetime()
            MERGE (h)-[:HAS_SESSION]->(s)
        """, host_ip=host_ip, session_type=session_type,
            user=user, privileged=privileged)

    def add_attack_edge(self, from_ip: str, to_ip: str,
                        technique: str, mitre_id: str = "",
                        success: bool = True):
        """Create an attack path edge."""
        self._run("""
            MATCH (a:Host {ip: $from_ip}), (b:Host {ip: $to_ip})
            MERGE (a)-[r:ATTACKED {technique: $technique}]->(b)
            SET r.mitre_id = $mitre_id,
                r.success = $success,
                r.timestamp = datetime()
        """, from_ip=from_ip, to_ip=to_ip,
            technique=technique, mitre_id=mitre_id, success=success)

    # ─── Query Operations ─────────────────────────────────

    def get_graph_stats(self) -> Dict:
        """Overall counts."""
        results = self._run("""
            MATCH (h:Host)
            WITH count(h) AS hosts
            OPTIONAL MATCH (v:Vulnerability)
            WITH hosts, count(v) AS vulns
            OPTIONAL MATCH (s:Service)
            WITH hosts, vulns, count(s) AS services
            OPTIONAL MATCH ()-[r:ATTACKED]->()
            RETURN hosts, vulns, services, count(r) AS attacks
        """)
        if not results:
            return {"hosts": 0, "vulns": 0, "services": 0, "attacks": 0}
        return dict(results[0])

    def get_critical_hosts(self, min_vulns: int = 3) -> List[Dict]:
        """Hosts with most vulnerabilities."""
        results = self._run("""
            MATCH (h:Host)-[:HAS_VULN]->(v:Vulnerability)
            WITH h, count(v) AS vuln_count, avg(v.cvss) AS avg_cvss
            WHERE vuln_count >= $min_vulns
            RETURN h.ip AS ip, h.os AS os,
                   vuln_count, avg_cvss
            ORDER BY avg_cvss DESC
        """, min_vulns=min_vulns)
        return [dict(r) for r in results]

    def get_privileged_hosts(self) -> List[Dict]:
        """Hosts with privileged sessions."""
        results = self._run("""
            MATCH (h:Host)-[:HAS_SESSION]->(s:Session {privileged: true})
            RETURN DISTINCT h.ip AS ip, h.os AS os, s.user AS user
        """)
        return [dict(r) for r in results]

    def get_attack_paths(self, from_ip: str, to_ip: str) -> List[Dict]:
        """Shortest attack path between two hosts."""
        results = self._run("""
            MATCH path = shortestPath(
                (a:Host {ip: $from_ip})-[*..10]->(b:Host {ip: $to_ip})
            )
            RETURN [node in nodes(path) |
                    coalesce(node.ip, node.cve, node.username)] AS nodes,
                   [rel in relationships(path) | type(rel)] AS rels
        """, from_ip=from_ip, to_ip=to_ip)
        return [dict(r) for r in results]

    def export_json(self, path: str):
        """Export graph to JSON."""
        import json

        hosts = [dict(r["h"]) for r in self._run("MATCH (h:Host) RETURN h")]
        vulns = [dict(r["v"]) for r in self._run(
            "MATCH (v:Vulnerability) RETURN v"
        )]
        sessions = [dict(r["s"]) for r in self._run(
            "MATCH (s:Session) RETURN s"
        )]

        data = {
            "hosts": hosts,
            "vulnerabilities": vulns,
            "sessions": sessions,
        }

        try:
            with open(path, "w") as f:
                json.dump(data, f, indent=2, default=str)
            console.print(f"[green][+] Graph exported: {path}[/green]")
        except Exception as e:
            console.print(f"[red]Export failed: {e}[/red]")

    def clear(self):
        """Delete all nodes (careful!)."""
        self._run("MATCH (n) DETACH DELETE n")
        console.print("[yellow][!] Graph cleared[/yellow]")


# ─── Singleton accessor ───────────────────────────────────

def get_attack_graph() -> AttackGraph:
    return AttackGraph()