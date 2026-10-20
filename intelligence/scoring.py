"""
intelligence/scoring.py - CVSS + EPSS + KEV prioritization

Combines multiple scoring systems for accurate prioritization.
"""

import time
from typing import Dict, List
import requests
from rich.console import Console

from core.config import CONFIG

console = Console()


class VulnerabilityScorer:
    """
    Scoring engine combining:
    - CVSS base score
    - EPSS (exploitation probability)
    - CISA KEV (known exploited)
    - Public exploit availability
    """

    EPSS_API = "https://api.first.org/data/v1/epss"
    KEV_URL = (
        "https://www.cisa.gov/sites/default/files/feeds/"
        "known_exploited_vulnerabilities.json"
    )

    def __init__(self):
        self.kev_cache = None
        self.kev_last_fetch = 0
        self.kev_cache_ttl = 3600  # 1 hour

    # ─── CVSS ─────────────────────────────────────────────

    def compute_cvss(self, vector: str) -> Dict:
        """Compute CVSS from vector string."""
        try:
            from cvss import CVSS3, CVSS2
            if vector.startswith("CVSS:3"):
                c = CVSS3(vector)
                return {
                    "score": c.base_score,
                    "severity": c.severities()[0],
                    "vector": vector,
                }
            elif vector.startswith("AV:"):
                c = CVSS2(vector)
                return {
                    "score": c.base_score,
                    "severity": c.severities()[0],
                    "vector": vector,
                }
        except Exception as e:
            console.print(f"[yellow]CVSS parse error: {e}[/yellow]")
        return {"score": 0, "severity": "UNKNOWN", "vector": vector}

    # ─── EPSS ─────────────────────────────────────────────

    def get_epss(self, cve_id: str) -> Dict:
        """Get EPSS score for a CVE."""
        try:
            r = requests.get(
                self.EPSS_API,
                params={"cve": cve_id},
                timeout=10,
            )
            data = r.json().get("data", [])
            if data:
                return {
                    "epss": float(data[0].get("epss", 0)),
                    "percentile": float(data[0].get("percentile", 0)),
                    "date": data[0].get("date", ""),
                }
        except Exception as e:
            console.print(f"[yellow]EPSS fetch error: {e}[/yellow]")
        return {"epss": 0, "percentile": 0, "date": ""}

    def get_epss_bulk(self, cve_ids: List[str]) -> Dict[str, Dict]:
        """Bulk EPSS fetch (max 100)."""
        results = {}
        if not cve_ids:
            return results

        try:
            r = requests.get(
                self.EPSS_API,
                params={"cve": ",".join(cve_ids[:100])},
                timeout=15,
            )
            for item in r.json().get("data", []):
                results[item["cve"]] = {
                    "epss": float(item.get("epss", 0)),
                    "percentile": float(item.get("percentile", 0)),
                }
        except Exception:
            pass
        return results

    # ─── CISA KEV ─────────────────────────────────────────

    def _fetch_kev(self):
        """Fetch KEV catalog (cached)."""
        now = time.time()
        if self.kev_cache and (now - self.kev_last_fetch) < self.kev_cache_ttl:
            return

        try:
            r = requests.get(self.KEV_URL, timeout=30)
            data = r.json()
            self.kev_cache = {
                v["cveID"]: v for v in data.get("vulnerabilities", [])
            }
            self.kev_last_fetch = now
            console.print(f"[green][+] KEV loaded: {len(self.kev_cache)} CVEs[/green]")
        except Exception as e:
            console.print(f"[yellow]KEV fetch error: {e}[/yellow]")
            self.kev_cache = {}

    def is_kev(self, cve_id: str) -> bool:
        self._fetch_kev()
        return cve_id in (self.kev_cache or {})

    def get_kev_info(self, cve_id: str) -> Dict:
        self._fetch_kev()
        return (self.kev_cache or {}).get(cve_id, {})

    # ─── Combined Priority ────────────────────────────────

    def prioritize(self, cve_id: str, cvss_score: float = 0) -> Dict:
        """
        Combined priority scoring.

        Formula:
          base = CVSS
          + 2 if KEV
          + 2 if EPSS > 0.5
          + 1 if EPSS > 0.1
        """
        epss_data = self.get_epss(cve_id) if cve_id else {"epss": 0, "percentile": 0}
        epss = epss_data.get("epss", 0)
        is_kev = self.is_kev(cve_id) if cve_id else False

        priority = cvss_score
        reasons = [f"CVSS: {cvss_score}"]

        if is_kev:
            priority += 2
            reasons.append("CISA KEV (+2)")

        if epss > 0.5:
            priority += 2
            reasons.append(f"EPSS: {epss:.3f} (+2)")
        elif epss > 0.1:
            priority += 1
            reasons.append(f"EPSS: {epss:.3f} (+1)")

        # Priority label
        if priority >= 9:
            label = "CRITICAL"
            action = "Patch immediately (24 hours)"
        elif priority >= 7:
            label = "HIGH"
            action = "Patch within 7 days"
        elif priority >= 4:
            label = "MEDIUM"
            action = "Patch within 30 days"
        else:
            label = "LOW"
            action = "Patch within 90 days"

        return {
            "cve_id": cve_id,
            "cvss": cvss_score,
            "epss": epss,
            "epss_percentile": epss_data.get("percentile", 0),
            "kev": is_kev,
            "priority_score": round(priority, 2),
            "priority_label": label,
            "action": action,
            "reasons": reasons,
        }

    def score_findings(self, findings: List[Dict]) -> List[Dict]:
        """Enrich findings with priority scoring."""
        if not findings:
            return []

        # Collect CVEs for bulk EPSS
        cve_ids = []
        for f in findings:
            cve = f.get("cve_id") or f.get("cve") or ""
            if cve:
                cve_ids.append(cve)

        epss_bulk = self.get_epss_bulk(cve_ids) if cve_ids else {}

        enriched = []
        for f in findings:
            cve = f.get("cve_id") or f.get("cve") or ""
            cvss = f.get("cvss", 0) or 0

            if cve:
                epss = epss_bulk.get(cve, {}).get("epss", 0)
                is_kev = self.is_kev(cve)

                priority = cvss
                if is_kev:
                    priority += 2
                if epss > 0.5:
                    priority += 2
                elif epss > 0.1:
                    priority += 1

                f["priority"] = {
                    "priority_score": round(priority, 2),
                    "priority_label": self._label(priority),
                    "epss": epss,
                    "kev": is_kev,
                }
            else:
                f["priority"] = {
                    "priority_score": cvss,
                    "priority_label": self._label(cvss),
                    "epss": 0,
                    "kev": False,
                }

            enriched.append(f)

        return enriched

    @staticmethod
    def _label(score: float) -> str:
        if score >= 9:
            return "CRITICAL"
        if score >= 7:
            return "HIGH"
        if score >= 4:
            return "MEDIUM"
        return "LOW"


# ─── CLI test ─────────────────────────────────────────────

if __name__ == "__main__":
    scorer = VulnerabilityScorer()
    result = scorer.prioritize("CVE-2024-3094", 10.0)
    print(result)