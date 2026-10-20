"""
intelligence/cve_feed.py - NVD API v2 + RSS feeds

FIX: RSS feeds now have 10-second timeout (previously hung indefinitely).
FIX: Network errors handled gracefully.
"""

import json
from datetime import datetime, timedelta
from typing import Dict, List
import requests
import feedparser
from rich.console import Console
from rich.table import Table

from core.config import CONFIG

console = Console()


class CVEFeed:
    """Fetch CVEs from NVD + security news from RSS."""

    NVD_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"

    RSS_FEEDS = {
        "The Hacker News": "https://feeds.feedburner.com/TheHackersNews",
        "BleepingComputer": "https://www.bleepingcomputer.com/feed/",
        "Krebs on Security": "https://krebsonsecurity.com/feed/",
        "SANS ISC": "https://isc.sans.edu/rssfeed.xml",
        "CISA Alerts": "https://www.cisa.gov/cybersecurity-advisories/all.xml",
        "Exploit-DB": "https://www.exploit-db.com/rss.xml",
    }

    def __init__(self):
        self.api_key = CONFIG["nvd_api_key"]
        self.cache_file = CONFIG["cve_cache_file"]
        self.rss_timeout = CONFIG.get("rss_timeout", 10)
        self.http_timeout = CONFIG.get("http_timeout", 30)

    # ─── NVD API ──────────────────────────────────────────

    def fetch_recent_cves(self, days: int = 7, severity: str = "") -> List[Dict]:
        """Fetch recent CVEs from NVD."""
        end = datetime.utcnow()
        start = end - timedelta(days=days)

        params = {
            "pubStartDate": start.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "pubEndDate": end.strftime("%Y-%m-%dT%H:%M:%S.000"),
            "resultsPerPage": 200,
        }
        if severity:
            params["cvssV3Severity"] = severity.upper()

        headers = {"apiKey": self.api_key} if self.api_key else {}

        console.print(f"[cyan][*] Fetching CVEs from NVD (last {days} days)...[/cyan]")

        try:
            r = requests.get(
                self.NVD_BASE,
                params=params,
                headers=headers,
                timeout=self.http_timeout,
            )
            r.raise_for_status()
            data = r.json()

            cves = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})

                # Extract English description
                desc = ""
                for d in cve.get("descriptions", []):
                    if d.get("lang") == "en":
                        desc = d.get("value", "")
                        break

                # Extract CVSS
                cvss, sev = 0, "UNKNOWN"
                metrics = cve.get("metrics", {})
                for key in ["cvssMetricV31", "cvssMetricV30", "cvssMetricV2"]:
                    if key in metrics and metrics[key]:
                        m = metrics[key][0].get("cvssData", {})
                        cvss = m.get("baseScore", 0)
                        sev = m.get("baseSeverity", "UNKNOWN")
                        break

                cves.append({
                    "id": cve.get("id", ""),
                    "description": desc[:500],
                    "cvss_score": cvss,
                    "severity": sev,
                    "published": cve.get("published", ""),
                    "last_modified": cve.get("lastModified", ""),
                    "references": [
                        ref.get("url") for ref in cve.get("references", [])
                    ][:5],
                })

            self._save_cache(cves)
            console.print(f"[green][+] Found {len(cves)} CVEs[/green]")
            return cves

        except requests.exceptions.HTTPError as e:
            if e.response.status_code == 403:
                console.print("[yellow][!] NVD rate limit hit. Increase sleep.[/yellow]")
            else:
                console.print(f"[red]NVD HTTP error: {e}[/red]")
            return []
        except requests.exceptions.Timeout:
            console.print("[red]NVD request timed out[/red]")
            return []
        except Exception as e:
            console.print(f"[red]NVD fetch error: {e}[/red]")
            return []

    def fetch_critical_cves(self, days: int = 7) -> List[Dict]:
        return self.fetch_recent_cves(days=days, severity="CRITICAL")

    def search_cve(self, keyword: str) -> List[Dict]:
        """Search NVD by keyword."""
        params = {"keywordSearch": keyword, "resultsPerPage": 50}
        headers = {"apiKey": self.api_key} if self.api_key else {}

        try:
            r = requests.get(
                self.NVD_BASE,
                params=params,
                headers=headers,
                timeout=self.http_timeout,
            )
            r.raise_for_status()
            data = r.json()

            results = []
            for item in data.get("vulnerabilities", []):
                cve = item.get("cve", {})
                desc = next(
                    (d["value"] for d in cve.get("descriptions", [])
                     if d.get("lang") == "en"),
                    "",
                )
                results.append({
                    "id": cve.get("id", ""),
                    "description": desc[:400],
                    "cvss_score": 0,
                    "severity": "UNKNOWN",
                })
            return results
        except Exception as e:
            console.print(f"[red]CVE search error: {e}[/red]")
            return []

    # ─── RSS Feeds (FIXED) ────────────────────────────────

    def fetch_rss_news(self, limit_per_feed: int = 5) -> List[Dict]:
        """
        Fetch news from RSS feeds.

        FIX: Uses requests.get with 10s timeout, then feedparser on content.
        Previously: feedparser.parse(url) hung indefinitely on slow feeds.
        """
        console.print("[cyan][*] Fetching RSS security news...[/cyan]")
        all_news = []

        for source, url in self.RSS_FEEDS.items():
            try:
                # FIX: fetch with timeout FIRST
                r = requests.get(
                    url,
                    timeout=self.rss_timeout,   # ← 10 sec
                    headers={"User-Agent": "Mozilla/5.0 Jarvis/6.0"},
                )
                r.raise_for_status()

                # Parse from bytes
                feed = feedparser.parse(r.content)

                for entry in feed.entries[:limit_per_feed]:
                    all_news.append({
                        "source": source,
                        "title": entry.get("title", ""),
                        "link": entry.get("link", ""),
                        "published": entry.get("published", ""),
                        "summary": entry.get("summary", "")[:300],
                    })

            except requests.Timeout:
                console.print(f"[yellow][!] {source}: timeout ({self.rss_timeout}s)[/yellow]")
            except requests.ConnectionError:
                console.print(f"[yellow][!] {source}: connection error[/yellow]")
            except Exception as e:
                console.print(f"[yellow][!] {source}: {e}[/yellow]")

        console.print(f"[green][+] Fetched {len(all_news)} news items[/green]")
        return all_news

    # ─── Display ──────────────────────────────────────────

    def display_cves(self, cves: List[Dict], limit: int = 20):
        if not cves:
            console.print("[yellow]No CVEs to display[/yellow]")
            return

        table = Table(title=f"Recent CVEs ({len(cves)} total)")
        table.add_column("CVE ID", style="cyan", no_wrap=True)
        table.add_column("Severity", style="red")
        table.add_column("CVSS", style="yellow")
        table.add_column("Description", overflow="fold")

        for cve in cves[:limit]:
            sev_color = {
                "CRITICAL": "red",
                "HIGH": "orange3",
                "MEDIUM": "yellow",
                "LOW": "green",
            }.get(cve.get("severity", ""), "white")

            table.add_row(
                cve.get("id", "")[:20],
                f"[{sev_color}]{cve.get('severity', '?')}[/{sev_color}]",
                str(cve.get("cvss_score", 0)),
                cve.get("description", "")[:100] + "...",
            )
        console.print(table)

    def display_news(self, news: List[Dict], limit: int = 20):
        if not news:
            console.print("[yellow]No news[/yellow]")
            return

        table = Table(title=f"Security News ({len(news)} items)")
        table.add_column("Source", style="cyan", no_wrap=True)
        table.add_column("Title", overflow="fold")

        for item in news[:limit]:
            table.add_row(item.get("source", "?"), item.get("title", "")[:80])
        console.print(table)

    # ─── Cache ────────────────────────────────────────────

    def _save_cache(self, cves: List[Dict]):
        try:
            self.cache_file.write_text(json.dumps({
                "updated": datetime.utcnow().isoformat(),
                "count": len(cves),
                "cves": cves[:500],   # cap size
            }, indent=2))
        except Exception:
            pass

    def load_cache(self) -> List[Dict]:
        if self.cache_file.exists():
            try:
                data = json.loads(self.cache_file.read_text())
                return data.get("cves", [])
            except Exception:
                return []
        return []

    # ─── Daily Digest ─────────────────────────────────────

    def daily_digest(self) -> Dict:
        cves = self.fetch_recent_cves(days=1)
        critical = [c for c in cves if c.get("severity") == "CRITICAL"]
        news = self.fetch_rss_news()

        return {
            "date": datetime.utcnow().isoformat(),
            "total_cves": len(cves),
            "critical_cves": len(critical),
            "news_count": len(news),
            "top_cves": sorted(cves, key=lambda x: x.get("cvss_score", 0),
                               reverse=True)[:10],
            "news": news[:20],
        }