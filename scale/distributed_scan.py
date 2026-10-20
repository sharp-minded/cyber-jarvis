"""
scale/distributed_scan.py - Celery parallel scanning

Requires: Redis running, then:
    celery -A scale.distributed_scan.app worker -l info
"""

import os
from typing import Dict, List
from rich.console import Console

console = Console()

try:
    from celery import Celery
    CELERY_AVAILABLE = True
except ImportError:
    CELERY_AVAILABLE = False
    console.print("[yellow][!] celery not installed — distributed scanning disabled[/yellow]")


if CELERY_AVAILABLE:
    redis_url = os.getenv("REDIS_URL", "redis://localhost:6379/0")
    app = Celery("jarvis", broker=redis_url, backend=redis_url)
    app.conf.update(
        task_serializer="json",
        accept_content=["json"],
        result_serializer="json",
        timezone="UTC",
        enable_utc=True,
        task_time_limit=1800,
        worker_prefetch_multiplier=1,
    )

    @app.task
    def scan_target_task(target: str, scan_type: str = "nmap", args: list = None):
        """Distributed nmap scan."""
        from core.tools_engine import RemoteToolExecutor
        from core.scope_guard import validate_scope

        # FIX: scope check inside worker
        allowed, reason = validate_scope(target)
        if not allowed:
            return {"success": False, "error": f"SCOPE DENIED: {reason}"}

        args = args or ["-sV", "-T4", target]
        return RemoteToolExecutor.execute(scan_type, args, target)

    @app.task
    def nuclei_scan_task(target: str):
        """Distributed nuclei scan."""
        from tools_integration.nuclei_manager import NucleiManager
        return NucleiManager().scan(target)

    @app.task
    def burp_scan_task(target: str):
        """Distributed Burp scan."""
        from tools_integration.burp_api import BurpAPI
        burp = BurpAPI()
        if not burp.is_ready():
            return {"error": "Burp not available"}
        return burp.full_scan(target)


class DistributedScanner:
    """Orchestrate distributed scans across Celery workers."""

    def __init__(self):
        self.available = CELERY_AVAILABLE

    def is_ready(self) -> bool:
        if not self.available:
            return False
        try:
            inspect = app.control.inspect()
            return bool(inspect.active())
        except Exception:
            return False

    def scan_many(
        self,
        targets: List[str],
        scan_type: str = "nmap",
        timeout: int = 1800,
    ) -> Dict:
        """Scan multiple targets in parallel."""
        if not self.available:
            return {"error": "Celery not available"}

        from core.scope_guard import validate_scope

        # Filter out-of-scope targets FIRST
        valid_targets = []
        rejected = []
        for t in targets:
            allowed, reason = validate_scope(t)
            if allowed:
                valid_targets.append(t)
            else:
                rejected.append({"target": t, "reason": reason})

        if rejected:
            console.print(f"[yellow][!] {len(rejected)} targets outside scope[/yellow]")

        if not valid_targets:
            return {"error": "All targets outside scope", "rejected": rejected}

        console.print(
            f"[cyan][*] Distributed scan: {len(valid_targets)} targets "
            f"(type={scan_type})[/cyan]"
        )

        # Submit jobs
        jobs = []
        for t in valid_targets:
            if scan_type == "nuclei":
                j = nuclei_scan_task.delay(t)
            elif scan_type == "burp":
                j = burp_scan_task.delay(t)
            else:
                j = scan_target_task.delay(t, scan_type)
            jobs.append({"target": t, "task_id": j.id})

        # Wait for results
        console.print("[yellow][*] Waiting for results...[/yellow]")
        from celery.result import AsyncResult

        results = []
        for j in jobs:
            try:
                res = AsyncResult(j["task_id"], app=app)
                results.append({
                    "target": j["target"],
                    "task_id": j["task_id"],
                    "result": res.get(timeout=timeout),
                })
            except Exception as e:
                results.append({
                    "target": j["target"],
                    "task_id": j["task_id"],
                    "error": str(e),
                })

        return {
            "total": len(valid_targets),
            "results": results,
            "rejected": rejected,
        }