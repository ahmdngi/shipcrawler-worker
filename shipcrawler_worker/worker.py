"""ShipCrawler worker for Sirb — vessel OSINT via the shipcrawler-parallel pipeline.

This worker lives in its own repo so Sirb remains agnostic. Install::

    pip install git+https://github.com/ahmdngi/shipcrawler-worker.git

Then pip install discovers it automatically via ``sirb_workers`` entry point.
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import subprocess
import sys
import time
from pathlib import Path
from typing import Optional

from sirb.core import SirbWorker, Task, Result, Finding


# Path to the shipcrawler-parallel orchestrate.py
_SC_SCRIPTS = Path(
    os.path.expanduser("~/.hermes/skills/research/shipcrawler-parallel/scripts")
)
_ORCHESTRATE = _SC_SCRIPTS / "orchestrate.py"
_REPORT_BASE = Path(os.path.expanduser("~/hermes-vault/osint-reports"))

# Known shadow fleet flags
_SHADOW_FLAGS = {"palau", "togo", "comoros", "tanzania", "cameroon",
                 "sierra leone", "cook islands", "dominica"}

# Products associated with maritime satellite comms (elevates severity)
_VSAT_KEYWORDS = ["VSAT", "SAILOR", "KVH", "Inmarsat", "Iridium", "Starlink"]

# Equasis rate-limit indicators
_EQUASIS_RATELIMIT_PATTERNS = [
    re.compile(r"VESSEL NOT FOUND", re.IGNORECASE),
    re.compile(r"Failed to parse", re.IGNORECASE),
    re.compile(r"rate.limit", re.IGNORECASE),
    re.compile(r"too many requests", re.IGNORECASE),
]


class ShipCrawlerWorker(SirbWorker):
    """Execute vessel OSINT investigations via the ShipCrawler pipeline.

    Supports:
    - Single vessel (``params: {mmsi: \"...\"}``)
    - Batch mode (``params: {mmsi: [\"...\", \"...\"]}``) — one pipeline call
      handles up to 3 MMSIs in parallel internally
    - Fast mode (~2 min) and deep mode (~10 min, agent-driven)
    - Automatic retry on Equasis rate limiting
    - Multi-finding extraction: Shodan, AIS, compliance, shadow fleet, CVE
    """

    name = "shipcrawler"
    description = "Vessel OSINT via Equasis + AIS + Shodan/Web pipeline"

    _port_config: dict = {}

    def __init__(self, config: Optional[dict] = None):
        super().__init__()
        config = config or {}
        self._config = config
        self._port_config = config.get("ports", {})

    # ── required: execute ───────────────────────────────────────────────

    async def execute(self, task: Task) -> Result:
        """Run ShipCrawler on one or more vessels.

        Task params:
            - ``mmsi`` (required): single MMSI string **or** list of MMSIs
            - ``imo`` (optional): IMO number (single vessel only)
            - ``name`` (optional): vessel name hint
            - ``mode`` (optional): ``"fast"`` (default) or ``"deep"``
        """
        mmsi_raw = task.params.get("mmsi", [])
        if isinstance(mmsi_raw, str):
            mmsi_list = [mmsi_raw]
        elif isinstance(mmsi_raw, list):
            mmsi_list = mmsi_raw
        else:
            return Result(task_id=task.id, worker=self.name, status="failure",
                          error="Task.params 'mmsi' must be a string or list")

        if not mmsi_list:
            return Result(task_id=task.id, worker=self.name, status="failure",
                          error="Task.params 'mmsi' is empty")

        mode = task.params.get("mode", "fast")

        # Single vessel
        if len(mmsi_list) == 1:
            mmsi = mmsi_list[0]
            imo = task.params.get("imo", "")
            name = task.params.get("name", task.params.get("vessel_name", ""))

            if mode == "deep":
                return await self._execute_deep(task, [mmsi], {mmsi: {"imo": imo, "name": name}})
            return await self._execute_fast(task, mmsi, imo, name)

        # Batch — multiple vessels in one pipeline call
        name_map = {}
        vessel_params = task.params.get("vessels", {})
        for m in mmsi_list:
            vp = vessel_params.get(m, {})
            name_map[m] = {
                "imo": vp.get("imo", ""),
                "name": vp.get("name", ""),
            }

        if mode == "deep":
            return await self._execute_deep(task, mmsi_list, name_map)
        return await self._execute_batch(task, mmsi_list, name_map)

    # ── fast mode: subprocess orchestrate.py ────────────────────────────

    async def _execute_fast(self, task: Task, mmsi: str,
                            imo: str, name: str) -> Result:
        """Run the parallel pipeline on a single vessel."""
        if not _ORCHESTRATE.exists():
            return Result(task_id=task.id, worker=self.name, status="failure",
                          error=f"ShipCrawler scripts not found at {_ORCHESTRATE}")

        cmd = self._build_cmd(mmsi=mmsi, imo=imo, name=name)

        proc = await self._run_cmd(cmd, timeout=300)
        if isinstance(proc, Result):
            return proc  # already a failure result

        output, is_ratelimit = self._parse_output(proc)
        if is_ratelimit:
            # Retry once after 30s cooldown
            print(f"[shipcrawler] Equasis rate-limit detected for {mmsi}, "
                  f"retrying in 30s...")
            await asyncio.sleep(30)
            proc = await self._run_cmd(cmd, timeout=300)
            if isinstance(proc, Result):
                return proc
            output, _ = self._parse_output(proc)

        return self._vessel_to_result(task, mmsi, output, name)

    async def _execute_batch(self, task: Task, mmsi_list: list[str],
                             name_map: dict) -> Result:
        """Run pipeline once for up to 3 MMSIs in parallel internally."""
        if not _ORCHESTRATE.exists():
            return Result(task_id=task.id, worker=self.name, status="failure",
                          error=f"ShipCrawler scripts not found at {_ORCHESTRATE}")

        if not mmsi_list:
            return Result(task_id=task.id, worker=self.name, status="failure",
                          error="Empty batch")

        all_findings = []
        all_artifacts = []
        all_errors = []
        max_retries = 2

        for i in range(0, len(mmsi_list), 3):
            batch = mmsi_list[i:i + 3]
            cmd_base = [sys.executable, str(_ORCHESTRATE), "--parallel",
                        "--report", "--quiet"]
            for m in batch:
                cmd_base.extend(["--mmsi", m])
                vp = name_map.get(m, {})
                if vp.get("imo"):
                    cmd_base.extend(["--imo", vp["imo"]])
                if vp.get("name"):
                    cmd_base.extend(["--name", vp["name"]])

            for attempt in range(max_retries):
                proc = await self._run_cmd(cmd_base, timeout=360)
                if isinstance(proc, Result):
                    # Fatal error, add error finding
                    all_errors.append(f"batch-{i}: {proc.error}")
                    break

                output, is_ratelimit = self._parse_output(proc)
                if is_ratelimit and attempt < max_retries - 1:
                    print(f"[shipcrawler] Equasis rate-limit in batch, "
                          f"retrying in 30s...")
                    await asyncio.sleep(30)
                    continue

                # Extract findings per vessel
                results = output.get("results", [])
                for v in results:
                    vmmsi = v.get("mmsi", "")
                    findings = self._extract_findings(v, vmmsi)
                    all_findings.extend(findings)

                    vname = v.get("identity", {}).get("vessel_name", vmmsi)
                    report_dir = _REPORT_BASE / f"{vname.replace(' ', '-').lower()}-report"
                    for fname in ["merged-vessel.json", "analyst-report.md",
                                  "red-team-playbook.md", "indicators-and-detection.md"]:
                        p = report_dir / fname
                        if p.exists() and str(p) not in all_artifacts:
                            all_artifacts.append(str(p))

                break

        status = "success"
        if all_errors and not all_findings:
            status = "failure"
        elif all_errors:
            status = "partial"

        # Add batch-level aggregate finding
        all_findings.append(Finding(
            target_id=",".join(mmsi_list[:5]),
            target_type="batch",
            finding_type="batch_scan",
            severity="info",
            weight=0.1,
            detail={
                "vessel_count": len(mmsi_list),
                "vessels": mmsi_list,
                "findings_total": len(all_findings),
            },
            source="shipcrawler",
            worker=self.name,
            created_at=time.time(),
        ))

        return Result(
            task_id=task.id, worker=self.name, status=status,
            findings=all_findings, artifacts=all_artifacts,
            error="; ".join(all_errors) if all_errors else "",
        )

    # ── deep mode: Hermes agent-driven ──────────────────────────────────

    async def _execute_deep(self, task: Task, mmsi_list: list[str],
                            name_map: dict) -> Result:
        """Run agent-driven ShipCrawler via hermes chat, parse reports."""
        hermes = self._find_hermes()
        if not hermes:
            # Fall back to fast batch for all vessels
            return await self._execute_batch(task, mmsi_list, name_map)

        vessels_str = ", ".join(mmsi_list)
        query = f"Run ShipCrawler on MMSI(s) {vessels_str}"
        cmd = [hermes, "chat", "-q", "--skills", "shipcrawler", "--", query]

        proc = await self._run_cmd(cmd, timeout=600)
        if isinstance(proc, Result):
            return proc

        # Try to find report files generated by the agent
        all_findings = []
        all_artifacts = []

        for mmsi in mmsi_list:
            # Scan report dirs for this vessel
            for d in _REPORT_BASE.iterdir():
                if not d.is_dir():
                    continue
                merged = d / "merged-vessel.json"
                if not merged.exists():
                    continue
                try:
                    data = json.loads(merged.read_text())
                    results = data.get("results", [])
                    for v in results:
                        if v.get("mmsi") == mmsi:
                            all_findings.extend(
                                self._extract_findings(v, mmsi))
                            for fname in [
                                "merged-vessel.json", "analyst-report.md",
                                "red-team-playbook.md",
                                "indicators-and-detection.md",
                            ]:
                                p = d / fname
                                if p.exists():
                                    all_artifacts.append(str(p))
                            break
                except (json.JSONDecodeError, Exception):
                    continue

        if not all_findings:
            # Fallback: return raw output stub
            lines = proc.stdout.splitlines() if proc.stdout else []
            return Result(
                task_id=task.id, worker=self.name, status="partial",
                findings=[],
                raw={"stdout_tail": "\n".join(lines[-30:])},
                error="Deep mode ran but no structured findings parsed",
            )

        return Result(
            task_id=task.id, worker=self.name, status="success",
            findings=all_findings, artifacts=all_artifacts,
        )

    # ── finding extraction ─────────────────────────────────────────────

    def _extract_findings(self, vessel: dict, mmsi: str) -> list[Finding]:
        """Convert a ShipCrawler merged vessel record into Sirb findings."""
        findings = []
        identity = vessel.get("identity", {})
        attack = vessel.get("attack_surface", {})
        shodan_summary = attack.get("summary", {})
        shodan_data = attack.get("shodan", {})
        web_osint = attack.get("web_osint", {})
        compliance = vessel.get("compliance", {})
        position = vessel.get("position", {})

        vessel_name = identity.get("vessel_name", "unknown")
        now = time.time()

        # ── Shodan exposure ──
        findings.extend(self._shodan_findings(
            shodan_summary, shodan_data, mmsi, vessel_name, now))

        # ── Compliance / PSC ──
        findings.extend(self._compliance_findings(
            compliance, mmsi, now))

        # ── Shadow fleet ──
        findings.extend(self._shadow_fleet_findings(
            identity, compliance, mmsi, vessel_name, now))

        # ── CVE enrichment from Shodan matches ──
        findings.extend(self._cve_findings(
            shodan_data, mmsi, now))

        # ── Web OSINT ──
        findings.extend(self._web_osint_findings(
            web_osint, mmsi, now))

        # ── AIS position + intelligence ──
        findings.extend(self._ais_findings(
            position, vessel, mmsi, now))

        return findings

    # ── finding sub-methods ─────────────────────────────────────────────

    def _shodan_findings(self, summary: dict, data: dict,
                         mmsi: str, vessel_name: str,
                         now: float) -> list[Finding]:
        findings = []
        total_hits = summary.get("total_hits", -1)

        if total_hits > 0:
            findings.append(Finding(
                target_id=mmsi, target_type="vessel",
                finding_type="shodan_exposure",
                severity="critical" if total_hits > 10 else "high",
                weight=min(1.0, total_hits / 20),
                detail={"total_hits": total_hits,
                        "queries": list(data.keys())},
                source="shodan", worker=self.name, created_at=now,
            ))

            for query, result in data.items():
                q_hits = result.get("total", 0)
                if q_hits <= 0:
                    continue
                matches = result.get("matches", [])
                products = list(set(
                    m.get("product", "") for m in matches
                    if m.get("product")
                ))
                ips = [m.get("ip", "") for m in matches[:3]]
                is_vsat = any(
                    any(kw in (p or "").upper()
                        for kw in _VSAT_KEYWORDS)
                    for p in products
                )

                findings.append(Finding(
                    target_id=mmsi, target_type="vessel",
                    finding_type="exposed_service",
                    severity="high" if is_vsat else "medium",
                    weight=min(1.0, q_hits / 10),
                    detail={"query": query, "hits": q_hits,
                            "products": products, "sample_ips": ips},
                    source="shodan", worker=self.name, created_at=now,
                ))

        elif total_hits == 0:
            findings.append(Finding(
                target_id=mmsi, target_type="vessel",
                finding_type="no_exposure",
                severity="info", weight=0.2,
                detail={"note": "No Shodan-visible services detected"},
                source="shodan", worker=self.name, created_at=now,
            ))

        return findings

    def _compliance_findings(self, compliance: dict, mmsi: str,
                             now: float) -> list[Finding]:
        findings = []

        detention_rate = compliance.get("detention_rate_36m", "")
        if detention_rate and detention_rate != "0.00%":
            try:
                rate_val = float(detention_rate.strip("%"))
            except ValueError:
                rate_val = 0
            findings.append(Finding(
                target_id=mmsi, target_type="vessel",
                finding_type="psc_detention",
                severity="high" if rate_val > 10 else "medium",
                weight=min(1.0, rate_val / 50),
                detail={"detention_rate_36m": detention_rate},
                source="equasis", worker=self.name, created_at=now,
            ))

        return findings

    def _shadow_fleet_findings(self, identity: dict, compliance: dict,
                               mmsi: str, vessel_name: str,
                               now: float) -> list[Finding]:
        findings = []

        pi_value = compliance.get("pi", "")
        if not pi_value or "unknown" in pi_value.lower():
            findings.append(Finding(
                target_id=mmsi, target_type="vessel",
                finding_type="no_pi_insurance",
                severity="high", weight=0.9,
                detail={"pi_club": pi_value},
                source="equasis", worker=self.name, created_at=now,
            ))

        flag = (identity.get("flag") or "").lower()
        if flag in _SHADOW_FLAGS:
            findings.append(Finding(
                target_id=mmsi, target_type="vessel",
                finding_type="shadow_fleet_flag",
                severity="critical", weight=0.95,
                detail={"flag": flag, "vessel_name": vessel_name},
                source="equasis", worker=self.name, created_at=now,
            ))

        # Check manager country — if in sanctioned/conflict zones
        manager = compliance.get("manager", {}).get("country", "")
        if manager and manager.upper() in ("RU", "IR", "KP", "SY"):
            findings.append(Finding(
                target_id=mmsi, target_type="vessel",
                finding_type="sanctioned_manager",
                severity="critical", weight=0.9,
                detail={"manager_country": manager},
                source="equasis", worker=self.name, created_at=now,
            ))

        return findings

    def _cve_findings(self, shodan_data: dict, mmsi: str,
                      now: float) -> list[Finding]:
        """Extract CVE references from Shodan match banners."""
        findings = []
        seen_cves: set[str] = set()

        for query, result in shodan_data.items():
            for match in result.get("matches", []):
                # Check cpe, vulns, or banner for CVE mentions
                vulns = match.get("vulns", {})
                if isinstance(vulns, dict):
                    for cve_id in vulns:
                        if cve_id.upper().startswith("CVE-") and cve_id not in seen_cves:
                            seen_cves.add(cve_id)
                            findings.append(Finding(
                                target_id=mmsi, target_type="vessel",
                                finding_type="known_vulnerability",
                                severity="critical",
                                weight=0.85,
                                detail={"cve": cve_id, "query": query,
                                        "product": match.get("product", ""),
                                        "port": match.get("port", "")},
                                source="shodan", worker=self.name,
                                created_at=now,
                            ))

                # Also scan banner text for CVE patterns
                banner = match.get("data", "") or match.get("banner", "") or ""
                for cve_match in re.finditer(r"CVE-\d{4}-\d{4,7}", banner, re.IGNORECASE):
                    cve_id = cve_match.group(0).upper()
                    if cve_id not in seen_cves:
                        seen_cves.add(cve_id)
                        findings.append(Finding(
                            target_id=mmsi, target_type="vessel",
                            finding_type="known_vulnerability",
                            severity="high",
                            weight=0.7,
                            detail={"cve": cve_id, "source": "banner",
                                    "query": query,
                                    "port": match.get("port", "")},
                            source="shodan", worker=self.name,
                            created_at=now,
                        ))

        return findings

    def _web_osint_findings(self, web_osint: dict, mmsi: str,
                            now: float) -> list[Finding]:
        findings = []
        for category, hits in web_osint.items():
            if hits:
                findings.append(Finding(
                    target_id=mmsi, target_type="vessel",
                    finding_type="web_osint",
                    severity="medium", weight=0.6,
                    detail={"category": category, "hits": hits[:5]},
                    source="web", worker=self.name, created_at=now,
                ))
        return findings

    def _ais_findings(self, position: dict, vessel: dict,
                      mmsi: str, now: float) -> list[Finding]:
        """Extract position, destination, and port call intelligence."""
        findings = []

        # ── Current position ──
        if position and position.get("latitude"):
            dest = position.get("destination", "")
            speed = position.get("speed", "")
            status = position.get("status", "")

            position_detail = {
                "lat": position.get("latitude"),
                "lon": position.get("longitude"),
                "destination": dest,
                "speed": speed,
            }
            if status:
                position_detail["status"] = status

            findings.append(Finding(
                target_id=mmsi, target_type="vessel",
                finding_type="current_position",
                severity="info", weight=0.3,
                detail=position_detail,
                source="ais", worker=self.name, created_at=now,
            ))

            # ── Destination change detection ──
            # (In future: compare against previous run's destination)
            if dest and dest.strip().upper() not in ("", "FOR ORDERS",
                                                       "WAITING", "UNKNOWN"):
                findings.append(Finding(
                    target_id=mmsi, target_type="vessel",
                    finding_type="ais_destination",
                    severity="info", weight=0.4,
                    detail={"destination": dest.strip(),
                            "speed": speed, "status": status},
                    source="ais", worker=self.name, created_at=now,
                ))

            # ── Status anomaly ──
            if status and "under way" in status.lower() and speed in ("0.0", "0.1", ""):
                findings.append(Finding(
                    target_id=mmsi, target_type="vessel",
                    finding_type="ais_anomaly",
                    severity="medium", weight=0.5,
                    detail={"anomaly": "Under way but speed=0",
                            "status": status, "speed": speed},
                    source="ais", worker=self.name, created_at=now,
                ))

        # ── Port calls from AIS agent data ──
        # The AIS extractor captures raw port call data under
        # vessel["position"]. Some orchestrator versions include it
        port_calls = vessel.get("port_calls", vessel.get("position", {}).get("port_calls", []))
        if isinstance(port_calls, list) and port_calls:
            recent = port_calls[:5]
            findings.append(Finding(
                target_id=mmsi, target_type="vessel",
                finding_type="port_calls",
                severity="info", weight=0.3,
                detail={"recent_calls": recent, "total": len(port_calls)},
                source="ais", worker=self.name, created_at=now,
            ))

        return findings

    # ── discover ────────────────────────────────────────────────────────

    async def discover(self) -> list[Task]:
        """Discover vessels from static file and port scans."""
        tasks = []

        # 1. Static vessel file
        data_dir = os.environ.get(
            "SIRB_WORKER_DATA",
            os.path.expanduser("~/hermes-vault/sirb-data"),
        )
        vessels_file = Path(data_dir) / "vessels.json"
        if vessels_file.exists():
            try:
                with open(vessels_file) as f:
                    vessels = json.load(f)
                for v in vessels:
                    mmsi = v.get("mmsi", v.get("MMSI", ""))
                    if mmsi:
                        tasks.append(Task(
                            type="vessel_osint", worker=self.name,
                            params=v, priority=v.get("priority", 1),
                        ))
            except Exception as e:
                print(f"[shipcrawler] WARN: failed to read {vessels_file}: {e}")

        # 2. AIS port scanning
        if self._port_config:
            from shipcrawler_worker.discovery import PortConfig, PortScanner
            port_cfg = PortConfig(self._port_config)
            for key in self._port_config.keys():
                port_def = port_cfg.get(key)
                if not port_def:
                    continue
                scanner = PortScanner(port_def)
                vessels = await scanner.scan()
                for v in vessels:
                    mmsi = v.get("mmsi", "")
                    if mmsi:
                        tasks.append(Task(
                            type="vessel_osint", worker=self.name,
                            params={"mmsi": mmsi, "name": v.get("name", ""),
                                    "port": key},
                            priority=0,
                        ))

        # 3. Geo-targeted area scan (lat/lon + radius)
        geo_config = self._config.get("geo_targets", []) if hasattr(self, "_config") else []
        if not geo_config:
            geo_config = os.environ.get("SIRB_GEO_TARGETS", "")
            if geo_config:
                try:
                    geo_config = json.loads(geo_config)
                except Exception:
                    geo_config = []
        if geo_config:
            from shipcrawler_worker.discovery import GeoScanner
            for gt in geo_config:
                lat = gt.get("lat")
                lon = gt.get("lon")
                radius_km = gt.get("radius_km", 50)
                label = gt.get("label", f"{lat},{lon}")
                if lat is None or lon is None:
                    continue
                scanner = GeoScanner(lat=lat, lon=lon, radius_km=radius_km)
                vessels = await scanner.scan()
                print(f"[shipcrawler] geo scan @ {label}: "
                      f"{len(vessels)} vessel(s)")
                for v in vessels:
                    mmsi = v.get("mmsi", "")
                    if mmsi:
                        tasks.append(Task(
                            type="vessel_osint", worker=self.name,
                            params={"mmsi": mmsi,
                                    "name": v.get("name", ""),
                                    "geo": label,
                                    "lat": v.get("lat"),
                                    "lon": v.get("lon"),
                                    "destination": v.get("destination", "")},
                            priority=0,
                        ))

        return tasks

    # ── validate ────────────────────────────────────────────────────────

    async def validate(self, result: Result) -> bool:
        if result.status == "failure":
            return False
        return True

    # ── rate limits ─────────────────────────────────────────────────────

    def rate_limits(self) -> dict[str, int]:
        return {
            "equasis": 4,
            "shodan": 30,
            "vesselfinder": 30,
        }

    # ── internal helpers ────────────────────────────────────────────────

    def _build_cmd(self, mmsi: str, imo: str = "",
                   name: str = "") -> list[str]:
        cmd = [
            sys.executable, str(_ORCHESTRATE),
            "--mmsi", mmsi, "--parallel", "--report", "--quiet",
        ]
        if imo:
            cmd.extend(["--imo", imo])
        if name:
            cmd.extend(["--name", name])
        return cmd

    async def _run_cmd(self, cmd: list[str],
                       timeout: int) -> subprocess.CompletedProcess | Result:
        """Run a subprocess, returning the proc or a failure Result."""
        try:
            loop = asyncio.get_event_loop()
            proc = await asyncio.wait_for(
                loop.run_in_executor(
                    None,
                    lambda: subprocess.run(
                        cmd, capture_output=True, text=True, timeout=timeout,
                    ),
                ),
                timeout=timeout + 10,
            )
        except asyncio.TimeoutError:
            return Result(
                task_id="", worker=self.name, status="failure",
                error=f"ShipCrawler timed out after {timeout}s",
            )

        if proc.returncode != 0:
            return Result(
                task_id="", worker=self.name, status="failure",
                error=f"ShipCrawler exited {proc.returncode}: "
                      f"{proc.stderr[:500] if proc.stderr else ''}",
            )
        return proc

    def _parse_output(self, proc: subprocess.CompletedProcess
                      ) -> tuple[dict, bool]:
        """Parse stdout JSON, returning (output, is_rate_limited)."""
        is_ratelimit = False

        # Check stderr for rate-limit signals
        if proc.stderr:
            for pattern in _EQUASIS_RATELIMIT_PATTERNS:
                if pattern.search(proc.stderr):
                    is_ratelimit = True
                    break

        # Try parsing stdout
        try:
            output = json.loads(proc.stdout)
        except json.JSONDecodeError:
            # Check stdout for rate-limit signals
            if proc.stdout:
                for pattern in _EQUASIS_RATELIMIT_PATTERNS:
                    if pattern.search(proc.stdout):
                        is_ratelimit = True
                        break
            return {}, is_ratelimit

        # Check if any results indicate rate-limit
        for result in output.get("results", []):
            for agent, status_val in result.get("agents", {}).items():
                if "fail" in str(status_val).lower() or "error" in str(status_val).lower():
                    for pattern in _EQUASIS_RATELIMIT_PATTERNS:
                        if pattern.search(str(status_val)):
                            is_ratelimit = True
                            break

        return output, is_ratelimit

    def _vessel_to_result(self, task: Task, mmsi: str,
                          output: dict, name_hint: str) -> Result:
        """Convert a parsed vessel output dict into a Sirb Result."""
        results = output.get("results", [])
        if not results:
            return Result(task_id=task.id, worker=self.name, status="failure",
                          error="ShipCrawler returned empty results")

        vessel = results[0]
        identity = vessel.get("identity", {})
        vessel_name = identity.get("vessel_name", name_hint or mmsi)

        findings = self._extract_findings(vessel, mmsi)

        # Artifacts
        safe_name = vessel_name.replace(" ", "-").lower()
        report_dir = _REPORT_BASE / f"{safe_name}-report"
        artifacts = []
        for fname in ["merged-vessel.json", "analyst-report.md",
                       "red-team-playbook.md", "indicators-and-detection.md"]:
            p = report_dir / fname
            if p.exists():
                artifacts.append(str(p))

        # Determine status
        agent_errors = []
        for agent, status_val in vessel.get("agents", {}).items():
            if status_val != "ok":
                agent_errors.append(f"{agent}: {status_val}")

        result_status = "success"
        if agent_errors and not findings:
            result_status = "failure"
        elif agent_errors:
            result_status = "partial"

        return Result(
            task_id=task.id, worker=self.name, status=result_status,
            findings=findings, artifacts=artifacts, raw=vessel,
            error="; ".join(agent_errors) if agent_errors else "",
        )

    def _find_hermes(self) -> Optional[str]:
        """Locate the Hermes CLI binary."""
        for p in ["hermes", "/usr/local/bin/hermes",
                  "/usr/local/lib/hermes-agent/venv/bin/hermes"]:
            if os.path.isfile(p) and os.access(p, os.X_OK):
                return p
        for p in os.environ.get("PATH", "").split(":"):
            candidate = os.path.join(p, "hermes")
            if os.path.isfile(candidate) and os.access(candidate, os.X_OK):
                return candidate
        return None
