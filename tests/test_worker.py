"""Tests for ShipCrawlerWorker — batch, retry, CVE, AIS, deep."""

import json
import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from sirb.core import Task, Result
from shipcrawler_worker import ShipCrawlerWorker


# ── Fixtures ────────────────────────────────────────────────────────────

@pytest.fixture
def worker():
    return ShipCrawlerWorker()


@pytest.fixture
def fake_script(tmp_path):
    """Create a fake orchestrate.py that exists."""
    f = tmp_path / "orchestrate.py"
    f.write_text("")
    return f


@pytest.fixture
def mock_vessel():
    return {
        "vessels": 1, "elapsed_seconds": 45.0,
        "results": [{
            "mmsi": "273342890",
            "agents": {"equasis": "ok", "ais": "ok", "shodan_web": "ok"},
            "identity": {
                "vessel_name": "YAZ", "imo": "9735323", "mmsi": "273342890",
                "flag": "Palau", "call_sign": "UBVQ5",
                "type": "Crude Oil Tanker",
                "gt": "22886", "dwt": "36903", "year_built": "2017",
                "status": "In Service",
            },
            "position": {
                "latitude": 59.5, "longitude": 24.5,
                "destination": "TALLINN", "speed": "0.0",
                "course": "0.0", "status": "Moored",
            },
            "compliance": {"detention_rate_36m": "0.00%", "pi": "Unknown"},
            "attack_surface": {
                "shodan": {
                    "imo 9735323": {"total": 0},
                    "port:3000 or port:8080": {"total": 0},
                    '"YAZ" vessel': {"total": 0},
                },
                "summary": {"total_hits": 0},
                "web_osint": {},
            },
            "ownership": {"note": "Not available"},
            "geographical": [],
        }],
    }


@pytest.fixture
def mock_vessel_cves():
    return {
        "vessels": 1, "elapsed_seconds": 45.0,
        "results": [{
            "mmsi": "111111111",
            "agents": {"equasis": "ok", "ais": "ok", "shodan_web": "ok"},
            "identity": {"vessel_name": "HACKME", "flag": "Russia"},
            "position": {"latitude": 60.0, "longitude": 25.0,
                         "destination": "HELSINKI", "speed": "10.5"},
            "compliance": {"detention_rate_36m": "5.00%",
                           "pi": "West of England"},
            "attack_surface": {
                "shodan": {
                    "default": {
                        "total": 3,
                        "matches": [
                            {"ip": "1.2.3.4", "port": 80,
                             "product": "Apache httpd",
                             "vulns": {"CVE-2021-41773": {},
                                       "CVE-2021-40438": {}},
                             "data": "Apache/2.4.49"},
                            {"ip": "1.2.3.5", "port": 22,
                             "product": "OpenSSH",
                             "vulns": {"CVE-2024-6387": {}},
                             "data": "SSH-2.0-OpenSSH_8.9"},
                        ],
                    },
                },
                "summary": {"total_hits": 3},
                "web_osint": {},
            },
        }],
    }


@pytest.fixture
def mock_batch():
    return {
        "vessels": 2, "elapsed_seconds": 75.0,
        "results": [
            {
                "mmsi": "273342890",
                "agents": {"equasis": "ok", "ais": "ok", "shodan_web": "ok"},
                "identity": {"vessel_name": "YAZ", "flag": "Palau"},
                "compliance": {"detention_rate_36m": "0.00%", "pi": "Unknown"},
                "position": {"latitude": 59.5, "longitude": 24.5,
                             "destination": "TALLINN", "speed": "0.0"},
                "attack_surface": {"shodan": {},
                                   "summary": {"total_hits": 0},
                                   "web_osint": {}},
            },
            {
                "mmsi": "311000987",
                "agents": {"equasis": "ok", "ais": "ok", "shodan_web": "ok"},
                "identity": {"vessel_name": "BOREALIS", "flag": "Russia"},
                "compliance": {"detention_rate_36m": "12.50%",
                               "pi": "London Club"},
                "position": {"latitude": 60.0, "longitude": 25.0,
                             "destination": "HELSINKI", "speed": "12.0"},
                "attack_surface": {"shodan": {},
                                   "summary": {"total_hits": 0},
                                   "web_osint": {}},
            },
        ],
    }


# ── Registration ────────────────────────────────────────────────────────

class TestRegistration:
    def test_name(self, worker):
        assert worker.name == "shipcrawler"

    def test_rate_limits(self, worker):
        limits = worker.rate_limits()
        assert "equasis" in limits


# ── Single vessel ──────────────────────────────────────────────────────

class TestSingleVessel:
    @pytest.mark.asyncio
    async def test_missing_mmsi_fails(self, worker):
        result = await worker.execute(Task(worker="shipcrawler"))
        assert result.status == "failure"
        assert "mmsi" in result.error.lower()

    @pytest.mark.asyncio
    async def test_missing_scripts_fails(self, worker):
        with patch("shipcrawler_worker.worker._ORCHESTRATE",
                   Path("/nonexistent/orch.py")):
            result = await worker.execute(Task(
                worker="shipcrawler",
                params={"mmsi": "273342890"},
            ))
        assert result.status == "failure"
        assert "not found" in result.error.lower()
    @pytest.mark.asyncio
    async def test_successful_execution(self, worker, mock_vessel,
                                        fake_script):
        with patch("shipcrawler_worker.worker._ORCHESTRATE", fake_script):
            with patch("shipcrawler_worker.worker.subprocess.run") as mr:
                mr.return_value = MagicMock(
                    returncode=0, stdout=json.dumps(mock_vessel), stderr="")
                result = await worker.execute(Task(
                    worker="shipcrawler",
                    params={"mmsi": "273342890"},
                ))
        assert result.status == "success"
        assert len(result.findings) > 0

    @pytest.mark.asyncio
    async def test_shadow_flag_detected(self, worker, mock_vessel,
                                        fake_script):
        mock_vessel["results"][0]["identity"]["flag"] = "Palau"
        with patch("shipcrawler_worker.worker._ORCHESTRATE", fake_script):
            with patch("shipcrawler_worker.worker.subprocess.run") as mr:
                mr.return_value = MagicMock(
                    returncode=0, stdout=json.dumps(mock_vessel), stderr="")
                result = await worker.execute(Task(
                    worker="shipcrawler",
                    params={"mmsi": "273342890"},
                ))
        ftypes = {f.finding_type for f in result.findings}
        assert "shadow_fleet_flag" in ftypes

    @pytest.mark.asyncio
    async def test_ais_anomaly(self, worker, fake_script):
        vessel = {
            "vessels": 1, "results": [{
                "mmsi": "123456789",
                "agents": {"equasis": "ok", "ais": "ok", "shodan_web": "ok"},
                "identity": {"vessel_name": "ANOMALY", "flag": "RU"},
                "compliance": {"detention_rate_36m": "0.00%", "pi": "Club"},
                "position": {"latitude": 55.0, "longitude": 20.0,
                             "destination": "GDANSK", "speed": "0.0",
                             "status": "Under way using engine"},
                "attack_surface": {"shodan": {},
                                   "summary": {"total_hits": 0},
                                   "web_osint": {}},
            }],
        }
        with patch("shipcrawler_worker.worker._ORCHESTRATE", fake_script):
            with patch("shipcrawler_worker.worker.subprocess.run") as mr:
                mr.return_value = MagicMock(
                    returncode=0, stdout=json.dumps(vessel), stderr="")
                result = await worker.execute(Task(
                    worker="shipcrawler",
                    params={"mmsi": "123456789"},
                ))
        ftypes = {f.finding_type for f in result.findings}
        assert "ais_anomaly" in ftypes


# ── CVE ────────────────────────────────────────────────────────────────

class TestCVEExtraction:
    @pytest.mark.asyncio
    async def test_cve_extracted_from_vulns(self, worker, mock_vessel_cves,
                                            fake_script):
        with patch("shipcrawler_worker.worker._ORCHESTRATE", fake_script):
            with patch("shipcrawler_worker.worker.subprocess.run") as mr:
                mr.return_value = MagicMock(
                    returncode=0, stdout=json.dumps(mock_vessel_cves),
                    stderr="")
                result = await worker.execute(Task(
                    worker="shipcrawler",
                    params={"mmsi": "111111111"},
                ))
        ftypes = {f.finding_type for f in result.findings}
        assert "known_vulnerability" in ftypes
        cves = {f.detail.get("cve", "") for f in result.findings
                if f.finding_type == "known_vulnerability"}
        assert "CVE-2021-41773" in cves
        assert "CVE-2024-6387" in cves


# ── Batch ──────────────────────────────────────────────────────────────

class TestBatchMode:
    @pytest.mark.asyncio
    async def test_batch_two_vessels(self, worker, mock_batch, fake_script):
        with patch("shipcrawler_worker.worker._ORCHESTRATE", fake_script):
            with patch("shipcrawler_worker.worker.subprocess.run") as mr:
                mr.return_value = MagicMock(
                    returncode=0, stdout=json.dumps(mock_batch), stderr="")
                result = await worker.execute(Task(
                    worker="shipcrawler",
                    params={"mmsi": ["273342890", "311000987"]},
                ))
        assert result.status == "success"
        tids = {f.target_id for f in result.findings
                if f.finding_type != "batch_scan"}
        assert "273342890" in tids
        assert "311000987" in tids
        batch_fs = [f for f in result.findings
                    if f.finding_type == "batch_scan"]
        assert len(batch_fs) == 1
        assert batch_fs[0].detail["vessel_count"] == 2

    @pytest.mark.asyncio
    async def test_empty_list_fails(self, worker):
        result = await worker.execute(Task(
            worker="shipcrawler", params={"mmsi": []},
        ))
        assert result.status == "failure"


# ── Equasis retry ─────────────────────────────────────────────────────

class TestEquasisRetry:
    @pytest.mark.asyncio
    async def test_retry_on_rate_limit(self, worker, mock_vessel,
                                       fake_script):
        rate_limited = MagicMock(
            returncode=0, stdout="{}",
            stderr="equasis: VESSEL NOT FOUND — rate limited")
        success = MagicMock(
            returncode=0, stdout=json.dumps(mock_vessel), stderr="")

        with patch("shipcrawler_worker.worker._ORCHESTRATE", fake_script):
            with patch("shipcrawler_worker.worker.subprocess.run") as mr:
                mr.side_effect = [rate_limited, success]
                with patch("shipcrawler_worker.worker.asyncio.sleep"):
                    result = await worker.execute(Task(
                        worker="shipcrawler",
                        params={"mmsi": "273342890"},
                    ))

        assert result.status == "success"
        assert len(result.findings) > 0


# ── Deep mode ─────────────────────────────────────────────────────────

class TestDeepMode:
    @pytest.mark.asyncio
    async def test_falls_back_without_hermes(self, worker, mock_vessel,
                                             fake_script):
        worker._find_hermes = lambda: None
        with patch("shipcrawler_worker.worker._ORCHESTRATE", fake_script):
            with patch("shipcrawler_worker.worker.subprocess.run") as mr:
                mr.return_value = MagicMock(
                    returncode=0, stdout=json.dumps(mock_vessel), stderr="")
                result = await worker.execute(Task(
                    worker="shipcrawler",
                    params={"mmsi": "273342890", "mode": "deep"},
                ))
        assert result.status is not None

    @pytest.mark.asyncio
    async def test_parses_report_files(self, worker, tmp_path):
        worker._find_hermes = lambda: "/usr/bin/hermes"
        with patch("shipcrawler_worker.worker.subprocess.run") as mr:
            mr.return_value = MagicMock(
                returncode=0, stdout="done", stderr="")
            report_dir = tmp_path / "yaz-report"
            report_dir.mkdir()
            merged = {"vessels": 1, "results": [{
                "mmsi": "273342890",
                "agents": {"equasis": "ok", "ais": "ok", "shodan_web": "ok"},
                "identity": {"vessel_name": "YAZ", "flag": "RU"},
                "compliance": {"detention_rate_36m": "0.00%", "pi": "Unknown"},
                "position": {"latitude": 59.5, "longitude": 24.5},
                "attack_surface": {"shodan": {},
                                   "summary": {"total_hits": 0},
                                   "web_osint": {}},
            }]}
            (report_dir / "merged-vessel.json").write_text(json.dumps(merged))

            with patch("shipcrawler_worker.worker._REPORT_BASE", tmp_path):
                result = await worker.execute(Task(
                    worker="shipcrawler",
                    params={"mmsi": "273342890", "mode": "deep"},
                ))
        assert result.status == "success"
        assert len(result.findings) > 0


# ── Discover ───────────────────────────────────────────────────────────

class TestDiscover:
    @pytest.mark.asyncio
    async def test_discover_empty_when_no_file(self, worker):
        with patch.dict(os.environ,
                        {"SIRB_WORKER_DATA": "/tmp/nonexistent"}):
            tasks = await worker.discover()
        assert tasks == []

    @pytest.mark.asyncio
    async def test_discover_from_json(self, worker, tmp_path):
        vessels = [{"mmsi": "273342890", "imo": "9735323"}]
        data_dir = tmp_path / "sirb-data"
        data_dir.mkdir()
        (data_dir / "vessels.json").write_text(json.dumps(vessels))
        with patch.dict(os.environ, {"SIRB_WORKER_DATA": str(data_dir)}):
            tasks = await worker.discover()
        assert len(tasks) == 1


# ── Validate ───────────────────────────────────────────────────────────

class TestValidate:
    @pytest.mark.asyncio
    async def test_accepts_success(self, worker):
        assert await worker.validate(Result(status="success")) is True

    @pytest.mark.asyncio
    async def test_rejects_failure(self, worker):
        assert await worker.validate(Result(status="failure")) is False
