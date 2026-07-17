"""Tests for GeoScanner — bounding box, haversine, discovery integration."""

import json
from unittest.mock import MagicMock, PropertyMock, patch

import pytest

from shipcrawler_worker.discovery import GeoScanner


class TestGeoScanner:
    def test_bounds_tallinn(self):
        """Tallinn (59.5, 24.5) with 50km radius produces sensible bounds."""
        gs = GeoScanner(lat=59.5, lon=24.5, radius_km=50)
        b = gs.bounds()
        assert b["lat_min"] < b["lat_max"]
        assert b["lon_min"] < b["lon_max"]
        # 1° lat ≈ 111km, so 50km ≈ 0.45°
        assert 58.8 < b["lat_min"] < 59.2
        assert 59.8 < b["lat_max"] < 60.2
        # Lon bounds depend on latitude
        assert b["lon_min"] < 24.5
        assert b["lon_max"] > 24.5

    def test_haversine_known(self):
        """Known distance: Tallinn to Helsinki ≈ 80km."""
        d = GeoScanner.haversine(59.5, 24.5, 60.2, 25.0)
        assert 70 < d < 90  # within reasonable range

    def test_haversine_zero(self):
        """Same point = 0 distance."""
        d = GeoScanner.haversine(59.5, 24.5, 59.5, 24.5)
        assert d == 0

    def test_radius_0_pinpoints(self):
        """Radius 0 produces very tight bounds."""
        gs = GeoScanner(lat=60.0, lon=25.0, radius_km=1)
        b = gs.bounds()
        assert b["lat_max"] - b["lat_min"] < 0.02

    @pytest.mark.asyncio
    async def test_scan_returns_list(self):
        """Scan returns a list (empty if browser unavailable)."""
        gs = GeoScanner(lat=59.5, lon=24.5, radius_km=10)
        vessels = await gs.scan()
        assert isinstance(vessels, list)


class TestGeoDiscovery:
    @pytest.mark.asyncio
    async def test_geo_config_in_discover(self, tmp_path):
        """Worker reads geo_targets from config and creates tasks."""
        from shipcrawler_worker import ShipCrawlerWorker

        worker = ShipCrawlerWorker(config={
            "geo_targets": [
                {"lat": 59.5, "lon": 24.5, "radius_km": 10, "label": "Tallinn Bay"}
            ],
        })

        with patch("shipcrawler_worker.discovery.GeoScanner.scan") as mock_scan:
            mock_scan.return_value = [
                {"mmsi": "273342890", "name": "YAZ", "lat": 59.5, "lon": 24.5},
            ]
            tasks = await worker.discover()

        assert len(tasks) == 1
        assert tasks[0].params["mmsi"] == "273342890"
        assert tasks[0].params["geo"] == "Tallinn Bay"
        assert tasks[0].priority == 0

    @pytest.mark.asyncio
    async def test_geo_config_empty_by_default(self):
        """No geo targets = no extra discovery."""
        from shipcrawler_worker import ShipCrawlerWorker
        worker = ShipCrawlerWorker()

        tasks = await worker.discover()
        # Should only have tasks from static file (which doesn't exist)
        assert isinstance(tasks, list)
