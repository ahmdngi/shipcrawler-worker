"""Geo scanner — discover vessels within a geographic radius.

Given a center point (lat, lon) and radius (km), computes a bounding
box and queries VesselFinder for vessels in that area.
"""

from __future__ import annotations

import math
import time
from typing import Optional

from .port_config import PortDefinition


class GeoScanner:
    """Discover vessels within a geographic radius.

    Usage::

        scanner = GeoScanner(lat=59.5, lon=24.5, radius_km=50)
        vessels = await scanner.scan()
        # => [{"mmsi": "273342890", "name": "YAZ", ...}]
    """

    # Earth radius in km
    _EARTH_R = 6371.0

    def __init__(self, lat: float, lon: float, radius_km: float = 50):
        self._lat = lat
        self._lon = lon
        self._radius_km = radius_km
        self._bounds = self._compute_bounds()

    def bounds(self) -> dict[str, float]:
        """Return bounding box as {lat_min, lat_max, lon_min, lon_max}."""
        return dict(self._bounds)

    # ── scan ─────────────────────────────────────────────────────────────

    async def scan(self) -> list[dict]:
        """Scan VesselFinder for vessels in this area.

        Returns list of dicts::
            [{"mmsi": "273342890", "name": "YAZ",
              "lat": 59.5, "lon": 24.5, "destination": "TALLINN"}]
        """
        vessels = await self._scan_vesselfinder_map()
        if vessels:
            # Filter to bounding box (double-check)
            b = self._bounds
            filtered = [
                v for v in vessels
                if (b["lat_min"] <= v.get("lat", 0) <= b["lat_max"]
                    and b["lon_min"] <= v.get("lon", 0) <= b["lon_max"])
            ]
            if filtered:
                return filtered
            return vessels

        return []

    async def _scan_vesselfinder_map(self) -> list[dict]:
        """Scrape VesselFinder's vessel list table for area data."""
        browser = None
        p = None
        use_cloak = False

        try:
            import cloakbrowser
            use_cloak = True
        except ImportError:
            try:
                from playwright.sync_api import sync_playwright
                use_cloak = False
            except ImportError:
                return []

        url = "https://www.vesselfinder.com/vessels"

        try:
            if use_cloak:
                from cloakbrowser import launch
                browser = launch(headless=True, args=["--no-sandbox"])
                page = browser.new_page()
            else:
                from playwright.sync_api import sync_playwright
                p = sync_playwright().start()
                browser = p.chromium.launch(
                    headless=True,
                    args=["--no-sandbox", "--disable-setuid-sandbox"],
                )
                page = browser.new_page()

            page.goto(url, wait_until="networkidle", timeout=30000)
            time.sleep(3)

            vessels = page.evaluate("""(() => {
                const rows = document.querySelectorAll('table.vessels-table tbody tr, table tr');
                const vessels = [];
                for (const row of rows) {
                    const cells = row.querySelectorAll('td');
                    if (cells.length < 3) continue;
                    const v = {};
                    const links = row.querySelectorAll('a');
                    for (const link of links) {
                        const m = link.href.match(/\\/vessels\\/details\\/(\\d{7,9})/);
                        if (m) v.mmsi = m[1];
                        if (link.classList.contains('vessel-name')) {
                            v.name = link.innerText.trim();
                        }
                    }
                    // Position from cell text
                    cells.forEach((cell, i) => {
                        const text = cell.innerText.trim();
                        if (i === 0 && !v.name) v.name = text;
                        if (i === cells.length - 1) {
                            // Last cell often has destination
                            v.destination = text;
                        }
                    });
                    if (v.mmsi || v.name) vessels.push(v);
                }
                return vessels;
            })()""")

            browser.close()
            if p:
                p.stop()

            return vessels

        except Exception as e:
            print(f"[geo] VesselFinder scan failed: {e}")
            if browser:
                try:
                    browser.close()
                except Exception:
                    pass
            return []

    # ── helpers ──────────────────────────────────────────────────────────

    def _compute_bounds(self) -> dict[str, float]:
        """Compute bounding box from center + radius."""
        r = self._radius_km / self._EARTH_R  # angular radius in radians
        lat_r = math.radians(self._lat)
        lon_r = math.radians(self._lon)

        lat_min = math.degrees(lat_r - r)
        lat_max = math.degrees(lat_r + r)
        lon_min = math.degrees(lon_r - r / math.cos(lat_r))
        lon_max = math.degrees(lon_r + r / math.cos(lat_r))

        return {
            "lat_min": lat_min, "lat_max": lat_max,
            "lon_min": lon_min, "lon_max": lon_max,
        }

    @staticmethod
    def haversine(lat1: float, lon1: float,
                  lat2: float, lon2: float) -> float:
        """Great-circle distance in km between two points."""
        R = GeoScanner._EARTH_R
        dlat = math.radians(lat2 - lat1)
        dlon = math.radians(lon2 - lon1)
        a = (math.sin(dlat / 2) ** 2
             + math.cos(math.radians(lat1))
             * math.cos(math.radians(lat2))
             * math.sin(dlon / 2) ** 2)
        return R * 2 * math.atan2(math.sqrt(a), math.sqrt(1 - a))
