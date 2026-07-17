"""Port scanner for ShipCrawler worker — discovers vessels in a port.

Uses Playwright (or CloakBrowser) to scrape VesselFinder port pages,
extracting vessel names, MMSIs, and positions.
"""

from __future__ import annotations

import time
import re
from typing import Optional

from .port_config import PortDefinition


class PortScanner:
    """Scan a port's vessel list from VesselFinder."""

    def __init__(self, port: PortDefinition):
        self._port = port

    async def scan(self) -> list[dict]:
        """Scan vessels currently in this port.

        Returns::
            [{"mmsi": "273342890", "name": "YAZ", "type": "...", "destination": "..."}]
        """
        vessels = await self._scan_vesselfinder()
        if vessels:
            return vessels

        print(f"[shipcrawler] No vessels found for {self._port.name} "
              f"(browser may be unavailable)")
        return []

    async def _scan_vesselfinder(self) -> list[dict]:
        """Scrape VesselFinder port page for vessel list."""
        url = self._port.vessel_finder_url
        if not url:
            return []

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

            raw = page.evaluate("""(() => {
                const vessels = [];
                const rows = document.querySelectorAll('tr');
                for (const row of rows) {
                    const cells = row.querySelectorAll('td');
                    if (cells.length < 3) continue;
                    const vessel = {};
                    const links = row.querySelectorAll('a');
                    for (const link of links) {
                        const m = link.href.match(/\\/vessels\\/details\\/(\\d{7,9})/);
                        if (m) vessel.mmsi = m[1];
                        if (link.classList.contains('vessel-name')) {
                            vessel.name = link.innerText.trim();
                        }
                    }
                    cells.forEach((cell, i) => {
                        const text = cell.innerText.trim();
                        if (i === 1 && !vessel.name) vessel.name = text;
                        if (i === 2) vessel.type = text;
                        if (i === cells.length - 1) vessel.destination = text;
                    });
                    if (vessel.mmsi || vessel.name) vessels.push(vessel);
                }
                return vessels;
            })()""")

            browser.close()
            if p:
                p.stop()

            seen: set[str] = set()
            unique = []
            for v in raw:
                mmsi = v.get("mmsi", "")
                if mmsi and mmsi not in seen:
                    seen.add(mmsi)
                    unique.append(v)
            return unique

        except Exception as e:
            print(f"[shipcrawler] VesselFinder scan failed for "
                  f"{self._port.name}: {e}")
            if browser:
                try:
                    browser.close()
                except Exception:
                    pass
            return []
