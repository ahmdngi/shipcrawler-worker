"""ShipCrawler worker for Sirb — vessel OSINT pipeline.

Exposes ``ShipCrawlerWorker(SirbWorker)`` for registration with Sirb.
"""

from .worker import ShipCrawlerWorker

__all__ = ["ShipCrawlerWorker"]
