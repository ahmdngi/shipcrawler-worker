# ShipCrawler Worker for Sirb

Vessel OSINT worker for the [Sirb](https://github.com/ahmdngi/sirb) swarm framework.

Runs the ShipCrawler pipeline (Equasis + AIS + Shodan/Web) against vessels, producing structured findings for the Sirb blackboard.

## Related Skills

| Skill | Description |
|-------|-------------|
| [**sirb**](https://github.com/ahmdngi/sirb) | Agnostic N-agent swarm framework — TaskQueue, WorkerPool, Blackboard, CLI. This worker plugs into it. |
| [**shipcrawler**](https://github.com/ahmdngi/shipcrawler-v4) | Sequential agent-driven ShipCrawler (~10 min/vessel). More thorough — the default for deep investigations. |
| [**shipcrawler-parallel**](https://github.com/ahmdngi/shipcrawler-parallel) | Parallel multi-agent pipeline (~2 min/vessel). This worker wraps `orchestrate.py` from here. |

**Flow:** shipcrawler-parallel (pipeline) → ShipCrawlerWorker (parser) → Sirb (blackboard + aggregator)

## Installation

```bash
pip install git+https://github.com/ahmdngi/shipcrawler-worker.git
```

Requires [shipcrawler-parallel](https://github.com/ahmdngi/shipcrawler-parallel) scripts at `~/.hermes/skills/research/shipcrawler-parallel/scripts/orchestrate.py`.

## Usage

```yaml
# sirb.yml
workers:
  - shipcrawler_worker
```

```bash
sirb run
```

### Single vessel

```bash
sirb run --tasks '{"tasks": [{"mmsi": "273342890", "imo": "9735323"}]}'
```

### Batch (up to 3 vessels in one pipeline call)

```bash
sirb run --tasks '{"tasks": [{"mmsi": ["273342890", "311000987"]}]}'
```

### Port discovery

```yaml
workers:
  shipcrawler_worker:
    ports:
      - tallinn
      # - helsinki
```

## Output

The worker creates these finding types on the Sirb blackboard:

| Finding Type | Source | Severity | What it means |
|-------------|--------|----------|---------------|
| `shodan_exposure` | shodan | critical / high | Vessel has internet-visible services |
| `exposed_service` | shodan | high / medium | Specific service/port visible on Shodan |
| `no_exposure` | shodan | info | No Shodan-visible services |
| `known_vulnerability` | shodan | critical / high | CVE found in Shodan banner or vulns dict |
| `psc_detention` | equasis | high / medium | Port State Control detention on record |
| `no_pi_insurance` | equasis | high | No P&I insurance found (shadow fleet indicator) |
| `shadow_fleet_flag` | equasis | critical | Vessel flagged in a known shadow fleet registry |
| `sanctioned_manager` | equasis | critical | Manager based in sanctioned country (RU/IR/KP/SY) |
| `web_osint` | web | medium | OSINT hits from web search (news, forums) |
| `current_position` | ais | info | Latest AIS position and destination |
| `ais_destination` | ais | info | Known destination from AIS |
| `ais_anomaly` | ais | medium | Under way but speed=0 — possible AIS manipulation |
| `port_calls` | ais | info | Recent port call history from AIS |
| `batch_scan` | shipcrawler | info | Batch summary (vessel count, findings total) |

## How It Works

```
orchestrate.py  ──JSON──→  ShipCrawlerWorker._extract_findings()  ──Findings──→  Sirb blackboard
     ^                              ^
  Pipeline adds                  Worker adds _dns_findings()
  "dns_records" to               that reads it and creates
  merged-vessel.json             Finding objects
```

## Adding a New Feature

When you add a new capability to ShipCrawler (e.g., DNS enumeration, Censys, leak checks), you need two changes:

### 1. Pipeline side (`shipcrawler-parallel`)

Add the new data to `orchestrate.py`'s merged JSON output. Nothing special — just include a new key in the vessel dict:

```python
# In orchestrate.py — new agent output
"dns": {
    "records": [
        {"domain": "vessel.example.com", "ip": "1.2.3.4", "type": "A"},
        ...
    ]
}
```

### 2. Worker side (this repo)

Add a new method in `ShipCrawlerWorker` that reads the new JSON key and creates `Finding` objects, then wire it into `_extract_findings()`:

```python
def _dns_findings(self, dns_data: dict, mmsi: str, now: float) -> list[Finding]:
    """Extract DNS record findings from pipeline output."""
    findings = []
    for record in dns_data.get("records", []):
        findings.append(Finding(
            target_id=mmsi, target_type="vessel",
            finding_type="dns_record", severity="medium",
            weight=0.5,
            detail={
                "domain": record.get("domain", ""),
                "ip": record.get("ip", ""),
                "type": record.get("type", ""),
            },
            source="dns", worker=self.name, created_at=now,
        ))
    return findings
```

Then add one line in `_extract_findings()`:

```python
findings.extend(self._dns_findings(vessel.get("dns", {}), mmsi, now))
```

**That's it.** The new findings appear on Sirb's blackboard, in the aggregator, trends, dashboard, and webhooks — automatically. No changes to Sirb itself.

### If you skip step 2

The new JSON data still comes through in `Result.raw` (accessible via `result.raw["dns"]` if you're reading results programmatically), but it won't appear as structured Sirb findings — it won't show in the aggregator, trends, or dashboard.

## Development

```bash
git clone https://github.com/ahmdngi/shipcrawler-worker.git
cd shipcrawler-worker
pip install -e .
python -m pytest tests/
```

## Tests

```
tests/test_worker.py — 17 tests covering:
  - Single vessel execution
  - Batch mode (multi-MMSI)
  - CVE extraction from Shodan
  - AIS anomaly detection
  - Equasis rate-limit retry
  - Deep mode fallback and report parsing
  - Discovery from static files
  - Validation logic
```

## Version History

| Version | Date | Changes |
|---------|------|---------|
| v0.2.0 | 2026-07-17 | Batch mode, CVE extraction, AIS intelligence, Equasis retry, deep mode fix |
| v0.1.0 | 2026-07-17 | Initial release — single vessel, port discovery, entry-point registration |

## License

MIT — Ahmed Nagi Nasr / TalTech EMA.
