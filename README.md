# ShipCrawler Worker for Sirb

Vessel OSINT worker for the [Sirb](https://github.com/ahmdngi/sirb) swarm framework.

Runs the ShipCrawler pipeline (Equasis + AIS + Shodan/Web) against vessels, producing structured findings for the Sirb blackboard.

## Installation

```bash
pip install git+https://github.com/ahmdngi/shipcrawler-worker.git
```

Requires [ShipCrawler Parallel](https://github.com/ahmdngi/shipcrawler-parallel) scripts and their dependencies.

## Usage

Register in `sirb.yml`:

```yaml
workers:
  - shipcrawler_worker
```

Run:

```bash
sirb run --workers shipcrawler --tasks vessels.json
```

Or with port discovery:

```yaml
workers:
  shipcrawler:
    ports:
      - tallinn
      # - helsinki
```

## Development

```bash
git clone https://github.com/ahmdngi/shipcrawler-worker.git
cd shipcrawler-worker
pip install -e .
```

## License

MIT — Ahmed Nagi Nasr / TalTech EMA.
