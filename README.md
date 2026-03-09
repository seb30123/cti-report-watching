# CTI Watch 🛡️

**Automated Cyber Threat Intelligence pipeline** — collects, enriches, scores and reports on security advisories from public sources.

[![CI](https://github.com/YOUR_USERNAME/cti-watch/actions/workflows/ci.yml/badge.svg)](https://github.com/YOUR_USERNAME/cti-watch/actions/workflows/ci.yml)
[![Python](https://img.shields.io/badge/python-3.11%2B-blue)](https://www.python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## What it does

CTI Watch pulls security feeds from public sources (CISA, CERT-FR, CISA KEV, Project Zero, SANS ISC…), enriches each item with CVE identifiers, IOCs, threat actor names, malware families and MITRE ATT&CK techniques, scores them by risk level, and generates a dated PDF report — all automatically, designed to run via cron.

```
Collect RSS/JSON → Enrich (CVE/IOC/MITRE) → Score → PDF Report
     main.py       app/enrich.py           scoring  app/report_pdf.py
                   app/mitre_map.py
                   app/patch_backlog.py
```

### Pipeline stages

| Step | Script | What it does |
|------|--------|-------------|
| 1 | `main.py` | Fetches RSS feeds + CISA KEV JSON catalog, deduplicates and stores raw items |
| 2 | `app/enrich.py` | Extracts CVEs, IPs, domains, URLs, hashes, vendor/product, APTs, malware; scores each item |
| 3 | `app/mitre_map.py` | Maps items to MITRE ATT&CK techniques via keyword rules |
| 4 | `app/patch_backlog.py` | Builds a `todo_patch` table of CVEs from KEV/actively-exploited items |
| 5 | `app/report_pdf.py` | Generates a dated PDF report with cover page, patch backlog, trends and detailed item cards |
| 6 | `app/cleanup_db.py` | Prunes items older than N days (default: 60) |

Or run all steps in sequence:

```bash
python app/run_all.py
```

---

## Sources

| Source | Category | Format |
|--------|----------|--------|
| [CISA Advisories](https://www.cisa.gov/cybersecurity-advisories) | advisory | RSS |
| [CERT-FR](https://www.cert.ssi.gouv.fr) | advisory | RSS |
| [CISA KEV Catalog](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | kev | JSON |
| [Google Project Zero](https://googleprojectzero.blogspot.com) | research | Atom |
| [SANS ISC](https://isc.sans.edu) | advisory | RSS |
| [Bleeping Computer](https://www.bleepingcomputer.com/news/security/) | advisory | RSS |

Add or remove sources by editing `sources.yaml`.

---

## Scoring

Each item receives a **risk score** (0–∞, typically 3–40) mapped to a severity:

| Severity | Score |
|----------|-------|
| 🔴 Critical | ≥ 22 |
| 🟠 High | ≥ 13 |
| 🔵 Medium | ≥ 7 |
| ⚪ Low | < 7 |

Signals considered: number of CVEs (with CVSS weighting when available from NVD), actionable IOC count, high-signal keywords (`rce`, `zero-day`, `actively exploited`…), CISA KEV category boost (+8), research source downgrade (×0.8).

---

## Requirements

- Python 3.11+
- See `requirements.txt`

---

## Installation

```bash
# 1. Clone
git clone https://github.com/YOUR_USERNAME/cti-watch.git
cd cti-watch

# 2. Create virtual environment
python3 -m venv .venv
source .venv/bin/activate       # Linux/macOS
# .venv\Scripts\activate        # Windows

# 3. Install dependencies
pip install -r requirements.txt

# 4. Configure sources
cp sources.yaml.example sources.yaml
# Edit sources.yaml if needed

# 5. First run — collect
python main.py

# 6. Run full pipeline
python app/run_all.py
```

The SQLite database (`cti_watch.db`) and reports (`reports/`) are created automatically.

---

## Cron setup (Linux)

Run the full pipeline daily at 08:00:

```bash
crontab -e
```

```
0 8 * * * cd /path/to/cti-watch && /path/to/cti-watch/.venv/bin/python app/run_all.py >> logs/cron.log 2>&1
```

---

## Project structure

```
cti-watch/
├── main.py                        # Entry point: RSS + KEV collection
├── sources.yaml                   # Feed configuration
├── sources.yaml.example           # Template
├── requirements.txt
│
├── app/
│   ├── run_all.py                 # Full pipeline orchestrator
│   ├── enrich.py                  # Enrichment step
│   ├── mitre_map.py               # MITRE ATT&CK mapping
│   ├── mitre_rules.py             # Keyword → technique rules + defensive recommendations
│   ├── report_pdf.py              # PDF report generator
│   ├── patch_backlog.py           # KEV → todo_patch table
│   ├── cleanup_db.py              # Database pruning
│   ├── cve_import.py              # Manual CVE context CSV import
│   │
│   ├── collectors/
│   │   ├── rss_collector.py       # RSS/Atom with retry + stale detection
│   │   ├── kev_collector.py       # CISA KEV JSON collector
│   │   ├── nvd_collector.py       # NVD API (CVSS + EPSS enrichment)
│   │   └── api_collector.py       # Generic JSON API collector (extensible)
│   │
│   ├── db/
│   │   ├── database.py            # SQLAlchemy engine + session factory
│   │   ├── tables.py              # RawItem model
│   │   ├── enriched_tables.py     # EnrichedItem, EnrichedCVE, EnrichedIOC, EnrichedRef
│   │   ├── mitre_tables.py        # MitreMatch model
│   │   ├── repository.py          # CRUD for raw_items
│   │   └── enrich_repository.py   # CRUD for enriched_*
│   │
│   └── utils/
│       ├── extractors.py          # Regex extractors (CVE, IP, hash, URL) with FP filters
│       ├── scoring.py             # Risk scoring with CVSS integration
│       ├── entities.py            # Vendor/product detection
│       ├── entities_advanced.py   # APT groups, malware families, version extraction
│       ├── ioc_quality.py         # URL classification (IOC vs reference)
│       ├── config.py              # sources.yaml loader
│       ├── text.py                # HTML → plain text
│       ├── hashing.py             # SHA-256 deduplication hash
│       ├── dates.py               # Date parsing
│       └── log.py / logger.py     # Logging (rich console + file)
│
└── tests/
    ├── conftest.py
    ├── test_extractors.py
    └── test_scoring.py
```

---

## Database schema

```
raw_items          ← collected items (deduplicated by SHA-256 hash)
enriched_items     ← processed items with score/severity/vendor/product
enriched_cves      ← CVE IDs per item
enriched_iocs      ← actionable IOCs (ip/domain/url/hash) per item
enriched_refs      ← reference URLs per item
mitre_matches      ← MITRE ATT&CK technique matches per item
todo_patch         ← CVEs from KEV/active exploitation to patch
cve_context        ← CVSS/EPSS/CWE from NVD (populated by nvd_collector)
```

---

## Configuration

### sources.yaml

```yaml
rss:
  - name: "My Custom Feed"
    url: "https://example.com/feed.xml"
    category: "advisory"   # advisory | kev | research

  - name: "CISA KEV"
    url: "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
    category: "kev"        # automatically uses kev_collector instead of rss_collector

apis: []
```

### KEV import depth

By default only the last 90 days of KEV entries are imported per run. To import the full catalog:

```python
# in main.py, change:
items = fetch_kev_items(url=url, source_name=name, recent_days=0, max_items=1200)
```

---

## Extending

**Add a new source** → edit `sources.yaml`.

**Add a MITRE rule** → add an entry to `RULES` in `app/mitre_rules.py`. Format:
```python
(["keyword1", "keyword2"], "T1234", "Technique Name", "tactic", confidence_0_100)
```

**Add a defensive recommendation** → add a `"T1234": "..."` entry to `MITRE_DEFENSES` in the same file.

**Add a new vendor/product** → edit the `VENDORS` and `PRODUCT_HINTS` lists in `app/utils/entities.py`.

---

## Contributing

Pull requests are welcome. For major changes, open an issue first.

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/my-feature`)
3. Commit your changes (`git commit -m 'Add my feature'`)
4. Push to the branch (`git push origin feature/my-feature`)
5. Open a pull request

Please make sure `pytest tests/` passes before submitting.

---

## Disclaimer

This tool uses only **public, freely available feeds**. It does not scrape, bypass authentication or collect any private data. Reports generated are for informational purposes only. Use responsibly.

---

## License

[MIT](LICENSE)
