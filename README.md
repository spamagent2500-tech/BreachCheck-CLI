# BreachCheck — Python CLI

BreachCheck is a privacy-preserving, lab-only breach exposure checker built to match the PNY Trainings **Build Your Own Security Tool** brief. It checks one email address, searches local CSV/JSON data, optionally queries the Have I Been Pwned breach API, performs a k-anonymity password range check, merges duplicate findings, scores severity, caches API results, and writes a per-address report.

This standalone repository contains the assignment-compliant Python implementation and its fictional lab fixtures.

## Safety

Use only your own address or data you have written permission to check. Use only fictional lab passwords. Never use a real password, another person’s address, a real breach dataset, or a committed API key. The password is entered with hidden terminal input; the full password and full hash are never printed or sent. Only the first five SHA-1 characters go to the password range API.

## Setup

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -r requirements.txt
```

For real email breach lookups, set the API key in the environment—not in source code or a committed file:

```bash
export HIBP_API_KEY='your-key-from-the-provider'
```

The email API is optional for offline lab work. Without a key, use `--offline`.

## Safe offline demo

```bash
python -m breachcheck \
  --email cybernova@northstar-labs.test \
  --dataset data/lab-fixtures.csv \
  --offline \
  --output reports/sample-report.txt
```

Export JSON or CSV:

```bash
python -m breachcheck --email cybernova@northstar-labs.test --dataset data/lab-fixtures.csv --offline --format json --output reports/sample-report.json
python -m breachcheck --email cybernova@northstar-labs.test --dataset data/lab-fixtures.csv --offline --format csv --output reports/sample-report.csv
```

## Real API lookup and password check

```bash
python -m breachcheck \
  --email your-own-address@example.com \
  --dataset data/lab-fixtures.csv \
  --check-password
```

The command prompts for the password without echoing it. The email breach API uses `HIBP_API_KEY`; the password range API uses the k-anonymity endpoint and sends only the five-character hash prefix. API results are cached under `.breachcheck-cache/` so repeated checks avoid unnecessary calls.

The email client handles HTTP 404 as no breach, retries HTTP 429 with `Retry-After` or exponential backoff, retries transient URL/timeout errors, and reports authentication/API failures clearly.

## Local datasets

CSV columns: `email,name,date,classes`. JSON can be an array of records or an object containing `records`; JSONL is also supported. Email matching is case-insensitive and performed locally. CSV and JSON streaming use iterators; the optional `ijson` dependency streams large JSON arrays.

## Stretch features

- Batch mode: `python -m breachcheck --batch addresses.txt --dataset data/lab-fixtures.csv --offline --delay 2`
- Re-check mode: add `--previous-report reports/old.json` to include `new_findings`.
- Report export: `--format text`, `json`, or `csv`.

## Tests

```bash
python -m unittest discover -s tests -v
```

Tests use mocked API responses and fictional lab data; they do not contact external services.

## Assignment mapping

| PDF requirement | Implementation |
|---|---|
| Local SHA-1 and k-anonymity | `breachcheck/password_check.py` |
| Email API and environment key | `breachcheck/breach_api.py` and `HIBP_API_KEY` |
| Local CSV/JSON parsing | `breachcheck/dataset.py` |
| Merge, severity, actions | `breachcheck/scoring.py` |
| 429, timeout, errors, cache | `breachcheck/breach_api.py`, `password_check.py`, `cache.py` |
| CLI report and exports | `breachcheck/cli.py`, `report.py` |
| Batch/re-check stretch | CLI `--batch`, `--previous-report` |

## Dashboard screenshots

The repository also includes verified screenshots of the React dashboard companion:

- [Desktop dashboard](docs/screenshots/dashboard-desktop.png)
- [Mobile dashboard](docs/screenshots/dashboard-mobile.png)
