# OTX → Sigma Rule Generator

Because manually converting threat intel into detection rules is *so last decade*.

This tool automatically pulls subscribed pulses from **AlienVault OTX**, filters them to the **last 1 year**, extracts supported IOCs, and converts them into **Sigma rules**—each saved as an individual `.yml` file, neatly organized into category-based directories.

## 🚀 Features

- Fetches OTX threat intel via API
- Time-filtered using `modified_since` (1-year lookback)
- Converts IPs, domains, URLs, and file hashes into Sigma rules
- Auto-sorts rules into category subfolders:
  - `network/`
  - `dns/`
  - `proxy/`
  - `file/`
- No database, no clutter—just useful detections
- Continuous polling option for ongoing intel ingestion

## 📦 Requirements

- Python 3.8+
- `requests`
- `PyYAML`

Install dependencies:

```bash
pip install -r requirements.txt
```

## 🔧 Setup & Usage

Add your OTX API key in the script:

```bash
OTX_API_KEY = "YOUR_KEY_HERE"
```

Run the script:

```bash
python main.py
```

Find generated Sigma rules here:

```bash
sigma_rules/<category>/*.yml
```

## 📁 Example Output Structure
sigma_rules/
 ├── network/
 ├── dns/
 ├── proxy/
 └── file/

## ⚠️ Notes

Unsupported IOC types are politely ignored

Rules are tagged experimental—validate before production

Field mappings may vary based on your SIEM/log source

## 📜 License

MIT — because sharing is caring.

PRs, improvements, and complaints welcome. The repo enjoys attention.