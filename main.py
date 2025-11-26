import requests
import time
from datetime import datetime, timedelta
from requests.exceptions import RequestException
import os
import yaml  # pip install pyyaml
import uuid

# ==============================
# CONFIGURATION
# ==============================
OTX_API_KEY = "cc67246c7278a9c830a4563062260bead550a6a687fc2d0f79fd63681c4fe218"  # <- replace with your real key
OTX_URL = "https://otx.alienvault.com/api/v1/pulses/subscribed"

OUTPUT_DIR = "sigma_rules"        # Root directory for generated Sigma rules
POLL_INTERVAL = 300               # 5 minutes
LOOKBACK_DAYS = 365               # Pull IOCs from the last 1 year

# ==============================
# FS SETUP
# ==============================
def init_output_dir():
    os.makedirs(OUTPUT_DIR, exist_ok=True)

def sanitize_filename(name: str) -> str:
    """Make filename safe for most filesystems."""
    return "".join(c if c.isalnum() or c in "-_" else "_" for c in name)[:120]

# ==============================
# IOC → SIGMA MAPPING
# ==============================
def indicator_to_sigma(indicator: dict, pulse: dict) -> dict | None:
    """
    Convert a single OTX indicator + its pulse context into a Sigma rule dict.
    Returns None if the IOC type is not supported.
    """
    i_type_raw = (indicator.get("type") or "").strip()
    i_type = i_type_raw.lower()
    value = indicator.get("indicator")
    if not value:
        return None

    pulse_name = pulse.get("name") or "OTX Pulse"
    pulse_id = pulse.get("id") or str(uuid.uuid4())
    created = (pulse.get("created") or "")[:10]  # YYYY-MM-DD if present

    # ---- Map OTX indicator type to logsource + field ----
    logsource = {}
    selection = {}

    # IP addresses
    if "ipv4" in i_type or "ipv6" in i_type:
        logsource = {"category": "network"}
        selection = {"dst_ip": value}

    # Domains / hostnames
    elif "domain" in i_type or "hostname" in i_type:
        logsource = {"category": "dns"}
        selection = {"dns.question.name": value}

    # URLs / URIs
    elif "url" in i_type or "uri" in i_type:
        logsource = {"category": "proxy"}
        selection = {"url.full": value}

    # File hashes
    elif "filehash-md5" in i_type:
        logsource = {"category": "file"}
        selection = {"file.hash.md5": value}
    elif "filehash-sha1" in i_type:
        logsource = {"category": "file"}
        selection = {"file.hash.sha1": value}
    elif "filehash-sha256" in i_type:
        logsource = {"category": "file"}
        selection = {"file.hash.sha256": value}
    elif "filehash-imphash" in i_type:
        logsource = {"category": "file"}
        selection = {"file.hash.imphash": value}
    else:
        # Unsupported / not directly mappable types (emails, CVEs, etc.)
        print(f"⚠️ Skipping unsupported indicator type: {i_type_raw} ({value})")
        return None

    # ---- Build Sigma rule structure ----
    rule_id = str(uuid.uuid4())

    sigma_rule = {
        "title": f"OTX {i_type_raw} IOC - {value}",
        "id": rule_id,
        "status": "experimental",
        "description": f"Indicator of compromise from AlienVault OTX pulse '{pulse_name}' ({pulse_id}).",
        "author": pulse.get("author_name") or "AlienVault OTX",
        "date": created or datetime.utcnow().strftime("%Y-%m-%d"),
        "references": pulse.get("references", []),
        "tags": (pulse.get("tags") or []) + ["otx", "threat-intel"],
        "logsource": logsource,
        "detection": {
            "selection": selection,
            "condition": "selection",
        },
        "falsepositives": [
            "Unknown – verify this IOC against your environment."
        ],
        "level": "medium",
    }

    return sigma_rule

# ==============================
# SAVE SIGMA RULES (WITH SUBDIRS)
# ==============================
def save_sigma_rule(sigma_rule: dict, indicator: dict, pulse: dict):
    i_type_raw = (indicator.get("type") or "ioc").strip()
    value = indicator.get("indicator") or "value"
    pulse_id = pulse.get("id") or "pulse"

    base_name = f"{pulse_id}_{i_type_raw}_{value}"
    safe_name = sanitize_filename(base_name)

    # Subcategory directory based on logsource.category
    category = sigma_rule.get("logsource", {}).get("category", "uncategorized")
    category_dir = os.path.join(OUTPUT_DIR, category)
    os.makedirs(category_dir, exist_ok=True)

    filename = os.path.join(category_dir, f"{safe_name}.yml")

    try:
        with open(filename, "w", encoding="utf-8") as f:
            yaml.safe_dump(
                sigma_rule,
                f,
                sort_keys=False,
                allow_unicode=True,
                default_flow_style=False,
            )
        print(f"💾 Sigma rule written: {filename}")
    except Exception as e:
        print(f"❌ Error writing Sigma rule for {value}: {e}")

# ==============================
# PROCESS PULSES → SIGMA
# ==============================
def process_pulses_to_sigma(pulses: list[dict]) -> int:
    count = 0
    for pulse in pulses:
        indicators = pulse.get("indicators", []) or []
        if not indicators:
            continue

        for ind in indicators:
            sigma_rule = indicator_to_sigma(ind, pulse)
            if sigma_rule is None:
                continue
            save_sigma_rule(sigma_rule, ind, pulse)
            count += 1
    return count

# ==============================
# FETCH PULSES (LAST YEAR ONLY)
# ==============================
def fetch_reports():
    headers = {"X-OTX-API-KEY": OTX_API_KEY}
    page = 1
    total_pulses = 0
    total_rules = 0

    # Compute modified_since = now - LOOKBACK_DAYS (UTC, ISO8601)
    lookback_start = datetime.utcnow() - timedelta(days=LOOKBACK_DAYS)
    modified_since = lookback_start.replace(microsecond=0).isoformat() + "Z"
    print(f"📅 Querying OTX pulses modified since: {modified_since}")

    while True:
        url = f"{OTX_URL}?page={page}&modified_since={modified_since}"
        try:
            response = requests.get(url, headers=headers, timeout=30)
            response.raise_for_status()
        except RequestException as e:
            print(f"⚠️ Network/Request error on page {page}: {e}")
            print("⏳ Waiting 60s before retrying...")
            time.sleep(60)
            continue  # retry same page

        data = response.json()
        results = data.get("results", [])
        print(f"📄 Page {page}: Got {len(results)} pulses")
        if not results:
            break

        # Convert to Sigma here
        rules_from_page = process_pulses_to_sigma(results)
        print(f"   → Generated {rules_from_page} Sigma rules from this page")
        total_rules += rules_from_page
        total_pulses += len(results)

        if not data.get("next"):
            break

        page += 1

    print(f"📊 Total pulses processed: {total_pulses}")
    print(f"📊 Total Sigma rules generated: {total_rules}")
    return total_rules

# ==============================
# MAIN LOOP
# ==============================
def main():
    print("🚀 Starting OTX → Sigma converter (last 1 year, with subdirs)...")
    init_output_dir()

    while True:
        print(f"\n[{datetime.now()}] 🔄 Fetching OTX pulses and generating Sigma rules...")
        total_rules = fetch_reports()
        print(f"✅ Done. Generated/updated ~{total_rules} Sigma rule files under '{OUTPUT_DIR}/<category>/'")

        print(f"⏳ Sleeping {POLL_INTERVAL} seconds...\n")
        time.sleep(POLL_INTERVAL)

if __name__ == "__main__":
    main()
