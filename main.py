import json
import yaml
import os
import sys
from typing import Dict, Any, List, Optional
from datetime import datetime

# ==============================================================================
# --- CONFIGURATION ---
# ==============================================================================

# Check for CLI argument: python main.py <alert_file_path>
if len(sys.argv) < 2:
    print("Error: Please provide the alert file path as a command-line argument.")
    print("Usage: python main.py alerts/[FILENAME].json")
    sys.exit(1)

# Get the alert file path from the command-line argument
file_path = sys.argv[1] 

# Use relative paths for portability across GitHub clones
threat_intel_ipv4 = "mocks/it/anomali_ip_1.2.3.4.json" 
threat_intel_domain = "mocks/it/defender_ti_domain_bad.example.net.json"
threat_intel_hash = "mocks/it/reversinglabs_sha256_7b1f4c2d16e0a0b43cbae2f9a9c2dd7e2bb3a0aaad6c0ad66b341f8b7deadbe0.json"
allow_list_path = "configs/allowlists.yml"
mitre_map_path = "configs/mitre_map.yml"
connectors_config_path = "configs/connectors.yml"

# --- Output Paths ---
OUTPUT_DIR = "out"
ISOLATION_LOG = os.path.join(OUTPUT_DIR, "isolation.log")
INCIDENTS_DIR = os.path.join(OUTPUT_DIR, "incidents")
SUMMARIES_DIR = os.path.join(OUTPUT_DIR, "summaries")

# --- Variables Initialization ---
enriched_ips: Dict[str, Any] = {}
enriched_domain: Dict[str, Any] = {}
enriched_hash: Dict[str, Any] = {}
log_data: Dict[str, Any] = {}
alert_type: str = "UNKNOWN"
base_severity: int = 0
total_intel_boost: int = 0
final_severity: int = 0
tags: List[str] = []
suppression_deduction: int = 0
incident_bucket: str = "Unknown"
mitre_tags: List[str] = []
actions_taken: List[Dict[str, str]] = []
timeline: List[Dict[str, Any]] = []
connectors_data: Dict[str, Any] = {} # <-- NEW VARIABLE

# --- Helper Functions ---
def log_timeline(stage: str, details: str):
    """Logs a timeline event with current timestamp."""
    timeline.append({
        "stage": stage,
        "ts": datetime.now().isoformat(),
        "details": details
    })

def create_output_dirs():
    """Ensures output directories exist."""
    os.makedirs(OUTPUT_DIR, exist_ok=True)
    os.makedirs(INCIDENTS_DIR, exist_ok=True)
    os.makedirs(SUMMARIES_DIR, exist_ok=True)

# --- Function for Intel Boost Calculation ---
def calculate_intel_boost(enriched_ips, enriched_domain, enriched_hash) -> tuple[int, int, int]:
    malicious_count = 0
    suspicious_count = 0
    total_boost = 0
    
    all_enriched_data = {}
    all_enriched_data.update(enriched_ips)
    all_enriched_data.update(enriched_domain)
    all_enriched_data.update(enriched_hash)
    
    for ioc, details in all_enriched_data.items():
        verdict = details.get('verdict', '').lower()
        
        if verdict == 'malicious':
            malicious_count += 1
        elif verdict == 'suspicious':
            suspicious_count += 1
    
    total_flagged_iocs = malicious_count + suspicious_count

    if malicious_count >= 1:
        total_boost += 20
    if suspicious_count >= 1:
        total_boost += 10
        
    base_contributors = 0
    if malicious_count >= 1:
        base_contributors += 1
    if suspicious_count >= 1:
        base_contributors += 1
        
    extra_iocs = total_flagged_iocs - base_contributors
    
    if extra_iocs > 0:
        extra_boost = extra_iocs * 5
        extra_boost = min(extra_boost, 20)
        total_boost += extra_boost
        
    return total_boost, malicious_count, suspicious_count


# ==============================================================================
## INGESTION
# ==============================================================================
create_output_dirs()

# Load Alert File
try:
    with open(file_path, 'r') as file:
        log_data = json.load(file)
        print(f"JSON data loaded successfully from {file_path}.")
except FileNotFoundError:
    print(f"Error: The alert file '{file_path}' was not found.")
    sys.exit(1)
except json.JSONDecodeError:
    print(f"Error: Could not decode JSON from '{file_path}'. Check for valid JSON syntax.")
    sys.exit(1)
except Exception as e:
    print(f"An unexpected error occurred during ingestion: {e}")
    sys.exit(1)

# Load Connectors Configuration (NEW)
try:
    with open(connectors_config_path, 'r') as f:
        connectors_data = yaml.safe_load(f) or {}
except FileNotFoundError:
    print(f"Error: Connectors config file '{connectors_config_path}' not found. Connector details unavailable.")
except Exception as e:
    print(f"An error occurred loading or parsing Connectors YAML: {e}")


# ==============================================================================
## NORMALIZATION
# ==============================================================================

alert_id = log_data.get('alert_id') or f"incident_{datetime.now().strftime('%Y%m%d%H%M%S')}"
source = log_data.get('source')
alert_type = log_data.get('type', alert_type)
created_at = log_data.get('created_at')
asset = log_data.get('asset', {})
indicators = log_data.get('indicators', {})
raw = log_data.get('raw', {})
device_id = asset.get('device_id')
hostname = asset.get('hostname')
ip = asset.get('ip')
ipv4_list = indicators.get('ipv4', [])
domains_list = indicators.get('domains', [])
urls_list = indicators.get('urls', [])
sha256_list = indicators.get('sha256', [])

normalized_indicators: List[Dict[str, str]] = []
indicator_data = {
    "ipv4": ipv4_list,
    "domains": domains_list,
    "urls": urls_list,
    "sha256": sha256_list,
}

for indicator_type, value_list in indicator_data.items():
    for value in value_list:
        normalized_indicators.append({
            "type": indicator_type,
            "value": value
        })

# ==============================================================================
## ENRICHMENT
# ==============================================================================


### ENRICHMENT IP ###
try:
    with open(threat_intel_ipv4, 'r') as file_ip:
        log_data_threat_ipv4 = json.load(file_ip)
except FileNotFoundError:
    log_data_threat_ipv4 = {}
    print(f"Error: The file '{threat_intel_ipv4}' was not found.")

threat_ip = log_data_threat_ipv4.get('ip')
threat_ip_score = log_data_threat_ipv4.get('confidence')
threat_ip_verdict = log_data_threat_ipv4.get('risk')
threat_ip_sources = "anomali"

for ip_alert in ipv4_list:
    if ip_alert == threat_ip and threat_ip_verdict:
        risk_data_ip = {
            "verdict": threat_ip_verdict,
            "score": threat_ip_score,
            "sources": [threat_ip_sources]
        }
        enriched_ips[ip_alert] = risk_data_ip
        
### ENRICHMENT DOMAIN ###
try:
    with open(threat_intel_domain, 'r') as file_domain:
        log_data_threat_domain = json.load(file_domain)
except FileNotFoundError:
    log_data_threat_domain = {}
    print(f"Error: The file '{threat_intel_domain}' was not found.")

threat_domain = log_data_threat_domain.get('domain')
threat_domain_score = log_data_threat_domain.get('score')
threat_domain_verdict = log_data_threat_domain.get('reputation')
threat_domain_sources = "defender_ti"

for domain_alert in domains_list:
    if domain_alert == threat_domain and threat_domain_verdict:
        risk_data_domain = {
            "verdict": threat_domain_verdict,
            "score": threat_domain_score,
            "sources": [threat_domain_sources]
        }
        enriched_domain[domain_alert] = risk_data_domain

### ENRICHMENT HASH ###
try:
    with open(threat_intel_hash, 'r') as file_hash:
        log_data_threat_hash = json.load(file_hash)
except FileNotFoundError:
    log_data_threat_hash = {}
    print(f"Error: The file '{threat_intel_hash}' was not found.")

threat_hash = log_data_threat_hash.get('sha256')
threat_hash_score = log_data_threat_hash.get('score')
threat_hash_verdict = log_data_threat_hash.get('classification')
threat_hash_sources = "reversinglabs"

for hash_alert in sha256_list:
    if hash_alert == threat_hash and threat_hash_verdict:
        risk_data_hash = {
            "verdict": threat_hash_verdict,
            "score": threat_hash_score,
            "sources": [threat_hash_sources]
        }
        enriched_hash[hash_alert] = risk_data_hash

# ==============================================================================
## ALLOWLIST PROCESSING
# ==============================================================================

allowlist_data: Dict[str, List[str]] = {}
try:
    with open(allow_list_path, 'r') as f:
        allowlist_data = yaml.safe_load(f) or {}
except FileNotFoundError:
    print(f"Error: Allowlist file '{allow_list_path}' was not found. Skipping allowlist checks.")
except Exception as e:
    print(f"An error occurred loading or parsing YAML: {e}")

allowlisted_ioc_count = 0
total_ioc_count = len(normalized_indicators)
is_allowlisted_tag_added = False

for ioc in normalized_indicators:
    ioc_type = ioc['type']
    ioc_value = ioc['value']
    
    is_ioc_allowlisted = ioc_type in allowlist_data and ioc_value in allowlist_data[ioc_type]
    
    # Tag IOC for JSON output
    ioc['allowlisted'] = is_ioc_allowlisted
    
    if is_ioc_allowlisted:
        allowlisted_ioc_count += 1
        
        if not is_allowlisted_tag_added:
            suppression_deduction = 25
            tags.append('allowlisted')
            is_allowlisted_tag_added = True


# ==============================================================================
## MITRE ATT&CK TAGGING
# ==============================================================================

DEFAULT_MITRE_TAGS = ["T1595", "T1071"] 
mitre_mapping: Dict[str, List[str]] = {}
try:
    with open(mitre_map_path, 'r') as f:
        mitre_mapping = yaml.safe_load(f) or {}
except FileNotFoundError:
    print(f"Error: MITRE map file '{mitre_map_path}' was not found. Using default tags.")
except Exception as e:
    print(f"An error occurred loading or parsing MITRE map YAML: {e}")

mapped_tags: Optional[List[str]] = mitre_mapping.get(alert_type)

if mapped_tags:
    mitre_tags = mapped_tags
else:
    mitre_tags = DEFAULT_MITRE_TAGS
    
tags.extend(mitre_tags)

# ==============================================================================
## TRIAGE & SCORING
# ==============================================================================

## Base Severity Mapping
alert_severities = {
    "Malware": 70,
    "Phishing": 60,
    "Beaconing": 65,
    "CredentialAccess": 75,
    "C2": 80
}

# 1. Determine Base Severity
base_severity = alert_severities.get(alert_type, 0)

# 2. Calculate Intel Boost
total_intel_boost, mal_count, susp_count = calculate_intel_boost(
    enriched_ips, enriched_domain, enriched_hash
)

# 3. Calculate Provisional Severity
provisional_severity = base_severity + total_intel_boost

# 4. Apply Allowlist Suppression Deduction
final_severity = provisional_severity - suppression_deduction

# 5. Apply Full Suppression Rule
if total_ioc_count > 0 and allowlisted_ioc_count == total_ioc_count:
    final_severity = 0
    tags.append('suppressed=true')

# 6. Apply Clamp: Clamp to 0..100
final_severity = max(0, min(100, final_severity))

# ==============================================================================
## CLAMPS & BUCKETS
# ==============================================================================
log_timeline("triage", f"Score clamped to {final_severity}.")

if final_severity == 0:
    incident_bucket = "Suppressed"
elif final_severity <= 39:
    incident_bucket = "Low"
elif final_severity <= 69:
    incident_bucket = "Medium"
elif final_severity <= 89:
    incident_bucket = "High"
else:
    incident_bucket = "Critical"

# ==============================================================================
## CONDITIONAL RESPONSE ACTION
# ==============================================================================
log_timeline("respond", "Checking conditional isolation requirement.")

is_device_allowlisted = False
if device_id:
    for ioc in normalized_indicators:
        if ioc.get('value') == device_id and ioc.get('allowlisted'):
            is_device_allowlisted = True
            break

if final_severity >= 70 and device_id and not is_device_allowlisted:
    action_ts = datetime.now().isoformat()
    
    isolation_log_line = f"isolate device_id={device_id} incident={alert_id} result=isolated\n"
    with open(ISOLATION_LOG, 'a') as f:
        f.write(isolation_log_line)
    
    # In a real environment, the EDR base_url (connectors_data['edr']['base_url']) 
    # would be used here to send the isolation command.
    
    action_details = { 
        "type": "isolate",
        "target": f"device:{device_id}",
        "result": "isolated",
        "ts": action_ts 
    }
    actions_taken.append(action_details)
    log_timeline("respond", f"Device {device_id} isolated successfully.")
else:
    log_timeline("respond", "Isolation conditions not met.")


# ==============================================================================
## INCIDENT JSON OUTPUT
# ==============================================================================

incident_json_data = {
    "incident_id": alert_id,
    "source_alert": log_data,
    "asset": {
        "device_id": device_id,
        "hostname": hostname,
        "ip": ip
    },
    "indicators": normalized_indicators,
    "triage": {
        "severity": final_severity,
        "bucket": incident_bucket,
        "tags": sorted(list(set(tags))),
        "suppressed": ('suppressed=true' in tags)
    },
    "mitre": {
        "techniques": mitre_tags
    },
    "actions": actions_taken,
    "timeline": timeline
}

incident_filename = os.path.join(INCIDENTS_DIR, f"{alert_id}.json")
with open(incident_filename, 'w') as f:
    json.dump(incident_json_data, f, indent=4)
log_timeline("respond", f"Incident JSON written to {incident_filename}")


# ==============================================================================
## ANALYST SUMMARY OUTPUT
# ==============================================================================

ioc_table_rows = ["| Type | Value | Risk Verdict | Allowlisted |"]
ioc_table_rows.append("| :--- | :--- | :--- | :--- |")

all_enriched_iocs = {**enriched_ips, **enriched_domain, **enriched_hash}

for ioc in normalized_indicators:
    ioc_value = ioc['value']
    ioc_type = ioc['type']
    is_allowlisted = 'True' if ioc.get('allowlisted') else 'False'
    
    risk_data = all_enriched_iocs.get(ioc_value, {})
    verdict = risk_data.get('verdict', 'Unknown')
    
    ioc_table_rows.append(f"| {ioc_type} | {ioc_value} | {verdict} | {is_allowlisted} |")

ioc_table = "\n".join(ioc_table_rows)

actions_table_rows = ["| Type | Target | Result | Timestamp |"]
actions_table_rows.append("| :--- | :--- | :--- | :--- |")

if actions_taken:
    for action in actions_taken:
        actions_table_rows.append(f"| {action['type']} | {action['target']} | {action['result']} | {action['ts'].split('T')[0]} |")
else:
    actions_table_rows.append("| None | N/A | N/A | N/A |")

actions_table = "\n".join(actions_table_rows)


markdown_summary = f"""
# Incident Summary: {alert_id}

## 1. Overview
| Field | Value |
| :--- | :--- |
| **Source Alert Type** | {alert_type} |
| **Device Hostname** | {hostname or 'N/A'} |
| **Device ID** | {device_id or 'N/A'} |
| **Timestamp** | {created_at or 'N/A'} |

---

## 2. Triage & Scoring
| Metric | Value |
| :--- | :--- |
| **Final Severity (0-100)** | {final_severity} |
| **Severity Bucket** | **{incident_bucket}** |
| **Initial Base Score** | {base_severity} |
| **Total Intel Boost** | +{total_intel_boost} |

**Tags:** {', '.join(sorted(list(set(tags))))}

---

## 3. Indicators of Compromise
**Total IOCs:** {total_ioc_count}

{ioc_table}

---

## 4. MITRE ATT&CK Mapping
**Techniques:** {', '.join(mitre_tags)}

---

## 5. Actions Taken
{actions_table}
"""

summary_filename = os.path.join(SUMMARIES_DIR, f"{alert_id}.md")
with open(summary_filename, 'w') as f:
    f.write(markdown_summary)
log_timeline("respond", f"Analyst summary written to {summary_filename}")


# ==============================================================================
## PRINT FINAL EXECUTION LOG
# ==============================================================================

print("\n" + "="*50)
print("FINAL EXECUTION SUMMARY")
print("="*50)
print(f"INCIDENT ID: {alert_id}")
print(f"FINAL SEVERITY: {final_severity} ({incident_bucket})")
print("-" * 50)
if actions_taken:
    print(f"RESPONSE ACTION: Device Isolation Triggered (See {ISOLATION_LOG})")
else:
    print("RESPONSE ACTION: No isolation action taken.")
print(f"OUTPUT: Incident JSON written to {incident_filename}")
print(f"OUTPUT: Analyst Summary written to {summary_filename}")
print("="*50)