import json
import sys
from datetime import datetime, timezone


def convert_severity(endor_sev):
  """Map Endor Labs severity to DefectDojo severity."""
  mapping = {
      "FINDING_LEVEL_CRITICAL": "Critical",
      "FINDING_LEVEL_HIGH": "High",
      "FINDING_LEVEL_MEDIUM": "Medium",
      "FINDING_LEVEL_LOW": "Low",
      "FINDING_LEVEL_INFO": "Info",
  }
  return mapping.get(endor_sev, "Medium")


def extract_cve(aliases):
  """Extract first CVE from aliases list."""
  if not aliases:
      return None
  for alias in aliases:
      if alias.startswith("CVE-"):
          return alias
  return None


def extract_cwe(vuln_spec):
  """Extract first CWE if available."""
  db_specific = vuln_spec.get("database_specific", {})
  cwe_ids = db_specific.get("cwe_ids", [])
  if cwe_ids:
      return cwe_ids[0]
  return None


def convert_endor_to_dd(endor_data):
  findings = []

  objects = endor_data.get("list", {}).get("objects", [])

  for item in objects:
      spec = item.get("spec", {}) or {}
      meta = item.get("meta", {}) or {}

      vuln_spec = (
          spec.get("vulnerability", {}).get("spec", {})
          if spec.get("vulnerability")
          else {}
      )

      severity = convert_severity(item.get("level"))

      aliases = vuln_spec.get("aliases", [])
      cve_id = extract_cve(aliases)
      cwe_id = extract_cwe(vuln_spec)

      cvss_vector = vuln_spec.get("cvss_v3_severity", {}).get("vector")

      dd_finding = {
          "title": spec.get("extra_key") or "Unnamed Finding",
          "description": spec.get("explanation") or "No description provided",
          "severity": severity,
          "mitigation": spec.get("remediation") or "No remediation provided",
          "date": meta.get("create_time") or datetime.now(timezone.utc).isoformat(),
          "cve": cve_id,
          "cwe": cwe_id,
          "cvssv3": cvss_vector,
          "file_path": None,
          "line": None,
          "endpoints": [],
          "tags": spec.get("finding_tags", []),
          "fix_available": "FINDING_TAGS_FIX_AVAILABLE" in spec.get("finding_tags", []),
      }

      findings.append(dd_finding)

  return {"findings": findings}


def main():
  if len(sys.argv) != 3:
      print(f"Usage: {sys.argv[0]} <endor_input.json> <defectdojo_output.json>")
      sys.exit(1)

  input_file = sys.argv[1]
  output_file = sys.argv[2]

  try:
      with open(input_file, "r") as f:
          endor_data = json.load(f)
  except Exception as e:
      print(f"Error reading input file: {e}")
      sys.exit(1)

  dd_data = convert_endor_to_dd(endor_data)

  try:
      with open(output_file, "w") as f:
          json.dump(dd_data, f, indent=2)
  except Exception as e:
      print(f"Error writing output file: {e}")
      sys.exit(1)

  print(f"✅ Conversion complete. Output saved to '{output_file}'")


if __name__ == "__main__":
  main()
