import json
import sys
from datetime import datetime


def iso_to_date(date_str):
    if not date_str:
        return None
    try:
        return datetime.fromisoformat(date_str.replace("Z", "")).date().isoformat()
    except Exception:
        return None


def severity_mapper(endor_level=None, db_severity=None):
    s = (endor_level or db_severity or "").upper()
    if "CRITICAL" in s:
        return "Critical"
    if "HIGH" in s:
        return "High"
    if "MEDIUM" in s or "MODERATE" in s:
        return "Medium"
    if "LOW" in s:
        return "Low"
    return "Info"


def get_cwe_id(db_spec):
    cwes = db_spec.get("cwe_ids") or []
    if cwes:
        try:
            return int(cwes[0].replace("CWE-", "").strip())
        except Exception:
            return None
    return None


def get_cve_alias(aliases):
    return next(
        (a for a in (aliases or []) if isinstance(a, str) and a.startswith("CVE-")),
        None,
    )


def generate_mitigation(vuln_spec):
    mitigation_lines = ["Upgrade to a fixed version where available."]
    for affected in (vuln_spec.get("affected") or [])[:3]:
        for r in (affected.get("ranges") or []):
            if r.get("fixed"):
                mitigation_lines.append(f"Fixed in: {r['fixed']}")
    return "\n".join(mitigation_lines)


def extract_package_name(vuln_spec):
    affected = vuln_spec.get("affected") or []
    if affected:
        pkg = affected[0].get("package") or {}
        return pkg.get("name")
    return None


def extract_version_info(vuln_spec):
    affected = vuln_spec.get("affected") or []
    if not affected:
        return None, None

    first = affected[0]

    versions = first.get("versions") or []
    current_version = ", ".join(versions) if versions else None

    fixed_version = None
    for r in (first.get("ranges") or []):
        if r.get("fixed"):
            fixed_version = r.get("fixed")
            break

    return current_version, fixed_version


def map_object_to_generic(obj):
    metadata = obj.get("meta") or {}
    specification = obj.get("spec") or {}
    finding_meta = specification.get("finding_metadata") or {}
    vulnerability = finding_meta.get("vulnerability") or {}
    vuln_meta = vulnerability.get("meta") or {}
    vuln_details = vulnerability.get("spec") or {}
    db_spec = vuln_details.get("database_specific") or {}
    cvss = vuln_details.get("cvss_v3_severity") or {}

    package_name = extract_package_name(vuln_details)

    current_version, fixed_version = extract_version_info(vuln_details)

    vuln_description = vuln_meta.get("description")
    if vuln_description and package_name:
        vuln_description = vuln_description.replace(f"in {package_name}", "").strip()

    if package_name and vuln_description and current_version:
        title = f"{package_name} {current_version} - {vuln_description}"
    elif package_name and vuln_description:
        title = f"{package_name} - {vuln_description}"
    else:
        title = vuln_description or package_name or "Endor finding"

    title = title[:511]

    desc_parts = []

    if package_name:
        desc_parts.append(f"Package: {package_name}")

    if current_version:
        desc_parts.append(f"Current Version: {current_version}")

    if fixed_version:
        desc_parts.append(f"Fixed Version: {fixed_version}")

    if vuln_meta.get("description"):
        desc_parts.append(f"Vulnerability: {vuln_meta.get('description')}")

    if specification.get("explanation"):
        desc_parts.append(specification.get("explanation"))

    description = "\n\n".join(desc_parts) or title

    severity = severity_mapper(cvss.get("level"), db_spec.get("severity"))
    cve = get_cve_alias(vuln_details.get("aliases"))
    cwe = get_cwe_id(db_spec)

    cvss_vector = cvss.get("vector")
    cvss_score = cvss.get("score")

    created_date = iso_to_date(metadata.get("create_time"))

    epss = vuln_details.get("epss_score") or {}
    raw_epss = (vuln_details.get("raw") or {}).get("epss_record") or {}

    epss_probability = epss.get("probability_score") or raw_epss.get("probability")
    epss_percentile = epss.get("percentile_score") or raw_epss.get("percentile")

    mitigation = generate_mitigation(vuln_details)

    result = {}
    for key, value in [
        ("title", title),
        ("description", description),
        ("severity", severity),
        ("mitigation", mitigation),
        ("date", created_date),
        ("cve", cve),
        ("cwe", cwe),
        ("cvssv3", cvss_vector),
        ("cvssv3_score", cvss_score),
        ("epss_score", epss_probability),
        ("epss_percentile", epss_percentile),
    ]:
        if value is not None:
            result[key] = value

    return result


def convert(input_file_path, output_file_path):
    with open(input_file_path, "r", encoding="utf-8") as f:
        raw_data = json.load(f)

    objects = raw_data.get("list", {}).get("objects", [])
    findings = list(map(map_object_to_generic, objects))

    output_data = {"findings": findings}

    with open(output_file_path, "w", encoding="utf-8") as f_out:
        json.dump(output_data, f_out, indent=4)

    print(f"[+] Converted {len(findings)} findings → {output_file_path}")


if __name__ == "__main__":
    if len(sys.argv) != 3:
        print("Usage: python convert.py <input_file> <output_file>")
        sys.exit(1)

    convert(sys.argv[1], sys.argv[2])
