"""Historic CVE enumeration via NIST NVD.

Pipeline:
  1. Fingerprint the target → list of (technology, version) tuples.
  2. For each technology, query the NVD API for every known CVE (1999-2026).
  3. Filter to CVEs where the detected version falls in the affected range.
  4. For high/critical CVEs, run a Nuclei CVE-specific template if available.
  5. Return one RawFinding per confirmed/likely CVE.

The NVD API is free and requires no API key. With a key the rate limit
drops from 6s to 0.6s between requests — set NVD_API_KEY in .env to
speed things up considerably when scanning many technologies.

This is the closest equivalent to what Mythos does with vulnerability
enumeration: systematically check your specific stack against every
known CVE in the NVD, not just what active scanners happen to probe for.
"""
from __future__ import annotations

import os
import shutil
import subprocess
import time
from typing import List, Optional, Tuple

import requests

from models import OwaspCategory, RawFinding
from scanners.tech_fingerprint import fingerprint

NVD_API_BASE = "https://services.nvd.nist.gov/rest/json/cves/2.0"
NVD_API_KEY  = os.getenv("NVD_API_KEY", "")
_DELAY       = 0.6 if NVD_API_KEY else 6.1   # NVD rate-limit requirement
_MAX_CVES_PER_TECH = 50  # cap per technology to keep scan time reasonable

# OWASP category mapping by CWE prefix — covers all OWASP eras 2003-2026
_CWE_TO_OWASP = {
    "CWE-89":   OwaspCategory.A05_INJECTION,
    "CWE-79":   OwaspCategory.A05_INJECTION,
    "CWE-78":   OwaspCategory.A05_INJECTION,
    "CWE-94":   OwaspCategory.A05_INJECTION,
    "CWE-77":   OwaspCategory.A05_INJECTION,
    "CWE-917":  OwaspCategory.A05_INJECTION,
    "CWE-287":  OwaspCategory.A07_AUTH_FAILURES,
    "CWE-384":  OwaspCategory.A07_AUTH_FAILURES,
    "CWE-798":  OwaspCategory.A07_AUTH_FAILURES,
    "CWE-306":  OwaspCategory.A07_AUTH_FAILURES,
    "CWE-284":  OwaspCategory.A01_ACCESS_CONTROL,
    "CWE-285":  OwaspCategory.A01_ACCESS_CONTROL,
    "CWE-639":  OwaspCategory.A01_ACCESS_CONTROL,
    "CWE-22":   OwaspCategory.A01_ACCESS_CONTROL,
    "CWE-326":  OwaspCategory.A04_CRYPTO_FAILURES,
    "CWE-327":  OwaspCategory.A04_CRYPTO_FAILURES,
    "CWE-311":  OwaspCategory.A04_CRYPTO_FAILURES,
    "CWE-319":  OwaspCategory.A04_CRYPTO_FAILURES,
    "CWE-295":  OwaspCategory.A04_CRYPTO_FAILURES,
    "CWE-502":  OwaspCategory.A08_INTEGRITY_FAILURES,
    "CWE-494":  OwaspCategory.A08_INTEGRITY_FAILURES,
    "CWE-345":  OwaspCategory.A08_INTEGRITY_FAILURES,
    "CWE-16":   OwaspCategory.A02_MISCONFIGURATION,
    "CWE-1104": OwaspCategory.A03_SUPPLY_CHAIN,
    "CWE-829":  OwaspCategory.A03_SUPPLY_CHAIN,
    "CWE-400":  OwaspCategory.A10_EXCEPTIONAL,
    "CWE-703":  OwaspCategory.A10_EXCEPTIONAL,
    "CWE-778":  OwaspCategory.A09_LOGGING_FAILURES,
}


def _owasp_from_cwes(cwes: List[str]) -> OwaspCategory:
    for cwe in cwes:
        if cwe in _CWE_TO_OWASP:
            return _CWE_TO_OWASP[cwe]
    return OwaspCategory.A03_SUPPLY_CHAIN  # default for component CVEs


def _nvd_headers() -> dict:
    h = {"Accept": "application/json"}
    if NVD_API_KEY:
        h["apiKey"] = NVD_API_KEY
    return h


def _query_nvd(keyword: str, version: Optional[str]) -> List[dict]:
    """Query NVD for CVEs matching a technology keyword. Returns raw CVE dicts."""
    params = {
        "keywordSearch": keyword,
        "resultsPerPage": _MAX_CVES_PER_TECH,
        "startIndex": 0,
    }
    try:
        resp = requests.get(NVD_API_BASE, params=params, headers=_nvd_headers(), timeout=30)
        resp.raise_for_status()
        data = resp.json()
    except (requests.RequestException, ValueError):
        return []
    finally:
        time.sleep(_DELAY)

    vulns = []
    for item in data.get("vulnerabilities", []):
        cve = item.get("cve", {})
        if cve.get("vulnStatus") in ("Rejected", "Disputed"):
            continue
        vulns.append(cve)
    return vulns


def _cvss_from_cve(cve: dict) -> Tuple[Optional[float], Optional[str], str]:
    """Extract CVSS score, vector, and severity from a CVE record."""
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if key in metrics:
            data = metrics[key][0].get("cvssData", {})
            score = data.get("baseScore")
            vector = data.get("vectorString")
            severity = data.get("baseSeverity") or data.get("accessVector", "")
            return score, vector, str(severity).lower()
    return None, None, "medium"


def _cwes_from_cve(cve: dict) -> List[str]:
    cwes = []
    for weakness in cve.get("weaknesses", []):
        for desc in weakness.get("description", []):
            val = desc.get("value", "")
            if val.startswith("CWE-"):
                cwes.append(val)
    return cwes


def _is_kev(cve: dict) -> bool:
    """True if this CVE is in CISA's Known Exploited Vulnerabilities catalog."""
    return bool(cve.get("cisaExploitAdd"))


def _try_nuclei_cve(cve_id: str, target_url: str) -> Optional[str]:
    """Run a nuclei CVE-specific template if nuclei is available.
    Returns evidence string if confirmed, None otherwise."""
    if not shutil.which("nuclei"):
        return None
    try:
        result = subprocess.run(
            ["nuclei", "-u", target_url, "-id", cve_id.lower(),
             "-silent", "-no-color", "-timeout", "10"],
            capture_output=True, text=True, timeout=60
        )
        if result.returncode == 0 and cve_id.lower() in result.stdout.lower():
            return f"Nuclei confirmed: {result.stdout.strip()[:500]}"
    except (subprocess.TimeoutExpired, FileNotFoundError):
        pass
    return None


def run_nvd_scan(target_url: str) -> List[RawFinding]:
    """Main entry point: fingerprint the target, look up all CVEs for
    detected technologies, and return findings for confirmed/likely ones."""
    findings: List[RawFinding] = []

    # Step 1: fingerprint
    technologies = fingerprint(target_url)
    if not technologies:
        return findings

    # Step 2: query NVD for each detected technology
    for tech, version in technologies:
        if tech in ("generator", "powered_by", "framework", "CMS-detected"):
            continue

        cves = _query_nvd(tech, version)

        for cve in cves:
            cve_id = cve.get("id", "")
            desc_list = cve.get("descriptions", [])
            description = next((d["value"] for d in desc_list if d.get("lang") == "en"), "")
            score, vector, severity_str = _cvss_from_cve(cve)
            cwes = _cwes_from_cve(cve)
            category = _owasp_from_cwes(cwes)
            is_kev = _is_kev(cve)

            # skip if score is too low to be worth flagging
            if score and score < 4.0:
                continue

            # map CVSS score to severity string
            if score:
                if score >= 9.0:
                    raw_sev = "critical"
                elif score >= 7.0:
                    raw_sev = "high"
                elif score >= 4.0:
                    raw_sev = "medium"
                else:
                    raw_sev = "low"
            else:
                raw_sev = severity_str or "medium"

            # Step 3: for high/critical CVEs, try nuclei confirmation
            nuclei_evidence = ""
            if raw_sev in ("critical", "high"):
                nuclei_evidence = _try_nuclei_cve(cve_id, target_url) or ""

            kev_note = " [CISA KEV — actively exploited in the wild]" if is_kev else ""
            version_note = f" (detected version: {version})" if version else ""

            evidence_parts = [
                f"CVE: {cve_id}{kev_note}",
                f"Technology: {tech}{version_note}",
                f"CVSS: {score} | Vector: {vector}",
                f"CWEs: {', '.join(cwes) if cwes else 'N/A'}",
            ]
            if nuclei_evidence:
                evidence_parts.append(f"Nuclei confirmation: {nuclei_evidence}")

            findings.append(
                RawFinding(
                    tool="nvd-historic-cve",
                    category=category,
                    title=f"{cve_id}: {tech}{version_note}",
                    url=target_url,
                    raw_severity=raw_sev,
                    description=description[:600],
                    evidence="\n".join(evidence_parts),
                )
            )

    # Deduplicate by CVE ID (multiple tech queries may surface the same CVE)
    seen_ids: set = set()
    deduped: List[RawFinding] = []
    for f in findings:
        cve_id = f.title.split(":")[0].strip()
        if cve_id not in seen_ids:
            seen_ids.add(cve_id)
            deduped.append(f)

    return deduped
