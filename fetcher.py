import csv
import io
import os
from datetime import datetime, timedelta, timezone
from typing import Any, Dict, List
import requests

CISA_KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
EXPLOIT_DB_CSV_URL = (
    "https://raw.githubusercontent.com/offensive-security/exploitdb/master/files_exploits.csv"
)


class VulnerabilityFetcher:
    """Fetches and correlates emerging vulnerabilities from CISA KEV, Exploit-DB, and NIST NVD."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.lookback_hours = config.get("lookback_hours", 24)
        self.min_cvss = config.get("min_cvss_score", 7.0)
        self.watchlist = [w.lower() for w in config.get("watchlist", [])]
        self.nvd_api_key = os.getenv("NVD_API_KEY", "").strip()

    def fetch_all(self) -> List[Dict[str, Any]]:
        cve_map: Dict[str, Dict[str, Any]] = {}

        if self.config.get("feeds", {}).get("cisa_kev", True):
            print("  -> Querying CISA Known Exploited Vulnerabilities (KEV)...")
            self._fetch_cisa_kev(cve_map)

        if self.config.get("feeds", {}).get("exploit_db", True):
            print("  -> Querying Exploit-DB database mirror...")
            self._fetch_exploit_db(cve_map)

        if self.config.get("feeds", {}).get("nist_nvd", True):
            print("  -> Querying NIST NVD 2.0 API...")
            self._fetch_nvd(cve_map)

        # Cross-reference against user's custom watchlist
        for cve_id, data in cve_map.items():
            text_corpus = (
                f"{data.get('title', '')} {data.get('description', '')}"
            ).lower()
            matched = [term for term in self.watchlist if term in text_corpus]
            data["matched_watchlist"] = matched

        return list(cve_map.values())

    def _fetch_cisa_kev(self, cve_map: Dict[str, Dict[str, Any]]) -> None:
        """Fetches actively weaponized vulnerabilities added to CISA KEV."""
        try:
            resp = requests.get(CISA_KEV_URL, timeout=15)
            if resp.status_code != 200:
                print(f"  [!] CISA KEV returned status code: {resp.status_code}")
                return

            data = resp.json()
            cutoff = datetime.now(timezone.utc) - timedelta(
                hours=self.lookback_hours
            )

            for vuln in data.get("vulnerabilities", []):
                date_added_str = vuln.get("dateAdded")
                if not date_added_str:
                    continue
                date_added = datetime.strptime(
                    date_added_str, "%Y-%m-%d"
                ).replace(tzinfo=timezone.utc)

                if date_added >= cutoff:
                    cve_id = vuln.get("cveID")
                    if not cve_id:
                        continue
                    cve_map[cve_id] = {
                        "cve_id": cve_id,
                        "title": vuln.get("vulnerabilityName", ""),
                        "vendor_project": vuln.get("vendorProject", ""),
                        "product": vuln.get("product", ""),
                        "description": vuln.get("shortDescription", ""),
                        "remediation_action": vuln.get("requiredAction", ""),
                        "cvss_score": None,
                        "severity": "CRITICAL",
                        "is_cisa_kev": True,
                        "has_public_exploit": False,
                        "sources": ["CISA KEV"],
                    }
        except Exception as e:
            print(f"  [-] CISA KEV fetch failed: {e}")

    def _fetch_exploit_db(self, cve_map: Dict[str, Dict[str, Any]]) -> None:
        """Fetches newly published public exploits directly from the Exploit-DB mirror."""
        try:
            resp = requests.get(EXPLOIT_DB_CSV_URL, timeout=20)
            if resp.status_code != 200:
                print(f"  [!] Exploit-DB returned status code: {resp.status_code}")
                return

            reader = csv.DictReader(io.StringIO(resp.text))
            cutoff = datetime.now(timezone.utc) - timedelta(
                hours=self.lookback_hours
            )

            for row in reader:
                date_str = row.get("date_published", "")
                if not date_str:
                    continue
                try:
                    pub_date = datetime.strptime(date_str, "%Y-%m-%d").replace(
                        tzinfo=timezone.utc
                    )
                except ValueError:
                    continue

                if pub_date >= cutoff:
                    codes = row.get("codes", "")
                    for token in codes.split(";"):
                        token = token.strip()
                        if token.startswith("CVE-"):
                            if token in cve_map:
                                cve_map[token]["has_public_exploit"] = True
                                cve_map[token]["exploit_id"] = row.get("id")
                                if "Exploit-DB" not in cve_map[token]["sources"]:
                                    cve_map[token]["sources"].append("Exploit-DB")
                            else:
                                cve_map[token] = {
                                    "cve_id": token,
                                    "title": row.get("description", ""),
                                    "description": row.get("description", ""),
                                    "cvss_score": None,
                                    "severity": "HIGH",
                                    "is_cisa_kev": False,
                                    "has_public_exploit": True,
                                    "exploit_id": row.get("id"),
                                    "sources": ["Exploit-DB"],
                                }
        except Exception as e:
            print(f"  [-] Exploit-DB fetch failed: {e}")

    def _fetch_nvd(self, cve_map: Dict[str, Dict[str, Any]]) -> None:
        """Fetches newly published or updated CVE records from NIST NVD API 2.0."""
        try:
            now = datetime.now(timezone.utc)
            start_date = (now - timedelta(hours=self.lookback_hours)).strftime(
                "%Y-%m-%dT%H:%M:%S.000"
            )
            end_date = now.strftime("%Y-%m-%dT%H:%M:%S.000")

            headers = {}
            if self.nvd_api_key:
                headers["apiKey"] = self.nvd_api_key

            params = {
                "pubStartDate": start_date,
                "pubEndDate": end_date,
            }

            resp = requests.get(
                NVD_API_URL, headers=headers, params=params, timeout=25
            )
            if resp.status_code != 200:
                print(f"  [!] NVD API returned status code {resp.status_code}")
                return

            vulnerabilities = resp.json().get("vulnerabilities", [])
            for item in vulnerabilities:
                cve_data = item.get("cve", {})
                cve_id = cve_data.get("id")
                if not cve_id:
                    continue

                metrics = cve_data.get("metrics", {})
                cvss_v31 = metrics.get("cvssMetricV31", [])
                score = None
                severity = "UNKNOWN"
                if cvss_v31:
                    cvss_obj = cvss_v31[0].get("cvssData", {})
                    score = cvss_obj.get("baseScore")
                    severity = cvss_obj.get("baseSeverity", "UNKNOWN")

                # Filter out low-severity CVEs unless already flagged by KEV/Exploit-DB
                if (
                    score is not None
                    and score < self.min_cvss
                    and cve_id not in cve_map
                ):
                    continue

                descriptions = cve_data.get("descriptions", [])
                desc_text = next(
                    (d["value"] for d in descriptions if d.get("lang") == "en"),
                    "",
                )

                if cve_id in cve_map:
                    cve_map[cve_id]["cvss_score"] = score
                    if severity != "UNKNOWN":
                        cve_map[cve_id]["severity"] = severity
                    if not cve_map[cve_id]["description"]:
                        cve_map[cve_id]["description"] = desc_text
                    if "NVD" not in cve_map[cve_id]["sources"]:
                        cve_map[cve_id]["sources"].append("NVD")
                else:
                    cve_map[cve_id] = {
                        "cve_id": cve_id,
                        "title": cve_id,
                        "description": desc_text,
                        "cvss_score": score,
                        "severity": severity,
                        "is_cisa_kev": False,
                        "has_public_exploit": False,
                        "sources": ["NVD"],
                    }
        except Exception as e:
            print(f"  [-] NIST NVD fetch failed: {e}")
