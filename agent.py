import json
import os
from typing import Any, Dict, List


class VulnerabilityAgent:
    """Uses Gemini to triage, prioritize, and generate actionable mitigations for CVEs."""

    def __init__(self):
        self.api_key = os.getenv("GEMINI_API_KEY", "").strip()
        if not self.api_key:
            raise ValueError(
                "GEMINI_API_KEY is not set. Please set it in your environment or .env file."
            )

        # Initialize Google GenAI client
        try:
            from google import genai
            self.client = genai.Client(api_key=self.api_key)
            self._use_new_sdk = True
        except ImportError:
            import google.generativeai as legacy_genai
            legacy_genai.configure(api_key=self.api_key)
            self.legacy_model = legacy_genai.GenerativeModel("gemini-1.5-flash")
            self._use_new_sdk = False

    def analyze_vulnerabilities(
        self, vulnerabilities: List[Dict[str, Any]]
    ) -> Dict[str, Any]:
        """Triages vulnerabilities into Tier 1 (Critical), Tier 2 (High), and Tier 3 (Monitoring)."""
        if not vulnerabilities:
            return {
                "summary": "Threat landscape is calm. No high-impact CVEs detected in the monitored window.",
                "tier_1_critical": [],
                "tier_2_high": [],
                "tier_3_monitoring": [],
            }

        # Focus on top 35 vulnerabilities to respect context window and prompt budget
        vuln_sample = vulnerabilities[:35]

        prompt = f"""
You are an expert Cyber Threat Intelligence (CTI) and AppSec engineer.
Review and triage the following list of newly detected/updated vulnerabilities:

{json.dumps(vuln_sample, indent=2)}

Guidelines for Classification:
- "tier_1_critical":
    * Any CVE in CISA KEV (actively exploited in the wild).
    * Any CVE with a confirmed public exploit (Exploit-DB).
    * Any CVE matching the user's tech stack watchlist.
    * Any CVSS >= 9.0 (Remote Code Execution, Pre-Auth Authentication Bypass).
- "tier_2_high":
    * CVSS between 7.5 and 8.9 without active exploitation proof yet.
    * Privilege escalation or data exfiltration in widely deployed enterprise libraries.
- "tier_3_monitoring":
    * Emerging issues, DoS, or vulnerabilities with low exploitability.

For each item, provide:
1. cve_id: (exact CVE string)
2. title: (succinct technical title)
3. cvss: (float score or string if unknown)
4. severity: ("CRITICAL", "HIGH", "MEDIUM")
5. plain_english_impact: 1-2 concise sentences answering: "What can an attacker actually achieve?"
6. actionable_remediation: A concrete, practical fix (e.g. "Upgrade package X to >= v2.4.1", "Disable feature Y in config").
7. is_cisa_kev: boolean
8. has_public_exploit: boolean
9. matched_watchlist: array of matched strings

Return strictly valid JSON with this exact schema:
{{
  "summary": "2-3 sentences summarizing key trends and top threats today.",
  "tier_1_critical": [...],
  "tier_2_high": [...],
  "tier_3_monitoring": [...]
}}
"""

        try:
            if self._use_new_sdk:
                from google.genai import types
                response = self.client.models.generate_content(
                    model="gemini-2.5-flash",
                    contents=prompt,
                    config=types.GenerateContentConfig(
                        response_mime_type="application/json",
                        temperature=0.2,
                    ),
                )
                raw_text = response.text
            else:
                response = self.legacy_model.generate_content(
                    prompt,
                    generation_config={"response_mime_type": "application/json", "temperature": 0.2},
                )
                raw_text = response.text

            return json.loads(raw_text)

        except Exception as e:
            print(f"  [!] LLM analysis error: {e}. Falling back to rule-based triage.")
            return self._fallback_triage(vuln_sample)

    def _fallback_triage(self, vulnerabilities: List[Dict[str, Any]]) -> Dict[str, Any]:
        """Rule-based sorting if Gemini API is unreachable."""
        t1, t2, t3 = [], [], []
        for v in vulnerabilities:
            item = {
                "cve_id": v.get("cve_id"),
                "title": v.get("title", v.get("cve_id")),
                "cvss": v.get("cvss_score") or "N/A",
                "severity": v.get("severity", "UNKNOWN"),
                "plain_english_impact": v.get("description", "")[:200] + "...",
                "actionable_remediation": v.get("remediation_action", "Check vendor advisories and update to latest version."),
                "is_cisa_kev": v.get("is_cisa_kev", False),
                "has_public_exploit": v.get("has_public_exploit", False),
                "matched_watchlist": v.get("matched_watchlist", []),
            }
            if v.get("is_cisa_kev") or v.get("has_public_exploit") or v.get("matched_watchlist"):
                t1.append(item)
            elif (v.get("cvss_score") or 0) >= 7.5:
                t2.append(item)
            else:
                t3.append(item)

        return {
            "summary": "Vulnerabilities triaged using rule-based fallback.",
            "tier_1_critical": t1,
            "tier_2_high": t2,
            "tier_3_monitoring": t3,
        }
