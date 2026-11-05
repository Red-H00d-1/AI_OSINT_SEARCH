import argparse
import json
import sys

try:
    import yaml
except ImportError:
    yaml = None

try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

from agent import VulnerabilityAgent
from emailer import EmailNotifier
from fetcher import VulnerabilityFetcher


def load_config(path: str = "config.yaml"):
    default_config = {
        "min_cvss_score": 7.0,
        "lookback_hours": 24,
        "watchlist": [
            "python", "docker", "kubernetes", "nginx", "react", "node",
            "linux", "postgres", "openssl", "redis"
        ],
        "feeds": {"cisa_kev": True, "nist_nvd": True, "exploit_db": True},
        "email": {"subject_prefix": "🛡️ [Threat Intel] Daily Vulnerability Brief"},
    }
    
    if yaml is None:
        print("[!] Note: PyYAML not installed in local environment. Using built-in config.")
        return default_config

    try:
        with open(path, "r", encoding="utf-8") as f:
            loaded = yaml.safe_load(f)
            return loaded if isinstance(loaded, dict) else default_config
    except Exception as e:
        print(f"[!] Warning: Could not read {path} ({e}). Using default settings.")
        return default_config


def main():
    parser = argparse.ArgumentParser(
        description="Autonomous Vulnerability Intelligence Agent"
    )
    parser.add_argument(
        "--dry-run",
        action="store_true",
        help="Execute analysis without sending email notifications",
    )
    parser.add_argument(
        "--config",
        default="config.yaml",
        help="Path to YAML configuration file (default: config.yaml)",
    )
    args = parser.parse_args()

    print("[*] ===================================================")
    print("[*] Starting Vulnerability Intelligence Pipeline")
    print("[*] ===================================================")

    config = load_config(args.config)

    # 1. Fetch raw vulnerabilities across OSINT sources
    print("[1/3] Ingesting threat data...")
    fetcher = VulnerabilityFetcher(config)
    raw_vulns = fetcher.fetch_all()
    print(f"      Found {len(raw_vulns)} relevant vulnerabilities.")

    if not raw_vulns:
        print("[+] Threat landscape is calm. No new matching CVEs found in this window.")
        return

    # 2. Run Gemini Agent triage & remediation generation
    print("[2/3] Triaging and assessing impact with Gemini AI...")
    try:
        agent = VulnerabilityAgent()
        report = agent.analyze_vulnerabilities(raw_vulns)
    except Exception as e:
        print(f"[!] Agent error: {e}")
        sys.exit(1)

    t1_count = len(report.get("tier_1_critical", []))
    t2_count = len(report.get("tier_2_high", []))
    print(f"      Triage complete: {t1_count} Critical (Tier 1), {t2_count} High (Tier 2)")

    # 3. Notification delivery
    print("[3/3] Preparing notification delivery...")
    if args.dry_run:
        print("\n--- [DRY RUN PREVIEW] ---")
        print(f"Executive Summary: {report.get('summary')}\n")
        notifier = EmailNotifier(config)
        print(notifier._render_plain_text(report, len(raw_vulns)))
    else:
        notifier = EmailNotifier(config)
        sent = notifier.send_digest(report)
        if not sent:
            print("[*] Email was skipped (credentials not configured). Outputting summary to console:")
            print(f"Executive Summary: {report.get('summary')}")

    print("[*] Pipeline finished successfully.")


if __name__ == "__main__":
    main()
