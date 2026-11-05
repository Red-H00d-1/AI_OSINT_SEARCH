from email.mime.multipart import MIMEMultipart
from email.mime.text import MIMEText
import os
import smtplib
from typing import Any, Dict, List


class EmailNotifier:
    """Formats a responsive HTML email and dispatches it via SMTP."""

    def __init__(self, config: Dict[str, Any]):
        self.config = config
        self.smtp_email = os.getenv("SMTP_EMAIL", "").strip()
        self.smtp_password = os.getenv("SMTP_APP_PASSWORD", "").strip()
        self.recipient_email = os.getenv("RECIPIENT_EMAIL", self.smtp_email).strip()

    def send_digest(self, report: Dict[str, Any]) -> bool:
        """Sends the triage report as an HTML email. Returns True if sent, False otherwise."""
        if not self.smtp_email or not self.smtp_password:
            print("  [!] SMTP_EMAIL or SMTP_APP_PASSWORD not set. Skipping email transmission.")
            return False

        t1 = report.get("tier_1_critical", [])
        t2 = report.get("tier_2_high", [])
        t3 = report.get("tier_3_monitoring", [])
        total_count = len(t1) + len(t2) + len(t3)

        subject = (
            f"{self.config.get('email', {}).get('subject_prefix', '🛡️ [Threat Intel]')} - "
            f"{len(t1)} Critical, {len(t2)} High"
        )

        html_content = self._render_html(report, total_count)
        plain_text = self._render_plain_text(report, total_count)

        msg = MIMEMultipart("alternative")
        msg["Subject"] = subject
        msg["From"] = f"Vulnerability Intelligence Agent <{self.smtp_email}>"
        msg["To"] = self.recipient_email

        msg.attach(MIMEText(plain_text, "plain"))
        msg.attach(MIMEText(html_content, "html"))

        try:
            with smtplib.SMTP_SSL("smtp.gmail.com", 465) as server:
                server.login(self.smtp_email, self.smtp_password)
                server.sendmail(self.smtp_email, self.recipient_email, msg.as_string())
            print(f"  [+] Daily digest successfully emailed to: {self.recipient_email}")
            return True
        except Exception as e:
            print(f"  [-] Failed to send email: {e}")
            return False

    def _render_cards(self, items: List[Dict[str, Any]], border_color: str) -> str:
        cards_html = ""
        for item in items:
            cve_id = item.get("cve_id", "UNKNOWN-CVE")
            cvss = item.get("cvss", "N/A")
            impact = item.get("plain_english_impact", "No impact analysis available.")
            remediation = item.get("actionable_remediation", "Apply vendor security patches.")
            
            badges = []
            if item.get("is_cisa_kev"):
                badges.append('<span style="background:#dc2626;color:#ffffff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;margin-right:6px;">🚨 CISA KEV</span>')
            if item.get("has_public_exploit"):
                badges.append('<span style="background:#ea580c;color:#ffffff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;margin-right:6px;">⚡ EXPLOIT AVAILABLE</span>')
            if item.get("matched_watchlist"):
                tags = ", ".join(item["matched_watchlist"]).upper()
                badges.append(f'<span style="background:#7c3aed;color:#ffffff;padding:2px 8px;border-radius:4px;font-size:11px;font-weight:700;margin-right:6px;">🎯 STACK: {tags}</span>')

            badges_html = "".join(badges)

            cards_html += f"""
            <div style="background:#ffffff;border:1px solid #e2e8f0;border-left:5px solid {border_color};border-radius:8px;padding:16px;margin-bottom:14px;box-shadow:0 1px 2px rgba(0,0,0,0.04);">
                <div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:6px;">
                    <a href="https://nvd.nist.gov/vuln/detail/{cve_id}" style="color:#0f172a;text-decoration:none;font-size:16px;font-weight:700;">{cve_id}</a>
                    <span style="font-size:13px;font-weight:700;color:#334155;background:#f1f5f9;padding:2px 8px;border-radius:4px;">CVSS: {cvss}</span>
                </div>
                <div style="margin-bottom:10px;">{badges_html}</div>
                <div style="font-size:14px;color:#334155;line-height:1.45;margin-bottom:8px;">
                    <strong>Impact:</strong> {impact}
                </div>
                <div style="font-size:13px;color:#065f46;background:#ecfdf5;border:1px solid #a7f3d0;padding:8px 12px;border-radius:6px;">
                    <strong>Mitigation:</strong> {remediation}
                </div>
            </div>
            """
        return cards_html

    def _render_html(self, report: Dict[str, Any], total_count: int) -> str:
        t1_items = report.get("tier_1_critical", [])
        t2_items = report.get("tier_2_high", [])
        summary = report.get("summary", "Automated threat landscape review completed.")

        t1_cards = self._render_cards(t1_items, "#dc2626") if t1_items else "<p style='color:#64748b;'>None detected today.</p>"
        t2_cards = self._render_cards(t2_items, "#ea580c") if t2_items else "<p style='color:#64748b;'>None detected today.</p>"

        return f"""
        <!DOCTYPE html>
        <html>
        <head><meta charset="utf-8"></head>
        <body style="font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Roboto,Helvetica,Arial,sans-serif;background-color:#f8fafc;color:#1e293b;padding:20px;margin:0;">
            <div style="max-width:680px;margin:0 auto;background:#ffffff;border-radius:12px;overflow:hidden;border:1px solid #e2e8f0;box-shadow:0 4px 6px -1px rgba(0,0,0,0.05);">
                <!-- Header -->
                <div style="background:linear-gradient(135deg, #0f172a 0%, #1e293b 100%);color:#ffffff;padding:28px 24px;">
                    <div style="display:inline-block;background:#38bdf8;color:#0f172a;font-size:11px;font-weight:800;padding:2px 8px;border-radius:4px;text-transform:uppercase;margin-bottom:8px;">Autonomous Intel Brief</div>
                    <h1 style="margin:0;font-size:22px;letter-spacing:-0.5px;">Vulnerability Intelligence Digest</h1>
                    <p style="margin:6px 0 0 0;color:#94a3b8;font-size:14px;">Daily automated triage from CISA KEV, Exploit-DB, and NIST NVD</p>
                </div>
                
                <!-- Executive Summary -->
                <div style="padding:18px 24px;background:#f8fafc;border-bottom:1px solid #e2e8f0;font-size:14px;line-height:1.5;color:#334155;">
                    <strong style="color:#0f172a;">Executive Summary:</strong> {summary}
                </div>

                <!-- Main Content -->
                <div style="padding:24px;">
                    <h2 style="font-size:15px;text-transform:uppercase;letter-spacing:0.5px;color:#dc2626;margin:0 0 12px 0;">
                        🚨 Tier 1: Immediate Action Required ({len(t1_items)})
                    </h2>
                    {t1_cards}

                    <h2 style="font-size:15px;text-transform:uppercase;letter-spacing:0.5px;color:#ea580c;margin:28px 0 12px 0;">
                        ⚠️ Tier 2: High Risk ({len(t2_items)})
                    </h2>
                    {t2_cards}
                </div>

                <!-- Footer -->
                <div style="padding:16px 24px;background:#f1f5f9;border-top:1px solid #e2e8f0;text-align:center;font-size:12px;color:#64748b;">
                    Total analyzed today: <strong>{total_count}</strong> CVEs • Automated by GitHub Actions
                </div>
            </div>
        </body>
        </html>
        """

    def _render_plain_text(self, report: Dict[str, Any], total_count: int) -> str:
        lines = [
            "==================================================",
            " VULNERABILITY INTELLIGENCE DIGEST",
            "==================================================",
            f"Executive Summary: {report.get('summary', '')}\n",
        ]
        
        t1 = report.get("tier_1_critical", [])
        if t1:
            lines.append(f"--- TIER 1: IMMEDIATE ACTION REQUIRED ({len(t1)}) ---")
            for item in t1:
                lines.append(f"• {item.get('cve_id')} (CVSS: {item.get('cvss')})")
                lines.append(f"  Impact: {item.get('plain_english_impact')}")
                lines.append(f"  Mitigation: {item.get('actionable_remediation')}\n")

        t2 = report.get("tier_2_high", [])
        if t2:
            lines.append(f"--- TIER 2: HIGH RISK ({len(t2)}) ---")
            for item in t2:
                lines.append(f"• {item.get('cve_id')} (CVSS: {item.get('cvss')})")
                lines.append(f"  Impact: {item.get('plain_english_impact')}")
                lines.append(f"  Mitigation: {item.get('actionable_remediation')}\n")

        lines.append(f"Total analyzed: {total_count}")
        return "\n".join(lines)
