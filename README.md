# 🛡️ Vulnerability Intelligence Agent

<p align="center">
  <img src="https://img.shields.io/badge/Python-3.11%2B-blue?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.11+" />
  <img src="https://img.shields.io/badge/AI-Google%20Gemini%202.5%20Flash-orange?style=for-the-badge&logo=google&logoColor=white" alt="Gemini AI" />
  <img src="https://img.shields.io/badge/Automation-GitHub%20Actions-2088FF?style=for-the-badge&logo=githubactions&logoColor=white" alt="GitHub Actions" />
  <img src="https://img.shields.io/badge/Cost-%240%20(100%25%20Free)-success?style=for-the-badge" alt="Zero Cost" />
  <img src="https://img.shields.io/badge/License-MIT-green?style=for-the-badge" alt="License MIT" />
</p>

<p align="center">
  <strong>An autonomous, serverless Threat Intelligence agent that correlates daily CVE feeds, filters noise against your specific tech stack, triages risks with Google Gemini, and delivers actionable briefs straight to your inbox.</strong>
</p>

---

## ⚡ The Problem: CVE Fatigue

Security and engineering teams are overwhelmed by dozens of new CVEs published daily. Most vulnerability digests are:
- **Noisy**: Flooded with low-severity or irrelevant issues.
- **Vague**: Long technical jargon without clear real-world impact.
- **Unprioritized**: No distinction between a theoretical flaw and an actively weaponized exploit in the wild.

### The Solution
The **Vulnerability Intelligence Agent** aggregates data across authoritative OSINT sources (**CISA KEV**, **Exploit-DB**, **NIST NVD**), prioritizes threats targeting your actual environment, and uses **Gemini 2.5 Flash** to provide a concise executive summary and concrete remediation commands.

---

## 🏗️ Architecture

```text
       [GitHub Actions Scheduler (Daily 06:00 UTC)]
                            │
                            ▼
 ┌─────────────────────────────────────────────────────────┐
 │                       fetcher.py                        │
 │  • CISA KEV (Actively exploited catalog)                │
 │  • Exploit-DB (Public weaponized PoCs)                  │
 │  • NIST NVD 2.0 (CVSS v3.1 scores & descriptions)       │
 └──────────────────────────┬──────────────────────────────┘
                            │
                            ▼
 ┌─────────────────────────────────────────────────────────┐
 │                        agent.py                         │
 │  • Matches CVEs against your custom stack (config.yaml) │
 │  • Gemini 2.5 Flash triages into Tier 1 / Tier 2        │
 │  • Synthesizes 1-line impact & actionable patch advice  │
 └──────────────────────────┬──────────────────────────────┘
                            │
                            ▼
 ┌─────────────────────────────────────────────────────────┐
 │                       emailer.py                        │
 │  • Builds responsive HTML cards with status badges      │
 │  • Dispatches daily digest via SMTP (Gmail)             │
 └──────────────────────────┬──────────────────────────────┘
                            │
                            ▼
                    📧 Your Inbox
```

---

## 📸 Sample Daily Brief Preview

Every morning, you receive an executive digest formatted with high-contrast priority badges:

```text
🛡️ Vulnerability Intelligence Brief
---------------------------------------------------------------------------------
Executive Summary: Today's threat landscape is dominated by active exploitation of 
authentication bypass flaws in edge appliances and an RCE affecting Dockerized Node runtimes.

🚨 TIER 1: IMMEDIATE ACTION REQUIRED (2)
---------------------------------------------------------------------------------
[CVE-2024-XXXX]  CVSS: 9.8  |  🚨 CISA KEV  |  ⚡ EXPLOIT AVAILABLE  |  🎯 STACK: DOCKER
• Impact: Pre-authentication remote code execution allowing root takeover of container hosts.
• Mitigation: Upgrade docker-engine to >= 26.1.1 immediately or disable legacy API daemon.

⚠️ TIER 2: HIGH PRIORITY (1)
---------------------------------------------------------------------------------
[CVE-2024-YYYY]  CVSS: 8.2  |  🎯 STACK: NGINX
• Impact: Memory disclosure via crafted HTTP/2 request headers.
• Mitigation: Apply vendor patch or disable HTTP/2 stream multiplexing in nginx.conf.
```

---

## 🚀 Quickstart & Local Setup

### 1. Clone & Set Up Environment
```bash
git clone https://github.com/Red-H00d-1/AI_OSINT_SEARCH.git
cd AI_OSINT_SEARCH

# Create virtual environment
python -m venv .venv

# Activate on Windows:
.venv\Scripts\activate
# Activate on Linux/macOS:
source .venv/bin/activate

# Install dependencies
pip install -r requirements.txt
```

### 2. Configure Environment Variables
Copy the template file to `.env`:
```bash
cp .env.example .env
```

Open `.env` and fill in your keys:
```env
# Gemini API Key (Free from Google AI Studio: https://aistudio.google.com/)
GEMINI_API_KEY=your_gemini_api_key_here

# NIST NVD API Key (Optional, free from https://nvd.nist.gov/developers/request-an-api-key)
NVD_API_KEY=

# Gmail SMTP Delivery Credentials
SMTP_EMAIL=your_email@gmail.com
SMTP_APP_PASSWORD=your_16_char_google_app_password
RECIPIENT_EMAIL=recipient_email@gmail.com
```

### 3. Run a Dry Run
Test the fetcher and AI triage without sending an email:
```bash
python main.py --dry-run
```

---

## ☁️ Serverless Automation (GitHub Actions)

This project runs **100% free** on GitHub Actions with no dedicated server required.

### Setup Repository Secrets:
1. On GitHub, navigate to **Settings** > **Secrets and variables** > **Actions**.
2. Click **New repository secret** and add:
   - `GEMINI_API_KEY`
   - `SMTP_EMAIL`
   - `SMTP_APP_PASSWORD`
   - `RECIPIENT_EMAIL`
   - `NVD_API_KEY` *(Optional)*
3. **Done!** The workflow in `.github/workflows/daily_digest.yml` will automatically execute every day at **06:00 UTC**.
4. You can also trigger a manual run anytime under the **Actions** tab on GitHub by clicking **Run workflow**.

---

## ⚙️ Configuration (`config.yaml`)

Customize the agent to match your organization's environment:

```yaml
# Minimum CVSS threshold for general CVEs
min_cvss_score: 7.0

# How far back to look for new CVEs (hours)
lookback_hours: 24

# Tech stack watchlist (case-insensitive keyword matching)
# CVEs matching these technologies are automatically escalated to Tier 1
watchlist:
  - python
  - docker
  - kubernetes
  - nginx
  - react
  - node
  - linux
  - postgres
  - openssl
  - redis
  - golang
  - aws
  - azure

# Enable or disable individual data feeds
feeds:
  cisa_kev: true
  nist_nvd: true
  exploit_db: true

# Email customizations
email:
  subject_prefix: "🛡️ [Threat Intel] Daily Vulnerability Brief"
```

---

## 🗺️ Roadmap

- [x] Multi-source OSINT ingestion (CISA KEV, Exploit-DB, NIST NVD 2.0).
- [x] Tech stack watchlist matching and escalation.
- [x] Gemini 2.5 Flash intelligent triage and mitigation generation.
- [x] Responsive HTML email digest with status badges.
- [x] GitHub Actions automated scheduler.
- [ ] **Discord / Slack Webhook integration** (direct channel alerts).
- [ ] **EPSS (Exploit Prediction Scoring System)** percentage integration.
- [ ] **Stateful caching** with GitHub Gist/Releases to track remediation over time.

---

## 📄 License

Distributed under the **MIT License**. See [`LICENSE`](LICENSE) for more information.
