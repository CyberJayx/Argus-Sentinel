# Argus Sentinel

Argus Sentinel is a platform-agnostic, low-profile, autonomous incident response and triage framework. It operates as an automated first line of defense to analyze incoming event streams, deduce threat origin mechanics, deploy containment vectors, execute emergency backups, and alert human analysts across out-of-band communication pipelines.

## Core Features
*   **Decoupled Architecture:** Integrates with any modern security stack (Wazuh, Elastic, Splunk, Palo Alto, Fortinet, CrowdStrike) using custom integration functions.
*   **Operational Stealth:** Runs entirely on an outbound pull-based client loop. No open listening ports or dashboards to be discovered by unauthorized network exploration.
*   **Automated Blast-Radius Mitigation:** Configurable protection for critical infrastructure assets, triggering automatic snapshot isolation and database safety backups.
*   **Collaborative Analyst Terminal:** Native interactive console mode enabling human analysts to converse with the tool, isolate root cause vectors, and command recovery actions.
*   **Multi-Channel Broadcasting:** Full built-in notification dispatch supporting WhatsApp Business Cloud API, Gmail/SMTP, Slack Webhooks, Discord Webhooks, and Telegram Bots.

## Setup & Deployment Instructions

### Prerequisites
*   Python 3.10 or higher
*   Dependencies: `pip install requests python-dotenv`

### Installation Step-by-Step

1. **Clone the repository locally:**
```bash
   git clone [https://github.com/YOUR_USERNAME/argus-sentinel.git](https://github.com/YOUR_USERNAME/argus-sentinel.git)
   cd argus-sentinel
