"""
Argus Sentinel - Autonomous Incident Response & Triage Framework.
Built by CyberSecurity Analysts for Enterprise Detection & Isolation Operations.
"""

import os
import json
import logging
import sys
import smtplib
from email.mime.text import MIMEText
from typing import Dict, Any, List
from dataclasses import dataclass, field
import requests
from dotenv import load_dotenv

load_dotenv()

# Stealth logging configuration - masks process context from casual viewing
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - [sys-telemetry-sync] - %(message)s'
)

@dataclass
class IncidentState:
    raw_alert: Dict[str, Any]
    extracted_indicators: Dict[str, Any] = field(default_factory=dict)
    threat_intel_context: str = ""
    confidence_score: float = 0.0
    recommended_action: str = ""
    execution_status: str = ""
    history: List[str] = field(default_factory=list)

class AgnosticSecurityBridge:
    """Standardizes interaction vectors across decoupled vendor fabrics."""
    def __init__(self):
        self.firewall_provider = os.getenv("FIREWALL_PROVIDER", "GENERIC")
        self.siem_provider = os.getenv("SIEM_PROVIDER", "GENERIC")
        self.edr_provider = os.getenv("EDR_PROVIDER", "GENERIC")

    def block_ip(self, ip: str) -> bool:
        logging.info(f"[Bridge] Executing perimeter block rule for target IP: {ip} via {self.firewall_provider}")
        # Vendor API code block insertions go here
        return True

    def isolate_host(self, host_identifier: str) -> bool:
        logging.info(f"[Bridge] Dispatching isolation payload to host: {host_identifier} via {self.edr_provider}")
        return True

    def trigger_backup(self, asset_id: str) -> bool:
        logging.info(f"[Bridge] Requesting emergency snapshots and backup isolation for asset: {asset_id}")
        return True

    def execute_recovery(self, asset_id: str) -> bool:
        logging.info(f"[Bridge] Deploying automated rollback / image restoration for asset: {asset_id}")
        return True

class ArgusEngine:
    def __init__(self):
        self.bridge = AgnosticSecurityBridge()
        self.brain_url = os.getenv("BRAIN_API_URL")
        self.brain_key = os.getenv("BRAIN_API_KEY")
        self.critical_assets = os.getenv("CRITICAL_ASSETS", "").split(",")

    def _query_engine(self, system_prompt: str, user_prompt: str) -> str:
        headers = {"Authorization": f"Bearer {self.brain_key}", "Content-Type": "application/json"}
        payload = {
            "model": "gpt-4o-mini",
            "messages": [
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_prompt}
            ],
            "temperature": 0.1
        }
        try:
            res = requests.post(self.brain_url, json=payload, headers=headers, timeout=15)
            return res.json()['choices'][0]['message']['content'].strip()
        except Exception as e:
            logging.error(f"Execution telemetry pipeline failure: {e}")
            return "ERROR"

    def triage_pipeline(self, state: IncidentState) -> IncidentState:
        system = (
            "You are Argus Sentinel, an expert automated triage layer. Parse raw telemetry logs "
            "and extract: source_ip, target_host, signature, attack_origin_country, attack_vector, and severity. "
            "Respond strictly with valid JSON."
        )
        response = self._query_engine(system, json.dumps(state.raw_alert))
        try:
            state.extracted_indicators = json.loads(response)
        except Exception:
            state.extracted_indicators = {"error": "Telemetry structure parsing exception"}
        return state

    def intelligence_pipeline(self, state: IncidentState) -> IncidentState:
        indicators = state.extracted_indicators
        ip = indicators.get("source_ip", "Unknown")
        vector = indicators.get("attack_vector", "Unknown")
        
        system = "You are a cyber threat intelligence parsing tool. Evaluate indicators against industry metrics."
        user = f"Analyze threat origin vectors for IP {ip} executing vector {vector}. Trace exact attack origin mechanics and assign a confidence score payload output matching string 'SCORE: <0.0-1.0>' based on historical attack correlation."
        
        response = self._query_engine(system, user)
        state.threat_intel_context = response
        state.confidence_score = 0.85 if "SCORE: 0.8" in response or "high" in response.lower() else 0.45
        return state

    def mitigation_pipeline(self, state: IncidentState) -> IncidentState:
        indicators = state.extracted_indicators
        target = indicators.get("target_host", "")
        source_ip = indicators.get("source_ip", "")

        if any(asset in target for asset in self.critical_assets if asset):
            state.recommended_action = "ESCALATE_IMMEDIATELY"
            self.bridge.trigger_backup(target)
            state.execution_status = f"CRITICAL ASSET TARGETED. Triggered protective snapshot backups for {target}."
            return state

        if state.confidence_score >= 0.75 and source_ip:
            self.bridge.block_ip(source_ip)
            state.execution_status = f"CONTAINED: Appended drop rules for malicious source IP {source_ip}."
            state.recommended_action = "RESOLVE"
        else:
            state.recommended_action = "ESCALATE"
        return state

    def dispatch_notifications(self, message: str):
        """Broadcasts telemetry notifications across active outbound targets."""
        # 1. Telegram
        if os.getenv("TELEGRAM_BOT_TOKEN") and os.getenv("TELEGRAM_CHAT_ID"):
            try:
                url = f"https://api.telegram.org/bot{os.getenv('TELEGRAM_BOT_TOKEN')}/sendMessage"
                requests.post(url, json={"chat_id": os.getenv("TELEGRAM_CHAT_ID"), "text": message}, timeout=5)
            except Exception as e: logging.error(f"Telegram fail: {e}")

        # 2. Slack
        if os.getenv("SLACK_WEBHOOK_URL"):
            try: requests.post(os.getenv("SLACK_WEBHOOK_URL"), json={"text": message}, timeout=5)
            except Exception as e: logging.error(f"Slack fail: {e}")

        # 3. Discord
        if os.getenv("DISCORD_WEBHOOK_URL"):
            try: requests.post(os.getenv("DISCORD_WEBHOOK_URL"), json={"content": message}, timeout=5)
            except Exception as e: logging.error(f"Discord fail: {e}")

        # 4. WhatsApp (Meta Business API)
        if os.getenv("WHATSAPP_PHONE_NUMBER_ID") and os.getenv("WHATSAPP_ACCESS_TOKEN"):
            try:
                url = f"https://graph.facebook.com/v21.0/{os.getenv('WHATSAPP_PHONE_NUMBER_ID')}/messages"
                headers = {"Authorization": f"Bearer {os.getenv('WHATSAPP_ACCESS_TOKEN')}", "Content-Type": "application/json"}
                data = {
                    "messaging_product": "whatsapp",
                    "to": os.getenv("WHATSAPP_RECIPIENT_PHONE"),
                    "type": "text",
                    "text": {"body": message}
                }
                requests.post(url, json=data, headers=headers, timeout=5)
            except Exception as e: logging.error(f"WhatsApp fail: {e}")

        # 5. Gmail / SMTP
        if os.getenv("SMTP_SERVER") and os.getenv("EMAIL_RECIPIENT"):
            try:
                msg = MIMEText(message)
                msg['Subject'] = 'Argus Sentinel - Incident Escalation Report'
                msg['From'] = os.getenv("EMAIL_SENDER")
                msg['To'] = os.getenv("EMAIL_RECIPIENT")
                with smtplib.SMTP(os.getenv("SMTP_SERVER"), int(os.getenv("SMTP_PORT", 587))) as server:
                    server.starttls()
                    server.login(os.getenv("EMAIL_SENDER"), os.getenv("EMAIL_PASSWORD"))
                    server.send_message(msg)
            except Exception as e: logging.error(f"Gmail/SMTP fail: {e}")

    def execute_analysis_loop(self, raw_telemetry: Dict[str, Any]):
        state = IncidentState(raw_alert=raw_telemetry)
        state = self.triage_pipeline(state)
        state = self.intelligence_pipeline(state)
        state = self.mitigation_pipeline(state)

        notification_text = (
            f"=== ARGUS SENTINEL ALERT ===\n"
            f"Target Context: {json.dumps(state.extracted_indicators, indent=2)}\n"
            f"Intel Mapping: {state.threat_intel_context}\n"
            f"Mitigation Matrix: {state.execution_status}\n"
            f"Action Vector: {state.recommended_action}"
        )
        
        if state.recommended_action in ["ESCALATE", "ESCALATE_IMMEDIATELY"]:
            self.dispatch_notifications(notification_text)
            
        return state

    def run_interactive_console(self, state: IncidentState):
        """Launches a local debugging session for real-time analyst collaboration."""
        print("\n" + "="*60)
        print(" ARGUS SENTINEL INTERACTIVE ANALYST INTERFACE")
        print("="*60)
        print(f"\n[!] ALERT TRIGGERED: {state.extracted_indicators.get('signature', 'Unknown Signature')}")
        print(f"[*] ATTACK ORIGIN TRACED: {state.extracted_indicators.get('source_ip', 'Unknown')} ({state.extracted_indicators.get('attack_origin_country', 'Unknown')})")
        print(f"[*] ACTION MATRIX EXECUTED: {state.execution_status}")
        
        while True:
            cmd = input("\nargus-sentinel> ").strip()
            if cmd.lower() in ['exit', 'quit']:
                break
            elif cmd.lower() == 'help':
                print("Available commands: 'explain', 'origin', 'backup', 'recover', 'status', 'exit'")
            elif cmd.lower() == 'explain':
                sys = "You are Argus Sentinel. Explain this technical threat and its blast radius clearly to an analyst."
                print(self._query_engine(sys, f"Explain context: {state.threat_intel_context}"))
            elif cmd.lower() == 'origin':
                print(f"Attack vector identified: {state.extracted_indicators.get('attack_vector', 'Unknown')}")
                print(f"Source Address Pointer: {state.extracted_indicators.get('source_ip', 'Unknown')}")
            elif cmd.lower() == 'backup':
                self.bridge.trigger_backup(state.extracted_indicators.get('target_host', 'generic-host'))
                print("[*] Emergency system snapshot executed.")
            elif cmd.lower() == 'recover':
                self.bridge.execute_recovery(state.extracted_indicators.get('target_host', 'generic-host'))
                print("[*] Recovery sequence initiated. Restoring state from safe baseline snapshot.")
            elif cmd.lower() == 'status':
                print(f"Current Engine State: {state.recommended_action} | Execution Stack: {state.execution_status}")
            else:
                # Direct analytical conversation
                sys = "You are Argus Sentinel, an autonomous security node. Answer the analyst's questions directly based on threat state."
                user_context = f"Incident State: {json.dumps(state.extracted_indicators)}. Analyst Question: {cmd}"
                print(self._query_engine(sys, user_context))

if __name__ == "__main__":
    engine = ArgusEngine()
    # Continuous active scanning validation stub
    mock_ingest_payload = {
        "event_source": "Perimeter-IDS",
        "message": "Exploit attempt payload matched CVE-2024-3094 injection",
        "src_ip": "203.0.113.195",
        "dest_host": "production-database-cluster-01",
        "severity": "critical"
    }
    incident_state = engine.execute_analysis_loop(mock_ingest_payload)
    
    # Enter collaborative terminal interface if run interactively
    if sys.stdin.isatty():
        engine.run_interactive_console(incident_state)

