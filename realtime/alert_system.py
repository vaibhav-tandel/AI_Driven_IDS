# alert_system.py — Logging and email notification for IDS alerts
import logging
import os
import sys
import smtplib
import time
from collections import defaultdict
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from datetime import datetime

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from config import LOG_DIR, LOG_FILE, EMAIL_ENABLED, EMAIL_SMTP_SERVER, \
    EMAIL_SMTP_PORT, EMAIL_SENDER, EMAIL_PASSWORD, EMAIL_RECIPIENT, ALERT_COOLDOWN_SECONDS


# ── Severity Classification ──

SEVERITY_MAP = {
    "DDoS":           "CRITICAL",
    "DoS Hulk":       "CRITICAL",
    "DoS GoldenEye":  "HIGH",
    "DoS Slowhttptest":"HIGH",
    "DoS Slowloris":  "HIGH",
    "PortScan":       "MEDIUM",
    "FTP-Patator":    "HIGH",
    "SSH-Patator":    "HIGH",
    "Bot":            "HIGH",
    "Heartbleed":     "CRITICAL",
    "Infiltration":   "CRITICAL",
    "Web Attack":     "HIGH",
    "Web Attack \xa0 Brute Force": "HIGH",
    "Web Attack \xa0 XSS": "HIGH",
    "Web Attack \xa0 Sql Injection": "CRITICAL",
}

SEVERITY_EMOJI = {
    "CRITICAL": "🔴",
    "HIGH":     "🟠",
    "MEDIUM":   "🟡",
    "LOW":      "🟢",
}


def get_severity(attack_type, confidence=0.0):
    """Determine severity based on attack type and confidence."""
    base = SEVERITY_MAP.get(attack_type, "MEDIUM")
    # Upgrade for very high confidence attacks
    if confidence > 95 and base == "HIGH":
        return "CRITICAL"
    # Downgrade for low confidence
    if confidence < 50 and base in ("CRITICAL", "HIGH"):
        return "MEDIUM"
    return base


class AlertSystem:
    """Manages file logging and optional email alerts for detected intrusions."""

    def __init__(self):
        # Ensure log directory exists
        os.makedirs(LOG_DIR, exist_ok=True)

        # Configure file logger
        self.logger = logging.getLogger("IDS_ALERTS")
        self.logger.setLevel(logging.DEBUG)

        # Avoid duplicate handlers
        if not self.logger.handlers:
            # File handler
            fh = logging.FileHandler(LOG_FILE, encoding="utf-8")
            fh.setLevel(logging.DEBUG)
            fh.setFormatter(logging.Formatter(
                "%(asctime)s | %(levelname)s | %(message)s",
                datefmt="%Y-%m-%d %H:%M:%S"
            ))
            self.logger.addHandler(fh)

            # Console handler (for real-time feedback)
            ch = logging.StreamHandler()
            ch.setLevel(logging.WARNING)
            ch.setFormatter(logging.Formatter(
                "%(asctime)s | %(message)s", datefmt="%H:%M:%S"
            ))
            self.logger.addHandler(ch)

        self.alert_count = 0
        self.email_enabled = EMAIL_ENABLED
        self.cooldown_seconds = ALERT_COOLDOWN_SECONDS
        self._alert_cooldown = defaultdict(float)
        print(f"📝 Alert logging to: {LOG_FILE}")

    def should_alert(self, src_ip, attack_type):
        """Return True only when cooldown window has elapsed for (src_ip, attack_type)."""
        key = (src_ip or "?", attack_type or "Unknown")
        now = time.time()
        if now - self._alert_cooldown[key] > self.cooldown_seconds:
            self._alert_cooldown[key] = now
            return True
        return False

    def log_alert(self, alert_data: dict):
        """Log an alert to file and optionally send email."""
        attack = alert_data.get("attack_type", "Unknown")
        severity = alert_data.get("severity", "MEDIUM")
        confidence = alert_data.get("confidence", 0)
        src_ip = alert_data.get("src_ip", "?")
        dst_ip = alert_data.get("dst_ip", "?")
        dst_port = alert_data.get("dst_port", "?")
        emoji = SEVERITY_EMOJI.get(severity, "⚪")

        msg = (f"{emoji} [{severity}] {attack} | "
               f"{src_ip} → {dst_ip}:{dst_port} | "
               f"Confidence: {confidence:.1f}%")

        if severity == "CRITICAL":
            self.logger.critical(msg)
        elif severity == "HIGH":
            self.logger.error(msg)
        elif severity == "MEDIUM":
            self.logger.warning(msg)
        else:
            self.logger.info(msg)

        self.alert_count += 1

        # Email for critical alerts
        if self.email_enabled and severity in ("CRITICAL", "HIGH"):
            self._send_email(alert_data)

    def log_benign(self, src_ip, dst_ip):
        """Log benign traffic (debug level only)."""
        self.logger.debug(f"✅ Normal | {src_ip} → {dst_ip}")

    def log_session_summary(self, stats: dict):
        """Log a session summary."""
        self.logger.info(
            f"📊 SESSION | Total: {stats.get('total', 0)} | "
            f"Attacks: {stats.get('attacks', 0)} | "
            f"Normal: {stats.get('normal', 0)} | "
            f"False Alarms: {stats.get('false_alarms', 0)}"
        )

    def _send_email(self, alert_data):
        """Send email notification for critical alerts."""
        try:
            msg = MIMEMultipart("alternative")
            msg["Subject"] = f"🚨 IDS Alert: {alert_data['attack_type']} ({alert_data['severity']})"
            msg["From"] = EMAIL_SENDER
            msg["To"] = EMAIL_RECIPIENT

            body = f"""
            <html><body style="font-family: monospace; background: #1a1a2e; color: #eaeaea; padding: 20px;">
            <h2 style="color: #ff3366;">🚨 Intrusion Detected</h2>
            <table style="border-collapse: collapse;">
                <tr><td style="padding: 5px; color: #00d4ff;">Attack Type:</td>
                    <td style="padding: 5px;">{alert_data.get('attack_type')}</td></tr>
                <tr><td style="padding: 5px; color: #00d4ff;">Severity:</td>
                    <td style="padding: 5px;">{alert_data.get('severity')}</td></tr>
                <tr><td style="padding: 5px; color: #00d4ff;">Confidence:</td>
                    <td style="padding: 5px;">{alert_data.get('confidence', 0):.1f}%</td></tr>
                <tr><td style="padding: 5px; color: #00d4ff;">Source:</td>
                    <td style="padding: 5px;">{alert_data.get('src_ip')}:{alert_data.get('src_port')}</td></tr>
                <tr><td style="padding: 5px; color: #00d4ff;">Destination:</td>
                    <td style="padding: 5px;">{alert_data.get('dst_ip')}:{alert_data.get('dst_port')}</td></tr>
                <tr><td style="padding: 5px; color: #00d4ff;">Time:</td>
                    <td style="padding: 5px;">{alert_data.get('timestamp')}</td></tr>
            </table>
            </body></html>
            """
            msg.attach(MIMEText(body, "html"))

            with smtplib.SMTP(EMAIL_SMTP_SERVER, EMAIL_SMTP_PORT) as server:
                server.starttls()
                server.login(EMAIL_SENDER, EMAIL_PASSWORD)
                server.sendmail(EMAIL_SENDER, EMAIL_RECIPIENT, msg.as_string())

            self.logger.info(f"📧 Email sent for {alert_data['attack_type']}")
        except Exception as e:
            self.logger.error(f"📧 Email failed: {e}")
