
from gc import get_count
from itertools import count
import re
from datetime import datetime

class BruteForceTracker:
    def __init__(self, threshold=5, time_window=60):
        self.threshold = threshold
        self.time_window = time_window
        self.attempts = {}
        self.last_alert = {}
        self.auth_keywords = ("login", "wp-login", "register", "reset", "signin", "signup", "auth", "password", "credentials", "authenticate", "token")

    def _parse_log_timestamp(self, full_line_str):
        """Extracts and converts standard log timestamps (e.g., 22/Dec/2016:16:20:10) to epoch seconds."""
        match = re.search(r'\[(\d{2}/\w{3}/\d{4}:\d{2}:\d{2}:\d{2})', full_line_str)
        if match:
            ts_str = match.group(1)
            try:
                dt = datetime.strptime(ts_str, "%d/%b/%Y:%H:%M:%S")
                return dt.timestamp()
            except ValueError:
                return None
        return None

    def evaluate_transaction(self, idx, ip_address, payload, full_line_str):
            payload_lower = payload.lower()
            line_lower = full_line_str.lower()

            is_auth = any(keyword in payload_lower for keyword in self.auth_keywords)
            if not is_auth:
                return None
            
            if '"post ' in line_lower:
                method = "POST"
            elif '"get ' in line_lower:
                method = "GET"
            else:
                return None

            log_epoch = self._parse_log_timestamp(full_line_str)
            if log_epoch is None:
                return None
            
            if ip_address not in self.attempts:
                self.attempts[ip_address] = {"GET": [], "POST": []}
            self.attempts[ip_address][method].append(log_epoch)

            self.attempts[ip_address][method] = [t for t in self.attempts[ip_address][method] if log_epoch - t <= self.time_window]
            
            get_count = len(self.attempts[ip_address]["GET"])
            post_count = len(self.attempts[ip_address]["POST"])
            total = get_count + post_count

            last_alert_time = self.last_alert.get(ip_address)

            if total >= self.threshold and (last_alert_time is None or log_epoch - last_alert_time > self.time_window):
                self.last_alert[ip_address] = log_epoch
  
                if post_count > 0:
                    severity = "HIGH"
                    attack = "Credential Brute-Force Attempt"
                    description = (
                        f"{post_count} POST authentication requests "
                        f"detected ({get_count} GET requests also observed). "
                        "Repeated credential submission indicates a brute-force attack."
                    )

                else:
                    severity = "MEDIUM"
                    attack = "Authentication Endpoint Enumeration"

                    description = (
                        f"{get_count} GET requests to authentication endpoints "
                        "without credential submission. This may indicate "
                        "reconnaissance or preparation for brute-force activity."
                    )

                return {
                    "line": f"{idx} (Behavioral Aggregation)",
                    "payload": (
                        f"{method} authentication activity from "
                        f"{ip_address} "
                        f"(GET={get_count}, POST={post_count})"
                    ),
                    "full_line": (
                        f"[State Alert] Host {ip_address} "
                        f"performed {total} authentication requests "
                        f"in {self.time_window} seconds."
                    ),
                    "intel": {
                        "attack_type": attack,
                        "mitre_id": "T1110",
                        "mitre_technique": "Brute Force",
                        "severity": severity,
                        "description": description
                    }              
                }
            return None