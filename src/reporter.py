import os
from datetime import datetime

class ReportGenerator:
    def __init__(self, log_path, total_lines, incident_reports):
        self.log_path = log_path
        self.total_lines = total_lines
        self.incident_reports = incident_reports
        self.threats_detected = len(incident_reports)

    def generate_report(self, output_dir="reports"):
        if not os.path.exists(output_dir):
            os.makedirs(output_dir)

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"MitreLog_report_{timestamp}.txt"
        filepath = os.path.join(output_dir, filename)

        with open(filepath, 'w', encoding="utf-8") as report_file:
            report_file.write("="*90 + "\n")
            report_file.write("              MITRELOG: INTELLIGENT THREAT DETECTION ENGINE REPORT\n")
            report_file.write("="*90 + "\n")

            report_file.write(f" Target Resource File   : {os.path.basename(self.log_path)}\n")
            report_file.write(f" Scan Timestamp         : {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            report_file.write(f" Total Log Metrics      : {self.total_lines} transactions evaluated\n")
            report_file.write(f" Threat Signatures      : {self.threats_detected} anomalies flagged\n")
            report_file.write("="*90 + "\n\n")

            if not self.incident_reports:
                report_file.write("[+] SUCCESS: No malicious anomalies detected within this log configuration pipeline.\n")
            else:
                for inc in self.incident_reports:
                    intel = inc["intel"]
                    report_file.write(f"[!] MALICIOUS ANOMALY DETECTED [Line {inc['line']}]\n")
                    report_file.write(f"    ↳ Context/Payload  : {inc['payload']}\n")
                    report_file.write(f"    ↳ Full Log Line    : {inc['full_line']}\n")
                    report_file.write(f"    ↳ Attack Profiling : {intel['attack_type']}\n")
                    report_file.write(f"    ↳ MITRE ATT&CK     : {intel['mitre_id']} — {intel['mitre_technique']}\n")
                    report_file.write(f"    ↳ Assigned Severity: {intel['severity']}\n")
                    report_file.write(f"    ↳ Intel Scope      : {intel['description']}\n")
                    report_file.write("-" * 90 + "\n")

            report_file.write("\n" + "="*90 + "\n")
            report_file.write("                        [ SECURITY ANALYSIS REPORT END ]\n")
            report_file.write("="*90 + "\n")
        print("\n" + "="*50)
        print(f" [*] SCAN COMPLETE: {self.threats_detected} threats found.")
        print(f" [*] Report saved to: {filepath}")
        print("="*50 + "\n")
        return filepath