#rule-based mapping of anomalous payloads to the MITRE ATT&CK matrix.
MITRE_SIGNATURES = [
    {
        "mitre_id": "T1190",
        "mitre_technique": "Exploit Public-Facing Application",
        "attack_type": "SQL Injection (SQLi) Attempt",
        "severity": "HIGH",
        "keywords": ["select", "union", "insert", "drop", "' or '1'='1", "--"],
        "description": "Exploitation of web database validation parameters to run unauthorized SQL commands."
    },
    {
        "mitre_id": "T1059.001",
        "mitre_technique": "Command and Scripting Interpreter: PowerShell",
        "attack_type": "PowerShell Script Execution",
        "severity": "HIGH",
        "keywords": ["powershell", "invoke-webrequest", "iwr ", "-encodedcommand", "-enc "],
        "description": "Adversaries abusing PowerShell commands within URL parameters to run malicious terminal scripts."
    },
    {
        "mitre_id": "T1059.007",
        "mitre_technique": "Command and Scripting Interpreter: JavaScript",
        "attack_type": "Cross-Site Scripting (XSS)",
        "severity": "MEDIUM",
        "keywords": ["<script>", "alert(", "onerror=", "onload=", "javascript:", "eval("],
        "description": "Injection of client-side script payloads designed to execute arbitrary code within a victim's browser session."
    },
    {
        "mitre_id": "T1083",
        "mitre_technique": "File and Directory Discovery",
        "attack_type": "Path Traversal / LFI",
        "severity": "HIGH",
        "keywords": ["etc/passwd", "win.ini", "../", "..\\", "boot.ini"],
        "description": "Unauthorized file-system path navigation parameters used to map local application folders or access system files."
    },
    {
        "mitre_id": "T1070.001",
        "mitre_technique": "Indicator Removal: Clear Windows Event Logs",
        "attack_type": "Indicator Removal Attempt",
        "severity": "CRITICAL",
        "keywords": ["wevtutil", " clear-log", "cliquery", "rmdir /s"],
        "description": "Adversaries attempting to clean system auditing logs or local traces via web command triggers."
    },
    {
        "mitre_id": "T1552",
        "mitre_technique": "Unsecured Credentials",
        "attack_type": "Exposed Cleartext Credentials",
        "severity": "MEDIUM",
        "keywords": ["?password=", "&password=", "?passwd=", "&pwd=", "?secret="],
        "description": "Sensible configuration credentials passed transparently within plaintext URL queries, risking capture or compromise."
    },
    {
        "mitre_id": "T1105",
        "mitre_technique": "Ingress Tool Transfer",
        "attack_type": "Ingress Tool Transfer Trigger",
        "severity": "CRITICAL",
        "keywords": ["certutil.exe", "curl ", "wget ", "bitsadmin", "-urlcache"],
        "description": "Web command parameters attempting to use utility binary vectors to download tools from remote systems."
    },
    {
        "mitre_id": "T1203",
        "mitre_technique": "Exploitation for Client Execution",
        "attack_type": "System Command Injection",
        "severity": "CRITICAL",
        "keywords": ["cmd.exe", "bin/bash", "whoami", "id;", "/bin/sh"],
        "description": "Direct execution of unauthorized system host shell context operations via web application parameters."
    }
]

# Mapping to Mitre Attack Types
def map_to_mitre(payload):
    payload_lower = payload.lower()
    for signature in MITRE_SIGNATURES:
        if any(keyword in payload_lower for keyword in signature["keywords"]):
            return {
                "attack_type": signature["attack_type"],
                "mitre_id": signature["mitre_id"],
                "mitre_technique": signature["mitre_technique"],
                "severity": signature["severity"],
                "description": signature["description"]
            }
    return {
        "attack_type": "Anomalous Web Payload Signature",
        "mitre_id": "T1190",
        "mitre_technique": "Exploit Public-Facing Application",
        "severity": "MEDIUM",
        "description": "The payload structural metric profile displays strong statistical deviations, signaling potential exploration or zero-day threats."
    }