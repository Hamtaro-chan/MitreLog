# MitreLog: Log Analysis & MITRE ATT&CK Mapping Tool
MitreLog is a command-line utility that analyses web application access logs to identify potentially malicious HTTP requests and map detected threats to the MITRE ATT&CK® framework for rapid threat investigation.

## The Security Problem Statement
Security Problem: Security Operations Centers (SOCs) monitor millions of log entries every day. Manually inspecting these logs to identify malicious activities is time-consuming and error-prone.

MitreLog addresses this challenge by providing an offline first-stage threat classification tool. The tool extracts structural features from incoming HTTP queries, classifies them using a pre-trained Random Forest model, and maps detected attacks to the MITRE ATT&CK® framework.

## Target end-user
* **SOC Analysts & Incident Responders**
* **Cybersecurity Students**
* **System & Web Administrators**

## Tool Capabilities
### What it does:
* Feature extraction: Extracts structural features from each HTTP request, including entropy, query length, special character frequencies, and common attack keyword counts.
* Threat Classification: Uses a pre-trained Random Forest classifier to distinguish normal traffic from malicious HTTP query.
* MITRE ATT&CK Mapping: Automatically maps detected attack patterns to relevant MITRE ATT&CK techniques.
* Security Reporting: Generates a report summarising detected threats and associated ATT&CK techniques.

### What it does not do:
* Active Protection: It is a detection and analysis tool. It does not block traffic, alter, or interact with active web applications. 
* Real-Time Detection: It is an offine tool, It processes previously collected log files rather than monitoring live network traffic.
* External Services: The tool operates entirely offline and does not require cloud services, paid APIs, or Internet connectivity.

## Installation
1. **Clone the Repository:**
   ```bash
   git clone https://github.com/Hamtaro-chan/MitreLog.git
   cd MitreLog
   ```
2. Install Dependencies
    ```bash
    pip install -r requirements.txt
    ```
3. Verify the Installation
    ```bash
    python src/tool.py --help
    ```

## Repository Structure

```text
MitreLog/
├── README.md
├── MANUAL.md
├── LICENSE
├── requirements.txt
├── datasets/
│   └── dataset_features.csv
├── src/
│   ├── tool.py
│   ├── model.pkl
│   ├── train_model.py
│   └── ...
└── examples/
    └── web_access.log
```

## Quick Start
Run MitreLog on a sample log file:
    ```bash
    python src/tool.py --log examples/web_access.log
    ```
Example Input:

Example output:

## Workflow

```text
Web Access Log
       │
       ▼
Log Parser
       │
       ▼
Feature Extraction
       │
       ▼
Random Forest Classifier
       │
       ▼
Threat Classification
       │
       ▼
MITRE ATT&CK Mapping
       │
       ▼
Security Report
```

## Configuration & Main Options
| Option | Description |
|---------|-------------|
| `--log <path>` | Path to the web server access log file. |

## Limitations
* The current model evaluates request paths and queries. It does not analyse HTTP POST bodies, request headers, or cookie values.
* Detections are directly tied to the feature parameters established during the training phase. Zero-day structural attacks may not trigger the threshold.
* The model is trained on web application HTTP logs only and is not intended for SSH, DNS, Windows Event Logs, or network flow analysis.

## Ethical-Use

This project is intended to support defensive cybersecurity operations, security awareness, and academic research. MitreLog performs offline analysis of web server access logs and does not include capabilities for offensive security, exploitation, or unauthorized access.

Users must ensure they have appropriate authorization before analyzing any log data. The developers are not responsible for any misuse of this software.

## License
This project is open-source and released under the terms of the MIT License.


    

