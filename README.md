# MitreLog: Access Log Analysis & MITRE ATT&CK Mapping Tool
MitreLog is a command-line utility that analyses web application access logs to identify potentially malicious HTTP requests and map detected threats to the MITRE ATT&CK® framework for rapid threat investigation.

## The Security Problem Statement
Security Problem: Security Operations Centers (SOCs) monitor millions of web server log entries every day. Manually inspecting these logs to identify malicious activities is time-consuming and error-prone.

MitreLog addresses this challenge by providing an offline first-stage threat classification tool. The tool extracts structural features from incoming HTTP queries, classifies them using a pre-trained Random Forest model, and maps detected attacks to the MITRE ATT&CK® framework.

## Target end-user
* **SOC Analysts & Incident Responders**
* **Cybersecurity Students**
* **System & Web Administrators**

## Tool Capabilities
### What it does:
* Feature extraction: Extracts structural features from each HTTP request, including entropy, query length, special character frequencies, and common attack keyword counts.
* Threat Classification: Uses a trained Random Forest classifier to distinguish normal traffic from malicious HTTP requests.
* MITRE ATT&CK Mapping: Automatically maps detected attack patterns to relevant MITRE ATT&CK techniques.
* Security Reporting: Generates a report summarising detected threats and associated ATT&CK techniques.

### What it does not do:
* Active Protection: It is a detection and analysis tool. It does not block traffic, alter, or interact with active web applications. 
* Real-Time Detection: It is an offline tool, It processes previously collected log files rather than monitoring live network traffic.
* External Services: The tool operates entirely offline and does not require cloud services, paid APIs, or Internet connectivity.

### Currently Supported Threats

- SQL Injection (SQLi)
- Cross-Site Scripting (XSS)
- Local File Inclusion / Path Traversal
- System Command Injection
- Ingress Tool Transfers (`wget`/`curl`)
- Credential Brute-Force Waves
- Authentication Endpoint Reconnaissance & Enumeration
- Unclassified or Suspicious High-Entropy Requests

## Requirements

- Python 3.13+
- pip


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
Example Input: in txt and log file
```text
10.82.30.199 - - [28/Jul/2009:08:58:49 -0700] "GET /assets/img/dummy/secondary-news-3.jpg HTTP/1.1" 200 5604
10.82.30.199 - - [28/Jul/2009:08:58:49 -0700] "GET /products?id=1%20UNION%20SELECT%20NULL,NULL,NULL-- HTTP/1.1" 500 532
10.82.30.199 - - [28/Jul/2009:08:58:49 -0700] "GET /assets/img/home-media-block-placeholder.jpg HTTP/1.1" 200 68831
10.82.30.199 - - [28/Jul/2009:08:58:49 -0700] "GET /assets/img/loading.gif HTTP/1.1" 200 2767
10.82.30.199 - - [28/Jul/2009:08:58:49 -0700] "GET /favicon.ico HTTP/1.1" 404 209
10.82.30.199 - - [28/Jul/2009:08:58:49 -0700] "GET /assets/swf/home-media-block.swf HTTP/1.1" 200 123884
```
Example output:
```text
==========================================================================================
              MITRELOG: THREAT DETECTION ENGINE REPORT
==========================================================================================
 Target Resource File   : input-sample1.txt
 Scan Timestamp         : 2026-07-15 20:13:20
 Total Log Metrics      : 356 transactions evaluated
 Threat Signatures      : 5 anomalies flagged
==========================================================================================

[!] MALICIOUS ANOMALY DETECTED [Line 5]
    ↳ Context/Payload  : /products?id=1%20UNION%20SELECT%20NULL,NULL,NULL--
    ↳ Full Log Line    : 10.82.30.199 - - [28/Jul/2009:08:58:49 -0700] "GET /products?id=1%20UNION%20SELECT%20NULL,NULL,NULL-- HTTP/1.1" 500 532
    ↳ Attack Profiling : SQL Injection (SQLi) Attempt
    ↳ MITRE ATT&CK     : T1190 — Exploit Public-Facing Application
    ↳ Assigned Severity: HIGH
    ↳ Intel Scope      : Exploitation of web database validation parameters to run unauthorized SQL commands.
------------------------------------------------------------------------------------------
[!] MALICIOUS ANOMALY DETECTED [Line 18]
    ↳ Context/Payload  : /search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E
    ↳ Full Log Line    : 10.153.239.5 - - [28/Jul/2009:18:11:30 -0700] "GET /search?q=%3Cscript%3Ealert(document.cookie)%3C/script%3E HTTP/1.1" 200 1984
    ↳ Attack Profiling : Cross-Site Scripting (XSS)
    ↳ MITRE ATT&CK     : T1059.007 — Command and Scripting Interpreter: JavaScript
    ↳ Assigned Severity: MEDIUM
    ↳ Intel Scope      : Injection of client-side script payloads designed to execute arbitrary code within a victim's browser session.
------------------------------------------------------------------------------------------
[!] MALICIOUS ANOMALY DETECTED [Line 218]
    ↳ Context/Payload  : /products?id=1%27%20OR%20%271%27=%271
    ↳ Full Log Line    : 10.153.239.5 - - [29/Jul/2009:09:12:13 -0700] "GET /products?id=1%27%20OR%20%271%27=%271 HTTP/1.1" 200 6234 -
    ↳ Attack Profiling : Unclassified Metric/Behavioral Anomaly
    ↳ MITRE ATT&CK     : N/A (Manual Review Required) — Potential False Positive or Unmapped Vector
    ↳ Assigned Severity: LOW/MEDIUM
    ↳ Intel Scope      : The Random Forest model flagged this payload due to high metric deviancy (atypical length or entropy score), but no explicit malicious threat signatures were matched. Manual verification is recommended to determine if this is a benign edge case.
------------------------------------------------------------------------------------------
[!] MALICIOUS ANOMALY DETECTED [Line 262]
    ↳ Context/Payload  : /../../../../windows/win.ini
    ↳ Full Log Line    : 10.216.113.172 - - [12/Aug/2009:05:57:55 -0700] "GET /../../../../windows/win.ini HTTP/1.1" 404 302
    ↳ Attack Profiling : Path Traversal / LFI
    ↳ MITRE ATT&CK     : T1083 — File and Directory Discovery
    ↳ Assigned Severity: HIGH
    ↳ Intel Scope      : Unauthorized file-system path navigation parameters used to map local application folders or access system files.
------------------------------------------------------------------------------------------

==========================================================================================
                        [ SECURITY ANALYSIS REPORT END ]
==========================================================================================

```

## Configuration & Main Options
| Argument | Type | Description |
| :--- | :--- | :--- |
| `--log <path>` | **Required** | Path layout pointing to the target web server access log file to analyze. |
| `--model <path>` | *Optional* | Path to an alternative trained model binary file. Defaults to `src/model.pkl`. |

## Limitations
* The current model evaluates request paths and queries. It does not analyse HTTP POST bodies, request headers, or cookie values.
* Detections are directly tied to the feature parameters established during the training phase. Zero-day structural attacks may not trigger the threshold.
* The model is trained on web application HTTP logs only and is not intended for SSH, DNS, Windows Event Logs, or network flow analysis.
* MitreLog is explicitly designed to triage web application server traffic (e.g., Apache, Nginx, and IIS). It is not designed to analyse network packets, authentication logs, or operating system event logs.
* As with any machine learning–based detection system, MitreLog may produce **false positives** (benign requests classified as malicious) and **false negatives** (malicious requests that are not detected). The generated results should be treated as decision-support information and verified by a security analyst before taking action.
* MITRE ATT&CK mappings are heuristic-based and intended to assist threat analysis. They should not be considered definitive attribution of attacker behaviour.

## Ethical-Use

This project is intended to support defensive cybersecurity operations, security awareness, and academic research. MitreLog performs offline analysis of web server access logs and does not include capabilities for offensive security, exploitation, or unauthorized access.

Users must ensure they have appropriate authorization before analyzing any log data. The developers are not responsible for any misuse of this software.

## License
This project is open-source and released under the terms of the MIT License.


    

