# MitreLog: Access Log Analysis & MITRE ATT&CK Mapping Tool
## User Command & Technical Manual

## System Requirements & Prerequisites

Before deploying MitreLog, ensure your execution environment meets the following specifications:

* **Runtime Environment:** Python 3.13+
* **Operating System:** Linux, macOS, or Windows 10/11 (PowerShell / Terminal preferred)
* **Core Dependencies:** Managed automatically via `requirements.txt` (`pandas`, `scikit-learn`, `joblib`, `numpy`, `scipy`)

## Installation & Quick Setup

Follow these steps to clone the codebase and initialize the environment layers:

### Step 1: Clone the Repository
   ```bash
   git clone https://github.com/Hamtaro-chan/MitreLog.git
   cd MitreLog
   ```
### Step 2: Initialize Dependencies
   ```bash
   pip install -r requirements.txt
   ```   

## Configuration & Main Options
| Argument | Type | Description |
| :--- | :--- | :--- |
| `--log <path>` | **Required** | Path layout pointing to the target web server access log file to analyze. |
| `--model <path>` | *Optional* | Path to an alternative trained model binary file. Defaults to `src/model.pkl`. |

## Execution Examples
   ```bash
   python src/tool.py --log examples/input-sample-1.txt
   ```
   with Alternative Model Path

    ```bash
    python src/tool.py --log examples/input-sample-1.txt --model src/model.pkl
   ```