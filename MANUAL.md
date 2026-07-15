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

## Troubleshooting

### Issue: `externally-managed-environment` when installing dependencies

On some Linux distributions (such as Ubuntu 23.04+ and Debian 12+), installing packages with `pip` may produce an error similar to:

```text
error: externally-managed-environment
```

This occurs because the operating system prevents installing Python packages into the system Python environment.

#### Solution

Create and activate a Python virtual environment before installing the dependencies.

Linux/macOS:

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

Windows (PowerShell):

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

After activation, your terminal prompt should display the virtual environment name:

```text
(.venv)
```

You can verify that the required packages were installed successfully by running:

```bash
pip list
```

or

```bash
python -c "import joblib, pandas, sklearn; print('Installation successful.')"
```

---

### Issue: `ModuleNotFoundError: No module named 'joblib'`

This error indicates that the required Python packages have not been installed in the currently active Python environment.

Ensure that:

1. The virtual environment is activated.
2. The project dependencies have been installed.

```bash
source .venv/bin/activate      # Linux/macOS
# or
.venv\Scripts\Activate.ps1      # Windows

pip install -r requirements.txt
```

You can verify that Python is using the virtual environment:

```bash
python -c "import sys; print(sys.executable)"
```

The printed path should point to the project's `.venv` directory.