# MitreLog: Access Log Analysis & MITRE ATT&CK Mapping Tool

# User Command & Technical Manual

## System Requirements & Prerequisites

Before deploying MitreLog, ensure your execution environment meets the following specifications:

- **Runtime Environment:** Python 3.13+
- **Operating System:** Linux, macOS, or Windows 10/11 (PowerShell or Terminal)
- **Core Dependencies:** Installed automatically via `requirements.txt` (`pandas`, `scikit-learn`, `joblib`, `numpy`, `scipy`)

---

## Installation & Quick Setup

Follow these steps to clone the repository and install the required dependencies.

### Step 1: Clone the Repository

```bash
git clone https://github.com/Hamtaro-chan/MitreLog.git
cd MitreLog
```

### Step 2: Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Configuration & Command-Line Options

| Argument | Required | Description |
|----------|:--------:|-------------|
| `--log <path>` | **Required** | Path to the web server access log file to analyse. |
| `--model <path>` | Optional | Path to an alternative trained model. Defaults to `src/model.pkl`. |

---

## Execution Examples

### Analyse a Log File

```bash
python src/tool.py --log examples/input-sample-1.txt
```

### Use a Custom Model

```bash
python src/tool.py \
    --log examples/input-sample-1.txt \
    --model src/model.pkl
```

---

# Troubleshooting

## Issue: `externally-managed-environment`

On some Linux distributions (such as Ubuntu 23.04+ and Debian 12+), installing Python packages with `pip` may produce an error similar to:

```text
error: externally-managed-environment
```

This occurs because the operating system prevents packages from being installed into the system-managed Python environment.

### Solution

Create and activate a Python virtual environment before installing the project dependencies.

### Linux / macOS

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
python -m venv .venv
.venv\Scripts\Activate.ps1
python -m pip install --upgrade pip
pip install -r requirements.txt
```

After activation, your terminal prompt should display something similar to:

```text
(.venv)
```

Verify that the required packages were installed successfully:

```bash
pip list
```

or

```bash
python -c "import joblib, pandas, sklearn; print('Installation successful.')"
```

---

## Issue: `ModuleNotFoundError: No module named 'joblib'`

This error indicates that the required Python packages have not been installed in the currently active Python environment.

Ensure that:

1. The virtual environment is activated.
2. The project dependencies have been installed.

### Linux / macOS

```bash
source .venv/bin/activate
pip install -r requirements.txt
```

### Windows (PowerShell)

```powershell
.venv\Scripts\Activate.ps1
pip install -r requirements.txt
```

You can verify that Python is using the virtual environment by running:

```bash
python -c "import sys; print(sys.executable)"
```

The output should point to the Python executable inside the project's `.venv` directory.