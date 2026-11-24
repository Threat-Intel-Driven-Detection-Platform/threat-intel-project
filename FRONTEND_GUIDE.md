# Frontend setup ΓÇö Threat Intel Driven Detection Platform

## What was added
- `app.py`: a Streamlit security-operations dashboard with Overview, Detection Alerts, IOC Inventory, MITRE Mapping, Risk Analysis, and Wazuh Integration pages.
- `requirements.txt`: includes the UI dependencies (Streamlit, Pandas, Plotly) while retaining the existing `requests` dependency.

The existing collectors, parsers, IOC matching, scoring engine, Wazuh configuration, and data files were not rewritten.

## Run on Windows
1. Extract the project ZIP.
2. Open the extracted `threat-intel-project` folder in VS Code.
3. Open a terminal in that folder.
4. (Recommended) Create and activate a virtual environment:

```powershell
py -m venv .venv
.\.venv\Scripts\Activate.ps1
```

5. Install dependencies:

```powershell
py -m pip install --upgrade pip
py -m pip install -r requirements.txt
```

6. Start the dashboard:

```powershell
py -m streamlit run app.py
```

Streamlit will print a local URL, normally `http://localhost:8501`. Open it in your browser. Stop the dashboard with `Ctrl+C` in the terminal.

## Run on Linux / Ubuntu / WSL

```bash
python3 -m venv .venv
source .venv/bin/activate
python -m pip install --upgrade pip
python -m pip install -r requirements.txt
python -m streamlit run app.py
```

## Data handling notes
The dashboard keeps datasets separate:
- **Production ┬╖ official output** reads `results/detections.json`. In the supplied project this file contains zero detections; the dashboard shows that honestly.
- **PCAP Ganna ┬╖ scored case** reads the 15 scored detections from the existing PCAP test output.
- **Synthetic lab ┬╖ validation** reads synthetic scored events and is visibly labelled as synthetic.
- **MTA case ┬╖ case validation** reads the 19 case-specific validation matches (not risk-scored).

Synthetic validation events are never silently mixed with production detections. Risk scores represent investigation priority, not proof of compromise. The MITRE page reflects the project's current mapping file, where no ATT&CK technique is confirmed.

## Troubleshooting
- If `streamlit` is not found, activate `.venv` and rerun `python -m pip install -r requirements.txt`.
- If PowerShell blocks activation, run `Set-ExecutionPolicy -Scope Process -ExecutionPolicy Bypass`, then activate the environment again.
- Keep the terminal open while using the dashboard.
- Run from the project root so the relative project structure remains available.
