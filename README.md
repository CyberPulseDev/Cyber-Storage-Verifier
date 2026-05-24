# Cyber Storage Verifier

**Cyber Storage Verifier** is an advanced Windows-focused forensic storage validation and integrity analysis application designed to detect counterfeit USB drives, fake-capacity storage devices, unstable NAND behavior, corruption anomalies, metadata inconsistencies, and suspicious storage behavior.

The application supports HDDs, SSDs, USB flash drives, SD cards, external drives, and removable storage devices through resumable block-level write/read verification using temporary test files created safely inside the selected target directory.

The tool never writes directly to raw disks or partitions.

## Features

- Counterfeit-capacity and fake-storage warning checks
- Quick, balanced, deep, full-capacity, random spot, boundary, and health-only scan modes
- Resumable block-based write/read verification
- SHA-256 block integrity validation
- Real-time processed, verified, corrupted, and failed block telemetry
- Live corruption analytics and SHA-256 mismatch detection
- Partial scan finalization with evidence preservation
- Verified, corrupted, and failed block range analysis
- Estimated authentic usable capacity detection
- Consecutive corruption tracking and corruption boundary detection
- Read/write speed measurement and speed-drop detection
- Windows drive, volume, filesystem, and PowerShell metadata collection
- Optional SMART summary support through `smartctl` from smartmontools
- Risk score, clear status, findings, and conclusion
- Text, JSON, CSV, and HTML report generation
- Scan history and session checkpoints
- Cyber-style Tkinter GUI
- Advanced cyber-forensic HTML dashboard reports
- Professional PDF forensic report export
- Storage authenticity visualization map
- SHA-256 mismatch forensic evidence tables
- Risk indicator and corruption analytics panels
- Visual corruption telemetry dashboard
- Interactive forensic-style reporting interface

## Screenshots

<img width="1352" height="882" alt="Screenshot 2026-05-23 205356" src="https://github.com/user-attachments/assets/35e97305-b8b6-49c6-989f-a6e64ea5ced7" />
<img width="1354" height="854" alt="Screenshot 2026-05-23 205417" src="https://github.com/user-attachments/assets/29bed4bb-d173-495e-85cb-a85dcf6becfd" />
<img width="1356" height="855" alt="Screenshot 2026-05-23 205420" src="https://github.com/user-attachments/assets/2f2ae115-aac2-4f95-9cbf-5b1e454dbe14" />
<img width="1356" height="855" alt="Screenshot 2026-05-23 205423" src="https://github.com/user-attachments/assets/51192301-7cf5-4def-827e-eacf7a5698c7" />
<img width="1361" height="852" alt="Screenshot 2026-05-23 205426" src="https://github.com/user-attachments/assets/fdca21b8-ce74-4d9c-ad80-64e5f27ef4be" />
<img width="1358" height="853" alt="Screenshot 2026-05-23 205429" src="https://github.com/user-attachments/assets/2ad2cac9-3a9f-42a6-86ec-3bfbdab49254" />
<img width="1353" height="852" alt="Screenshot 2026-05-23 205433" src="https://github.com/user-attachments/assets/7918071d-6cdc-420a-9c5f-c1c0a0469a01" />
<img width="1361" height="856" alt="Screenshot 2026-05-23 205437" src="https://github.com/user-attachments/assets/52454496-a9da-49a5-98c7-bf631fceb2ab" />
<img width="1356" height="858" alt="Screenshot 2026-05-23 205441" src="https://github.com/user-attachments/assets/7246fd45-52aa-4fc1-87d9-627678da98e8" />

#*New UI Update*
<img width="1918" height="986" alt="image" src="https://github.com/user-attachments/assets/dcabb658-0741-432b-9db1-bda6281568bb" />


# Latest Improvements — 24/05/2026

The latest update significantly improves forensic telemetry synchronization, corruption analytics, resumable recovery, evidence preservation, report rendering, and PDF export support while preserving the original integrity validation engine and scan architecture.

## Added Advanced Forensic Reporting System

- Fully redesigned cyber-forensic HTML dashboard reports
- Professional evidence presentation layout
- Storage authenticity visualization maps
- Verified/corrupted/failed range visualization
- SHA-256 mismatch evidence tables
- Corruption timeline analytics
- Risk indicator widgets
- Final warning evidence panels
- Visual corruption telemetry dashboards
- Added PDF forensic report exporting
- Improved non-technical readability
- Improved evidence presentation for dispute/report submissions

## Added & Improved

### Live Telemetry Improvements

- Real-time recalculation of:
  - Processed blocks
  - Verified blocks
  - Corrupted blocks
  - Failed blocks
  - Read failures
  - Coverage percentage
  - Current scan phase
  - Current block tracking
  - Estimated authentic capacity

### Verification Improvements

- Processed progress now advances even during corruption
- Verified capacity counts only SHA-256 validated blocks
- Separate tracking for:
  - Verified data
  - Corrupted data
  - Failed data
  - Processed data

### Partial Scan Finalization

- Reports now generate even if scans are interrupted through:
  - Stop Scan
  - Cancel
  - Emergency Stop
  - Severe corruption auto-stop

- Interrupted reports are clearly marked:
  - `SCAN INTERRUPTED - PARTIAL RESULTS`

### Advanced Corruption Intelligence

- First corruption block detection
- Corruption percentage analytics
- Consecutive corruption tracking
- Corruption start offset detection
- Estimated authentic usable capacity
- SHA-256 mismatch evidence generation
- Verified/corrupted/failed range mapping
- Fake-capacity boundary detection

### Reporting Engine Enhancements

- TXT / JSON / CSV / HTML / PDF support
- Corruption timeline visualization
- SMART summaries
- Device metadata
- Interruption reasons
- Verified and failed range reporting
- Storage authenticity visualization
- Risk indicator dashboards

### UI Improvements

- Advanced forensic dashboard design
- Improved telemetry widgets
- Warning banners
- Corruption visualization
- Stabilized ETA calculations
- Live findings updates
- Improved forensic evidence readability

### Resume Engine Improvements

- Enhanced checkpoint synchronization
- Improved finalize() handling
- Better interrupted-session recovery
- Improved corruption persistence tracking

## Requirements

- Windows 11 recommended
- Python 3.9 or later
- Tkinter, included with most Python Windows installers
- Optional: [smartmontools](https://www.smartmontools.org/) for deeper SMART health checks

No external Python packages are required.

# Requirements

- Windows 11 recommended
- Python 3.9 or later
- Tkinter (included with most Windows Python installers)

## Optional Python Dependencies

- For advanced PDF export support:

```bash
pip install weasyprint
```

- OR

```bash
pip install pdfkit
```

- If using `pdfkit`, also install:
  - wkhtmltopdf
  - https://wkhtmltopdf.org/downloads.html

## Optional SMART Health Checks

- Install smartmontools for deeper SMART analysis:
  - https://www.smartmontools.org/

- The application still works without smartmontools installed.

---

# Installation

- Clone the repository:

```bash
git clone https://github.com/CyberPulseDev/Cyber-Storage-Verifier.git
cd Cyber-Storage-Verifier
```

- Create a virtual environment (optional but recommended):

```bash
python -m venv .venv
.venv\Scripts\activate
```

- Install requirements:

```bash
pip install -r requirements.txt
```

- Run the application:

```bash
python cyber_storage_verifier.py
```

---

## How to Use

1. Open the application.
2. Select a target drive or folder.
3. Choose a scan mode.
4. Enter advertised capacity if you want to compare the seller-stated size with the Windows-reported size.
5. Start the scan.
6. Review the risk score, findings, and generated reports.

Reports are saved under:

```text
Documents/CyberStorageVerifier_Reports
```

## Important Safety Notes

- This tool creates temporary test files in the selected location.
- It does not overwrite raw disks or partitions.
- Full-capacity validation can take a long time and may fill most free space during the scan.
- Do not scan a drive that contains your only copy of important files.
- A partial scan cannot fully prove a large drive is genuine. Full-capacity validation gives the strongest result.

## Scan Modes

| Mode | Purpose |
|---|---|
| Quick Scan | Fast basic write/read verification |
| Balanced Scan | Default practical scan for most devices |
| Deep Scan | Larger test coverage for stronger confidence |
| Full Capacity Validation | Uses most available free space for the strongest fake-capacity check |
| Random Spot Check | Samples selected blocks instead of verifying all blocks |
| Fake-Capacity Boundary | Focuses around common fake-capacity boundary areas |
| Quick Health | Metadata and health checks without test writes |

## Reports Generated

The app can generate:

- `.txt` summary report
- `.json` structured report
- `.csv` block-level report
- `.html` readable browser report

## Optional SMART Checks

For deeper drive health information, install smartmontools and make sure `smartctl` is available in your PATH.

The application will still run without smartmontools, but SMART details may show as unavailable.

## Build as Windows EXE

Install PyInstaller:

```bash
pip install pyinstaller
```

Build:

```bash
pyinstaller --onefile --windowed --name "Cyber Storage Verifier" cyber_storage_verifier.py
```

The executable will be created in the `dist` folder.

## Suggested GitHub Topics

```text
python, tkinter, cybersecurity, storage, usb, ssd, hdd, sd-card, fake-capacity, integrity-checker, windows
```

## Disclaimer

Cyber Storage Verifier is a professional forensic storage validation and integrity analysis tool designed to help identify suspicious, unstable, degraded, or potentially counterfeit storage devices through block-level verification, SHA-256 integrity analysis, metadata inspection, corruption telemetry, and forensic reporting. Results generated by the application are intended as technical and forensic indicators only and should not be considered absolute proof of authenticity, failure, or malicious intent. Critical findings should be independently validated using repeated testing, manufacturer diagnostics, trusted forensic utilities, SMART analysis, and additional professional examination where appropriate.

## License

This project is released under the MIT License.
