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


# Latest Improvements — v2.1 (26/05/2026)

The latest v2.1 update significantly expands Cyber Storage Verifier into a full enterprise-style storage health diagnostics and forensic telemetry platform while preserving the original counterfeit-capacity verification engine, resumable block-validation architecture, and SHA-256 integrity verification system.

The update introduces advanced live storage-health monitoring, SMART diagnostics, responsive cyber-themed drive dashboards, forensic telemetry visualization, full-device diagnostics windows, improved corruption analytics, intelligent health-risk scoring, enhanced export/report systems, and significantly improved UI responsiveness.

---

## Added Storage Health & Diagnostics Dashboard

- Added advanced Storage Health & Diagnostics dashboard
- Added automatic multi-drive discovery and live telemetry rendering
- Added enterprise-style cyber-themed drive health cards
- Added responsive drive-card rendering and adaptive dashboard scaling
- Added automatic SSD/HDD/NVMe/USB/removable-media classification
- Added intelligent drive identity detection:
  - Model
  - Manufacturer
  - Firmware
  - Serial number
  - Filesystem
  - Bus/interface type
  - Media type
  - Capacity metadata
- Added enterprise-style health summary telemetry widgets
- Added live drive health score visualization
- Added dynamic status badges:
  - GOOD
  - WARNING
  - CRITICAL
  - UNKNOWN

---

## Added Advanced SMART Diagnostics Engine

- Added automatic smartctl discovery
- Added Windows-to-SMART device matching intelligence
- Added SMART confidence scoring
- Added advanced SMART parsing engine
- Added SMART telemetry synchronization
- Added raw SMART output inspection
- Added read-only hardware diagnostics architecture
- Added support for:
  - Reallocated sectors
  - Pending sectors
  - Offline uncorrectable sectors
  - CRC errors
  - Temperature telemetry
  - Power-on hours
  - Power-cycle counts
  - NVMe media integrity errors
  - SSD wear-level telemetry
  - Available spare analysis
  - Unsafe shutdown tracking
  - Host read/write telemetry

---

## Added Intelligent Device-Aware Telemetry

- Added SSD/NVMe wear-level analysis
- Added HDD-specific mechanical-drive interpretation
- Added intelligent fallback wording:
  - Mechanical HDD
  - Not Exposed
  - SMART Unavailable
  - USB Bridge Hidden
  - Not Reported
- Added USB/removable-device SMART fallback handling
- Added NVMe Percentage Used telemetry support
- Added Wear_Leveling_Count support
- Added Media_Wearout_Indicator support
- Added Percent_Lifetime_Remain support

---

## Added Full Drive Diagnostics Window

- Added complete "View Full Details" diagnostics viewer
- Added responsive Toplevel forensic diagnostics window
- Added tabbed diagnostics interface:
  - Overview
  - SMART Details
  - Health Analysis
  - Surface Stability
  - Raw SMART Output
  - History / Timeline
- Added SMART attribute tables
- Added raw SMART telemetry viewer
- Added forensic telemetry history rendering
- Added drive-specific recommendation engine
- Added single-drive TXT/JSON/HTML/PDF forensic report exporting

---

## Added Surface Stability & Read-Only Diagnostics

- Added read-only surface read stability analysis
- Added latency anomaly detection
- Added weak-region and slow-region detection
- Added sampled read-stability scoring
- Added timeout intelligence
- Added read-only CHKDSK preview support
- Added safer diagnostics-only execution model
- Explicitly prevents:
  - Raw disk writes
  - Formatting
  - Repair-volume operations
  - Firmware modification
  - Bad-sector repair execution

---

## Added Advanced Health Risk Intelligence

- Added predictive health-risk scoring engine
- Added SMART degradation analysis
- Added thermal-risk detection
- Added SSD wear-risk analysis
- Added CRC instability intelligence
- Added media/data integrity risk analysis
- Added contextual recommendations:
  - Backup recommended
  - Replacement recommended
  - Monitor this device
  - Mechanical HDD operating normally
  - SSD wear remains within normal range

---

## Added Responsive UI Improvements

- Added fully responsive Health Diagnostics dashboard layout
- Added adaptive drive-card scaling
- Added compact-window optimization
- Added automatic stacked-layout behavior
- Added dynamic resizing logic
- Added scrollable diagnostics containers
- Added improved telemetry readability
- Added improved cyber-style dashboard rendering

---

## Added Enhanced Reporting & Exporting

- Added enhanced forensic storage-health reporting
- Added SMART evidence rendering
- Added interruption-aware forensic exports
- Added advanced telemetry visualization panels
- Added improved PDF forensic export support
- Added enhanced HTML forensic dashboards
- Added drive-specific forensic export support
- Added improved forensic evidence readability
- Added improved non-technical report presentation

---

## Added Testing & Reliability Improvements

- Added extensive health diagnostics unit testing
- Added SMART parser validation tests
- Added HDD/NVMe telemetry rendering verification
- Added uncertain SMART mapping validation
- Added full-details-window testing
- Added export validation testing
- Added device-aware fallback handling tests
- Improved metadata caching reliability
- Improved PowerShell integration stability
- Improved diagnostics responsiveness
- Improved smartctl matching accuracy
- Improved overall application stability

---

## Existing Core Features Preserved

- Counterfeit-capacity detection
- SHA-256 integrity validation
- Resumable block verification
- Session checkpointing
- Corruption intelligence engine
- Fake-capacity boundary analysis
- Forensic evidence tracking
- Multi-format forensic reporting
- Scan history and recovery systems
- Cyber-themed Tkinter dashboard architecture

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
