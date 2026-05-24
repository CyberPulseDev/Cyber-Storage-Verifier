# Cyber Storage Verifier

**Cyber Storage Verifier** is a Windows-focused Python desktop application that checks HDDs, SSDs, USB flash drives, SD cards, and other external storage devices for counterfeit capacity indicators, unstable read/write behavior, metadata anomalies, and basic health indicators.

The tool performs verification using normal temporary files inside the selected target folder. It does **not** write directly to raw disks.

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

## Latest Improvements

The latest update significantly improves scan telemetry synchronization, corruption tracking, resumable recovery, and partial report generation while preserving the existing integrity validation engine and scan architecture.

### Added & Improved

- Live recalculation of:
  - Processed blocks
  - Verified blocks
  - Corrupted blocks
  - Failed blocks
  - Read failures
  - Risk score
  - Coverage percentage
  - Current scan phase
  - Current block tracking

- Fixed verification progress behavior
  - Processed progress now advances even during corruption
  - Verified capacity only counts successful SHA-256 validated blocks
  - Separate tracking for:
    - Verified data
    - Corrupted data
    - Failed data
    - Processed data

- Added partial scan finalization
  - Reports now generate even if scans are manually stopped
  - Supports:
    - Stop Scan
    - Cancel
    - Emergency Stop
    - Severe corruption auto-stop
  - Reports are marked:
    - `SCAN INTERRUPTED - PARTIAL RESULTS`

- Added advanced corruption intelligence
  - First corruption block detection
  - Corruption percentage analysis
  - Consecutive corruption tracking
  - Corruption start offset detection
  - Estimated authentic usable capacity
  - SHA-256 mismatch evidence
  - Verified/corrupted/failed range mapping

- Enhanced reporting engine
  - TXT / JSON / CSV / HTML improvements
  - Partial-session evidence preservation
  - Corruption timelines
  - SMART summaries
  - Device metadata
  - Interruption reasons
  - Verified and failed range reporting

- Added optional severe corruption auto-stop
  - Automatically finalizes scans after configurable consecutive corruption thresholds
  - Disabled by default
  - Configurable from Settings

- Improved Active Scan UI
  - Warning banners
  - Live corruption visualization
  - Processed vs verified telemetry
  - Stabilized ETA calculations
  - Live findings updates

- Improved resumable scan reliability
  - Enhanced checkpoint synchronization
  - Improved finalize() and finish_session() handling
  - Better interrupted-session recovery

## Requirements

- Windows 11 recommended
- Python 3.9 or later
- Tkinter, included with most Python Windows installers
- Optional: [smartmontools](https://www.smartmontools.org/) for deeper SMART health checks

No external Python packages are required.

## Installation

Clone the repository:

```bash
git clone https://github.com/YOUR-USERNAME/cyber-storage-verifier.git
cd cyber-storage-verifier
```

Create a virtual environment, optional but recommended:

```bash
python -m venv .venv
.venv\Scripts\activate
```

Install requirements:

```bash
pip install -r requirements.txt
```

Run the application:

```bash
python cyber_storage_verifier.py
```

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

Cyber Storage Verifier is designed to help identify suspicious storage behavior. Results should be treated as technical indicators, not absolute proof. Always validate important findings with deeper testing and trusted forensic or hardware tools.

## License

This project is released under the MIT License.
