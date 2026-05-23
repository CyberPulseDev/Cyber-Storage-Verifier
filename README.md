# Cyber Storage Verifier

**Cyber Storage Verifier** is a Windows-focused Python desktop application for checking HDDs, SSDs, USB pendrives, SD cards, and external storage devices for counterfeit-capacity signs, unstable read/write behavior, metadata anomalies, and basic health indicators.

The tool performs verification using normal temporary files inside the selected target folder. It does **not** write directly to raw disks.

## Features

- Counterfeit-capacity and fake-storage warning checks
- Quick, balanced, deep, full-capacity, random spot, boundary, and health-only scan modes
- Resumable block-based write/read verification
- SHA-256 block integrity validation
- Read/write speed measurement and speed-drop detection
- Windows drive, volume, filesystem, and PowerShell metadata collection
- Optional SMART summary support through `smartctl` from smartmontools
- Risk score, clear status, findings, and conclusion
- Text, JSON, CSV, and HTML report generation
- Scan history and session checkpoints
- Cyber-style Tkinter GUI

## Screenshots

Add screenshots here after uploading the project to GitHub:

```md
![Dashboard](docs/screenshots/dashboard.png)
![Scan Controls](docs/screenshots/scan-controls.png)
![Report](docs/screenshots/report.png)
```

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
