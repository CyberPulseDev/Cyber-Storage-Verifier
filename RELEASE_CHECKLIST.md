# GitHub Release Checklist

## Documentation

* [ ] Update `README.md` with latest Storage Health & Diagnostics dashboard, SMART diagnostics, responsive UI, and forensic telemetry features
* [ ] Update `CHANGELOG.md` with latest v2.1 diagnostics, SMART dashboard, and responsive UI improvements
* [ ] Update screenshots with latest Storage Health & Diagnostics dashboard UI
* [ ] Verify all README screenshots and image links load correctly
* [ ] Verify README installation commands use the correct repository URL
* [ ] Verify GitHub project description and repository topics are updated
* [ ] Verify Help Center changelog only shows latest version by default
* [ ] Verify older changelog versions expand/collapse correctly
* [ ] Verify README feature list includes:
  * Storage Health & Diagnostics
  * SMART dashboard
  * Full diagnostics viewer
  * Surface stability analysis
  * Health risk scoring
  * Drive telemetry dashboard

---

## Core Functional Testing

* [ ] Test `python cyber_storage_verifier.py` on Windows 11
* [ ] Test application startup without optional dependencies installed
* [ ] Test startup without smartmontools installed
* [ ] Test startup with smartmontools installed
* [ ] Test Quick Scan on a safe USB drive/folder
* [ ] Test Balanced Scan mode
* [ ] Test Deep Scan mode
* [ ] Test Fake-Capacity Boundary mode
* [ ] Test Quick Health mode
* [ ] Test corruption detection functionality
* [ ] Test SHA-256 mismatch detection
* [ ] Test corruption boundary detection
* [ ] Test estimated authentic capacity calculations
* [ ] Test live telemetry synchronization
* [ ] Test processed vs verified telemetry accuracy
* [ ] Test warning banners and live findings updates
* [ ] Test ETA stabilization during long scans
* [ ] Verify temporary test files clean up properly

---

## Storage Health & Diagnostics Testing

* [ ] Verify Storage Health & Diagnostics dashboard loads correctly
* [ ] Verify automatic multi-drive discovery works correctly
* [ ] Verify drive cards populate automatically
* [ ] Verify responsive dashboard layout works on resize
* [ ] Verify compact-window layout scaling works correctly
* [ ] Verify drive cards do not become unreadable on smaller windows
* [ ] Verify drive-card scrolling works correctly
* [ ] Verify health summary telemetry widgets update correctly
* [ ] Verify drive selection updates detail panels correctly
* [ ] Verify Refresh All Drives works correctly
* [ ] Verify Rescan Selected Drive works correctly
* [ ] Verify Export Health Report works correctly

---

## SMART & Health Diagnostics Validation

* [ ] Test application without smartmontools installed
* [ ] Test automatic smartctl detection
* [ ] Test SMART summary collection
* [ ] Test SMART attribute parsing
* [ ] Verify Windows-to-SMART device matching accuracy
* [ ] Verify SMART confidence scoring works correctly
* [ ] Verify HDD telemetry renders correctly
* [ ] Verify SSD telemetry renders correctly
* [ ] Verify NVMe telemetry renders correctly
* [ ] Verify USB/removable-device fallback handling works correctly
* [ ] Verify wear-level telemetry renders correctly
* [ ] Verify temperature telemetry renders correctly
* [ ] Verify fallback wording renders correctly:
  * Mechanical HDD
  * SMART Unavailable
  * Not Exposed
  * USB Bridge Hidden
* [ ] Verify health risk scoring works correctly
* [ ] Verify recommendations render correctly
* [ ] Verify PowerShell metadata collection works correctly
* [ ] Verify filesystem and volume metadata display correctly

---

## Full Diagnostics Viewer Testing

* [ ] Verify "View Full Details" button opens correctly
* [ ] Verify diagnostics Toplevel window renders correctly
* [ ] Verify responsive resizing works in diagnostics viewer
* [ ] Verify Overview tab renders correctly
* [ ] Verify SMART Details tab renders correctly
* [ ] Verify Health Analysis tab renders correctly
* [ ] Verify Surface Stability tab renders correctly
* [ ] Verify Raw SMART Output tab renders correctly
* [ ] Verify History/Timeline tab renders correctly
* [ ] Verify raw SMART output scrolling works correctly
* [ ] Verify Copy-to-Clipboard functionality works correctly
* [ ] Verify single-drive TXT export works correctly
* [ ] Verify single-drive JSON export works correctly
* [ ] Verify single-drive HTML export works correctly
* [ ] Verify single-drive PDF export works correctly

---

## Surface Stability & Read-Only Diagnostics

* [ ] Verify read-only CHKDSK preview works correctly
* [ ] Verify no destructive disk actions occur
* [ ] Verify surface read stability scan works correctly
* [ ] Verify weak-region detection works correctly
* [ ] Verify latency anomaly detection works correctly
* [ ] Verify timeout handling works correctly
* [ ] Verify read-only diagnostics cannot trigger repair actions

---

## Reporting Validation

* [ ] Confirm TXT reports generate correctly
* [ ] Confirm JSON reports generate correctly
* [ ] Confirm CSV block reports generate correctly
* [ ] Confirm forensic HTML dashboard reports render correctly
* [ ] Confirm PDF reports generate correctly
* [ ] Confirm storage authenticity visualization maps display correctly
* [ ] Confirm SHA-256 evidence tables render correctly
* [ ] Confirm verified/corrupted/failed range mapping works correctly
* [ ] Confirm forensic warning panels display correctly
* [ ] Confirm reports preserve evidence after interrupted scans
* [ ] Confirm SMART summaries render correctly in reports
* [ ] Confirm health diagnostics render correctly in reports
* [ ] Confirm drive telemetry exports correctly
* [ ] Confirm single-drive forensic exports work correctly

---

## Resume & Recovery Testing

* [ ] Confirm resumable sessions work properly
* [ ] Confirm checkpoint synchronization works correctly
* [ ] Confirm interrupted scans generate partial reports correctly
* [ ] Test Stop Scan recovery
* [ ] Test Cancel recovery
* [ ] Test Emergency Stop recovery
* [ ] Test severe corruption auto-stop functionality
* [ ] Confirm partial evidence preservation works correctly
* [ ] Confirm resumable corruption telemetry remains synchronized

---

## UI & Responsiveness Testing

* [ ] Verify dashboard scaling works correctly
* [ ] Verify Help Center layout renders correctly
* [ ] Verify changelog expand/collapse logic works correctly
* [ ] Verify all tabs resize properly
* [ ] Verify telemetry panels remain readable on smaller resolutions
* [ ] Verify no overlapping widgets exist
* [ ] Verify scrollbars behave correctly
* [ ] Verify dark cyber theme consistency across all windows
* [ ] Verify all buttons and widgets use consistent styling

---

## Build & Release

* [ ] Build EXE with PyInstaller
* [ ] Test EXE startup on Windows 11
* [ ] Test EXE startup without smartmontools installed
* [ ] Test EXE startup with smartmontools installed
* [ ] Confirm smartctl detection works correctly in EXE build
* [ ] Confirm reports generate correctly from EXE build
* [ ] Confirm Storage Health & Diagnostics works in EXE build
* [ ] Confirm SMART diagnostics work in EXE build
* [ ] Confirm View Full Details works in EXE build
* [ ] Verify no temporary scan files remain after cleanup
* [ ] Verify icon loads correctly in EXE build
* [ ] Verify report directories create correctly
* [ ] Create release tag (`v2.1`)
* [ ] Upload source ZIP to GitHub Releases
* [ ] Upload optional EXE build to GitHub Releases
* [ ] Verify release assets download correctly

---

## Final Verification

* [ ] Confirm `APP_VERSION = "2.1"` is correct
* [ ] Verify no debug/testing files are committed
* [ ] Verify `.gitignore` excludes reports, logs, cache, and temp sessions
* [ ] Review final GitHub repository formatting
* [ ] Review README formatting on GitHub
* [ ] Perform final end-to-end counterfeit-capacity scan test
* [ ] Perform final end-to-end Storage Health & Diagnostics validation
* [ ] Perform final forensic export validation
* [ ] Confirm application remains diagnostics-only with no destructive disk operations
