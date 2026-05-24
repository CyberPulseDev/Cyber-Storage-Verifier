# GitHub Release Checklist

## Documentation

* [ ] Update `README.md` with latest forensic dashboard, PDF export, and telemetry features
* [ ] Update `CHANGELOG.md` with latest forensic reporting improvements
* [ ] Update `requirements.txt` with optional PDF export dependencies
* [ ] Confirm all README image links and screenshots load correctly
* [ ] Verify README installation commands use the correct repository URL
* [ ] Verify GitHub topics and project description are updated

---

## Functional Testing

* [ ] Test `python cyber_storage_verifier.py` on Windows 11
* [ ] Test application startup without optional dependencies installed
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

---

## SMART & Metadata Validation

* [ ] Test application without smartmontools installed
* [ ] Test optional SMART summary collection
* [ ] Verify PowerShell metadata collection works correctly
* [ ] Confirm filesystem and volume metadata display properly

---

## Build & Release

* [ ] Build EXE with PyInstaller
* [ ] Test EXE startup on Windows 11
* [ ] Confirm reports generate correctly from EXE build
* [ ] Verify no temporary scan files remain after cleanup
* [ ] Create release tag (`v2.0`)
* [ ] Upload source ZIP to GitHub Releases
* [ ] Upload optional EXE build to GitHub Releases
* [ ] Verify release assets download correctly

---

## Final Verification

* [ ] Confirm `APP_VERSION = "2.0"` remains unchanged
* [ ] Verify no debug/testing files are committed
* [ ] Verify `.gitignore` excludes reports and temp sessions
* [ ] Review final GitHub repository formatting
* [ ] Perform final end-to-end scan test before release
