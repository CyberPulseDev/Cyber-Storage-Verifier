# GitHub Release Checklist

* [ ] Update `README.md` with latest telemetry and corruption tracking features
* [ ] Confirm all README image links work correctly
* [ ] Test `python cyber_storage_verifier.py` on Windows 11
* [ ] Test Quick Scan on a safe USB drive/folder
* [ ] Test corruption detection and partial report generation
* [ ] Confirm TXT / JSON / CSV / HTML reports generate correctly
* [ ] Confirm resumable sessions and checkpoint recovery work properly
* [ ] Confirm interrupted scans generate partial reports correctly
* [ ] Test severe corruption auto-stop functionality
* [ ] Build EXE with PyInstaller if needed
* [ ] Create release tag (example: `v2.0`)
* [ ] Upload source ZIP and optional EXE to GitHub Releases
* [ ] Verify README installation commands use the correct repository URL
