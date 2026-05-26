# Changelog

## v2.1 — Latest Release

### Storage Health & Diagnostics Dashboard

* Added advanced Storage Health & Diagnostics dashboard with automatic multi-drive health discovery.
* Added live device telemetry monitoring for detected storage devices.
* Added enterprise-style cyber-themed diagnostics UI.
* Added responsive health diagnostics layout with adaptive drive-card rendering.
* Added automatic grid resizing, dynamic stacking behavior, scrollable containers, and compact-window optimization.
* Added professional drive health cards with dynamic health score visualization.
* Added cyber-themed status badges, responsive telemetry widgets, SMART summaries, and risk indicator rendering.
* Added enterprise-style health summary widgets for total drives, healthy devices, warning devices, critical-risk devices, and unknown-state tracking.

### Drive Identity & Device Classification

* Added intelligent drive identity discovery.
* Added automatic detection of drive model, manufacturer, firmware version, serial number, filesystem, bus/interface type, media classification, and physical storage metadata.
* Added automatic SSD, HDD, NVMe, USB, and removable-media classification.
* Added intelligent device badge rendering.
* Added storage-type-specific telemetry presentation.
* Added contextual fallback wording such as `Mechanical HDD`, `Not Exposed`, `USB Bridge Hidden`, and `SMART Unavailable`.

### SMART & Windows Health Diagnostics

* Added advanced SMART diagnostics engine with automatic smartctl discovery.
* Added SMART parsing and Windows-to-SMART device mapping intelligence.
* Added SMART-device confidence matching using serial numbers, drive models, bus types, physical drive numbers, and metadata correlation logic.
* Added enhanced Windows storage telemetry integration using `Get-Disk`, `Get-PhysicalDisk`, `Get-Volume`, and `Get-StorageReliabilityCounter`.
* Added live temperature telemetry, wear-level tracking, SMART attribute monitoring, Windows health synchronization, power-cycle analysis, and power-on-hours telemetry integration.
* Added advanced SMART attribute parsing for:
  * `Spin_Retry_Count`
  * `Seek_Error_Rate`
  * `Start_Stop_Count`
  * `Load_Cycle_Count`
  * `Unsafe Shutdowns`
  * `Available Spare`
  * `Controller Busy Time`
  * `Host Read Commands`
  * `Host Write Commands`

### SSD, NVMe, HDD & USB Health Intelligence

* Added NVMe and SSD wear-level analysis using `Percentage Used`, `Wear_Leveling_Count`, `Media_Wearout_Indicator`, `Percent_Lifetime_Remain`, and Windows reliability wear telemetry.
* Added HDD-specific reliability analysis including reallocated sectors, pending sectors, offline uncorrectable sectors, CRC errors, power-on hours, start/stop counts, and mechanical-drive health interpretation.
* Added USB/removable-device fallback logic for devices where SMART or temperature telemetry is hidden by bridge controllers.
* Added drive-specific recommendation engine with contextual health guidance, including backup recommendations, thermal warnings, SMART degradation alerts, and mechanical-drive advisories.

### Predictive Health Risk Scoring

* Added advanced predictive health risk scoring engine.
* Added failure-intelligence logic based on SMART degradation indicators, SSD wear levels, temperature anomalies, CRC instability, and media/data integrity errors.
* Added improved risk interpretation for healthy, warning, critical, and unknown drive states.
* Added safer handling so unsupported telemetry is not treated as a device fault.

### Read-Only Diagnostic Tools

* Added read-only surface read stability diagnostics.
* Added latency anomaly analysis, slow-region detection, timeout intelligence, sampled stability scoring, and non-destructive read verification.
* Added read-only CHKDSK preview integration.
* Added filesystem warning analysis and non-destructive filesystem integrity inspection.
* Added diagnostics-only architecture with explicit prevention of destructive operations, firmware modification, raw-disk writes, formatting, repair-volume actions, and bad-sector repair execution.

### Full Drive Details Viewer

* Added complete `View Full Details` diagnostics window.
* Added responsive `Toplevel` UI with tabbed forensic telemetry views.
* Added dedicated tabs:
  * Overview
  * SMART Details
  * Health Analysis
  * Surface Stability
  * Raw SMART Output
  * History / Timeline
* Added SMART tables, health-analysis panels, raw SMART viewers, and diagnostic history rendering.
* Added raw SMART output viewer with scrollable forensic telemetry rendering, copy-to-clipboard support, and raw smartctl evidence inspection.
* Added single-drive forensic report export support for TXT, JSON, HTML, and PDF formats directly from the full diagnostics viewer.

### Reporting, Export & History Improvements

* Added improved report/export reliability with enhanced storage-health rendering.
* Added SMART evidence preservation and advanced telemetry presentation.
* Added health diagnostics history support for drive health timelines.
* Added single-drive export generation for selected device diagnostics.
* Improved TXT, JSON, HTML, and PDF storage-health report output.

### Testing & Stability

* Added extensive health diagnostics unit testing.
* Added tests for SMART parser validation, device-aware fallback handling, uncertain SMART mapping detection, full-details-window testing, export validation, and HDD/NVMe telemetry rendering verification.
* Improved drive discovery reliability.
* Improved metadata caching.
* Improved PowerShell integration stability.
* Improved smartctl matching accuracy.
* Improved responsive UI scaling.
* Improved diagnostics performance and overall application stability.

---

<details>
<summary>Older Versions</summary>

## v2.0

### Core Features

* Added multiple scan modes.
* Added resumable block verification.
* Added SHA-256 integrity checks.
* Added text, JSON, CSV, and HTML reports.
* Added scan history and session checkpointing.
* Added Windows metadata and optional SMART collection.
* Added cyber-themed Tkinter interface.
* Added fake-capacity boundary detection.
* Added read/write speed analysis.
* Added corruption tracking engine.
* Added risk scoring and forensic findings system.
* Added advanced session recovery architecture.
* Added partial verification support.
* Added live telemetry processing.
* Added corruption boundary analysis.
* Added estimated authentic usable capacity detection.

### Advanced Forensic Reporting System

* Added advanced cyber-forensic HTML dashboard reports.
* Added professional PDF forensic evidence export support.
* Added forensic telemetry visualization panels.
* Added storage authenticity visualization maps.
* Added SHA-256 mismatch forensic evidence tables.
* Added corruption timeline visualization.
* Added risk indicator widgets and warning panels.
* Added final forensic warning banners.
* Added visual corruption analytics dashboards.
* Improved report readability for non-technical users.
* Improved dispute/evidence presentation formatting.

### Telemetry & Verification Improvements

* Added real-time processed, verified, corrupted, and failed scan telemetry.
* Added live corruption analytics and SHA-256 mismatch evidence tracking.
* Fixed verification progress handling during corruption scenarios.
* Added processed vs verified telemetry separation.
* Added improved corruption percentage calculations.
* Added improved processed byte synchronization.
* Added live current block and phase tracking.
* Added estimated authentic usable capacity telemetry.
* Added improved corruption boundary identification.

### Partial Scan Finalization

* Added partial scan finalization with evidence preservation.
* Added support for interrupted scan report generation.
* Added support for Stop Scan, Cancel, Emergency Stop, and severe corruption auto-stop.
* Added interruption-aware forensic reporting.
* Added partial verified/corrupted evidence preservation.
* Added interruption reason tracking.

### Corruption Intelligence Engine

* Added verified, corrupted, and failed block range reporting.
* Added estimated authentic usable capacity detection.
* Added corruption percentage analytics.
* Added consecutive corruption tracking.
* Added corruption start offset detection.
* Added first corruption block detection.
* Added SHA-256 mismatch evidence generation.
* Added advanced corruption range mapping.
* Added fake-capacity boundary intelligence.

### Reporting Engine Enhancements

* Enhanced TXT forensic reporting.
* Enhanced JSON structured forensic reporting.
* Enhanced CSV block evidence reporting.
* Enhanced HTML forensic dashboard rendering.
* Added PDF forensic evidence exporting.
* Added SMART summaries to reports.
* Added forensic storage authenticity maps.
* Added forensic evidence panels.
* Added corruption timeline analytics.
* Added interruption-aware report generation.
* Added final forensic warning sections.

### Session & Recovery Improvements

* Enhanced session recovery and checkpoint synchronization.
* Improved `finalize()` reliability.
* Improved `finish_session()` reliability.
* Improved interrupted-session recovery.
* Improved resumable scan synchronization.
* Improved corruption persistence tracking.
* Improved checkpoint safety handling.

### Active Scan UI Improvements

* Improved Active Scan UI with warning banners.
* Added live findings updates.
* Added live corruption visualization.
* Added processed vs verified telemetry visualization.
* Improved ETA stabilization.
* Improved forensic telemetry rendering.
* Improved corruption analytics presentation.
* Improved dashboard synchronization.

### Stability & Architecture

* Preserved existing scan modes and verification engine.
* Preserved SHA-256 integrity validation architecture.
* Preserved SMART health checks.
* Preserved retry and recovery logic.
* Preserved resumable session architecture.
* Improved forensic reporting pipeline.
* Improved dashboard rendering engine.
* Improved report export reliability.

</details>
