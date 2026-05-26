#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Cyber Storage Verifier - Storage Authenticity Scanner

The application checks HDD, SSD, USB pendrive, SD card, and external storage
for counterfeit-capacity signals, unstable read/write behavior, metadata
anomalies, and basic health indicators. It never writes to raw disks; all test
data is created inside a normal folder on the selected target.

Python 3.9+ recommended. Windows 11 is the primary target.
Optional: smartctl from smartmontools for deeper SMART summaries.
"""

import csv
import ctypes
import hashlib
import html
import importlib.util
import json
import logging
import math
import os
import platform
import queue
import random
import shutil
import string
import subprocess
import sys
import tempfile
import threading
import time
import traceback
import webbrowser
from dataclasses import asdict, dataclass, field
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox
import tkinter as tk
from tkinter import ttk

APP_NAME = "Cyber Storage Verifier"
APP_VERSION = "2.1"
TEST_DIR_NAME = "_csv_temp_integrity_test"
SESSION_PREFIX = "session_"
CHECKPOINT_NAME = "checkpoint.json"
BLOCK_REPORT_NAME = "block_report.csv"
LOG_FILE_NAME = "scanner.log"
REPORT_DIR_NAME = "CyberStorageVerifier_Reports"
METADATA_CACHE_TTL_SECONDS = 90
MAX_TEXT_WIDGET_CHARS = 180000

CYBER_BG = "#070B14"
CYBER_PANEL = "#0B1220"
CYBER_PANEL_2 = "#101A2C"
CYBER_BORDER = "#1B3355"
CYBER_TEXT = "#D7F7FF"
CYBER_MUTED = "#7EA6B8"
CYBER_GREEN = "#39FF88"
CYBER_CYAN = "#00E5FF"
CYBER_BLUE = "#3B82F6"
CYBER_YELLOW = "#FFD166"
CYBER_ORANGE = "#FF9F1C"
CYBER_RED = "#FF3B6B"
CYBER_PURPLE = "#B46CFF"
INPUT_BG = "#081526"
INPUT_BG_HOVER = "#0D2138"
INPUT_BG_FOCUS = "#102B49"
INPUT_FG = "#F4FCFF"
INPUT_MUTED = "#9FBFD0"
INPUT_DISABLED_BG = "#101722"
INPUT_DISABLED_FG = "#586C7A"
INPUT_SELECT_BG = "#00A9C7"
INPUT_SELECT_FG = "#031019"
INPUT_BORDER = "#2C5E8F"
INPUT_BORDER_FOCUS = "#00E5FF"

BOUNDARY_PRESETS = [8, 16, 32, 64, 128, 256]
REPORT_FORMATS = ("Text", "JSON", "CSV", "HTML", "PDF")
SCAN_MODES = (
    "Quick Scan",
    "Balanced Scan",
    "Deep Scan",
    "Full Capacity Validation",
    "Random Spot Check",
    "Fake-Capacity Boundary",
    "Quick Health",
)
FLUSH_POLICIES = ("Fast", "Balanced", "Deep")


def is_frozen_app() -> bool:
    return bool(getattr(sys, "frozen", False))


def app_base_dir() -> Path:
    if is_frozen_app():
        return Path(sys.executable).resolve().parent
    try:
        return Path(__file__).resolve().parent
    except Exception:
        return Path.cwd()


def resource_path(relative_path) -> str:
    rel = Path(relative_path)
    if rel.is_absolute():
        return str(rel)
    base = Path(getattr(sys, "_MEIPASS", app_base_dir()))
    return str(base / rel)


def external_runtime_dir() -> Path:
    return app_base_dir() / "tools"


def writable_reports_root() -> Path:
    return Path.home() / "Documents" / REPORT_DIR_NAME


def app_cache_dir() -> Path:
    cache = ensure_reports_dir() / "cache"
    cache.mkdir(parents=True, exist_ok=True)
    return cache


APP_ICON_PATH = resource_path("assets/app.ico")
HISTORY_FILE = writable_reports_root() / "scan_history.json"
SETTINGS_FILE = writable_reports_root() / "app_settings.json"


def human_bytes(num: float) -> str:
    if num is None:
        return "Unknown"
    units = ["B", "KB", "MB", "GB", "TB", "PB"]
    n = float(num)
    for unit in units:
        if abs(n) < 1024.0:
            return f"{n:,.2f} {unit}"
        n /= 1024.0
    return f"{n:,.2f} EB"


def gb_to_bytes(gb: float) -> int:
    return int(gb * 1024 ** 3)


def mb_to_bytes(mb: float) -> int:
    return int(mb * 1024 ** 2)


def safe_float(value, default=0.0):
    try:
        if value is None:
            return default
        text = str(value).strip()
        if not text or text.upper() == "AUTO":
            return default
        return float(text)
    except Exception:
        return default


def safe_int(value, default=0):
    try:
        return int(float(str(value).strip()))
    except Exception:
        return default


def now_stamp() -> str:
    return datetime.now().strftime("%Y-%m-%d %H:%M:%S")


def file_stamp() -> str:
    return datetime.now().strftime("%Y%m%d_%H%M%S")


def run_command(cmd, timeout=12):
    try:
        result = subprocess.run(
            cmd,
            shell=False,
            capture_output=True,
            text=True,
            timeout=timeout,
            creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
        )
        return result.returncode, result.stdout.strip(), result.stderr.strip()
    except Exception as exc:
        return 999, "", str(exc)


def run_powershell(script: str, timeout=15):
    if os.name != "nt":
        return None, "PowerShell checks are only supported on Windows."
    cmd = ["powershell", "-NoProfile", "-ExecutionPolicy", "Bypass", "-Command", script]
    code, out, err = run_command(cmd, timeout=timeout)
    if code != 0:
        return None, err or out or f"PowerShell returned {code}"
    if not out:
        return None, "No PowerShell output"
    try:
        return json.loads(out), None
    except Exception:
        return out, None


def get_windows_drives():
    drives = []
    if os.name == "nt":
        bitmask = ctypes.windll.kernel32.GetLogicalDrives()
        for letter in string.ascii_uppercase:
            if bitmask & 1:
                root = f"{letter}:\\"
                if os.path.exists(root):
                    drives.append(root)
            bitmask >>= 1
    else:
        drives = ["/"]
    return drives


def get_drive_type(root: str) -> str:
    if os.name != "nt":
        return "Unknown"
    try:
        dtype = ctypes.windll.kernel32.GetDriveTypeW(ctypes.c_wchar_p(root))
        mapping = {
            0: "Unknown",
            1: "No root directory",
            2: "Removable",
            3: "Fixed",
            4: "Network",
            5: "CD-ROM",
            6: "RAM Disk",
        }
        return mapping.get(dtype, f"Unknown ({dtype})")
    except Exception:
        return "Unknown"


def get_volume_info(root: str):
    info = {
        "volume_name": "Unknown",
        "filesystem": "Unknown",
        "serial": "Unknown",
        "max_component_length": "Unknown",
        "flags": "Unknown",
    }
    if os.name != "nt":
        return info
    try:
        volume_name_buffer = ctypes.create_unicode_buffer(1024)
        fs_name_buffer = ctypes.create_unicode_buffer(1024)
        serial_number = ctypes.c_uint()
        max_component_length = ctypes.c_uint()
        file_system_flags = ctypes.c_uint()
        res = ctypes.windll.kernel32.GetVolumeInformationW(
            ctypes.c_wchar_p(root),
            volume_name_buffer,
            ctypes.sizeof(volume_name_buffer),
            ctypes.byref(serial_number),
            ctypes.byref(max_component_length),
            ctypes.byref(file_system_flags),
            fs_name_buffer,
            ctypes.sizeof(fs_name_buffer),
        )
        if res:
            info["volume_name"] = volume_name_buffer.value or "None"
            info["filesystem"] = fs_name_buffer.value or "Unknown"
            info["serial"] = f"{serial_number.value:08X}"
            info["max_component_length"] = str(max_component_length.value)
            info["flags"] = f"0x{file_system_flags.value:08X}"
    except Exception:
        pass
    return info


def get_disk_root(path):
    if os.name == "nt":
        drive, _ = os.path.splitdrive(os.path.abspath(path))
        return f"{drive}\\"
    return "/"


def get_disk_metadata_for_drive(root: str):
    if os.name != "nt":
        return {}, "Metadata collection is Windows-focused."
    drive_letter = root[0].upper()
    script = rf"""
$ErrorActionPreference = 'SilentlyContinue'
$part = Get-Partition -DriveLetter '{drive_letter}'
$disk = $part | Get-Disk
$physical = Get-PhysicalDisk | Where-Object {{
    $_.DeviceId -eq $disk.Number -or $_.FriendlyName -like "*$($disk.FriendlyName)*"
}} | Select-Object -First 1
$vol = Get-Volume -DriveLetter '{drive_letter}'
$obj = [PSCustomObject]@{{
    DriveLetter = '{drive_letter}'
    DiskNumber = $disk.Number
    FriendlyName = $disk.FriendlyName
    SerialNumber = $disk.SerialNumber
    Manufacturer = $disk.Manufacturer
    Model = $disk.Model
    BusType = $disk.BusType
    PartitionStyle = $disk.PartitionStyle
    IsBoot = $disk.IsBoot
    IsSystem = $disk.IsSystem
    IsReadOnly = $disk.IsReadOnly
    OperationalStatus = ($disk.OperationalStatus -join ', ')
    HealthStatus = $disk.HealthStatus
    Size = $disk.Size
    VolumeSize = $vol.Size
    VolumeSizeRemaining = $vol.SizeRemaining
    FileSystemType = $vol.FileSystemType
    PhysicalFriendlyName = $physical.FriendlyName
    PhysicalSerialNumber = $physical.SerialNumber
    PhysicalMediaType = $physical.MediaType
    PhysicalBusType = $physical.BusType
    PhysicalHealthStatus = $physical.HealthStatus
    PhysicalOperationalStatus = ($physical.OperationalStatus -join ', ')
}}
$obj | ConvertTo-Json -Compress -Depth 5
"""
    data, err = run_powershell(script, timeout=18)
    if isinstance(data, dict):
        return {k: ("Unknown" if v is None or v == "" else v) for k, v in data.items()}, None
    return {}, err or "PowerShell disk mapping unavailable."


_DISK_METADATA_CACHE = {}


def get_disk_metadata_for_drive_cached(root: str, ttl=METADATA_CACHE_TTL_SECONDS):
    key = normalize_drive_root(root).upper() if isinstance(root, str) else str(root)
    now = time.time()
    cached = _DISK_METADATA_CACHE.get(key)
    if cached and now - cached.get("timestamp", 0) <= ttl:
        return dict(cached.get("metadata", {})), cached.get("warning")
    metadata, warning = get_disk_metadata_for_drive(root)
    _DISK_METADATA_CACHE[key] = {"timestamp": now, "metadata": dict(metadata or {}), "warning": warning}
    return metadata, warning


def smartctl_available():
    names = ["smartctl.exe", "smartctl-nc.exe", "smartctl"]
    search_dirs = [
        external_runtime_dir(),
        app_base_dir() / "tools",
        app_base_dir(),
        Path(resource_path("tools")),
        Path(resource_path(".")),
        Path.cwd(),
        Path(r"C:\Program Files\smartmontools\bin"),
        Path(r"C:\Program Files (x86)\smartmontools\bin"),
    ]
    seen = set()
    for folder in search_dirs:
        try:
            folder = Path(folder)
            key = str(folder.resolve()).lower()
        except Exception:
            key = str(folder).lower()
        if key in seen:
            continue
        seen.add(key)
        for name in names:
            candidate = folder / name
            if candidate.is_file():
                return str(candidate)
    for name in names:
        path = shutil.which(name)
        if path:
            return path
    return None


def collect_smartctl_summary():
    exe = smartctl_available()
    if not exe:
        return None, "smartctl not found. Install smartmontools for deeper SMART health checks."
    code, out, err = run_command([exe, "--scan-open"], timeout=10)
    if code != 0 or not out:
        return None, err or "smartctl scan failed."
    devices = []
    for line in out.splitlines():
        dev = line.split()[0].strip()
        if not dev:
            continue
        code2, out2, err2 = run_command([exe, "-H", "-i", dev], timeout=15)
        devices.append({"device": dev, "summary": out2[:4000] if out2 else err2[:1000]})
    return devices, None


def ensure_reports_dir() -> Path:
    reports_dir = writable_reports_root()
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
        probe = reports_dir / ".write_test.tmp"
        probe.write_text("ok", encoding="utf-8")
        probe.unlink(missing_ok=True)
    except Exception:
        reports_dir = Path(tempfile.gettempdir()) / REPORT_DIR_NAME
        reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def pdf_engine_available():
    engines = []
    if importlib.util.find_spec("weasyprint") is not None:
        engines.append("WeasyPrint installed")
    if importlib.util.find_spec("pdfkit") is not None:
        engines.append("pdfkit installed")
    return engines


def check_packaged_runtime():
    reports_dir = ensure_reports_dir()
    smartctl_path = smartctl_available()
    icon_path = Path(APP_ICON_PATH)
    engines = pdf_engine_available()
    info = {
        "frozen": is_frozen_app(),
        "app_base_dir": str(app_base_dir()),
        "pyinstaller_meipass": str(getattr(sys, "_MEIPASS", "")),
        "external_runtime_dir": str(external_runtime_dir()),
        "reports_dir": str(reports_dir),
        "cache_dir": str(app_cache_dir()),
        "smartctl_path": smartctl_path or "Not detected",
        "icon_detected": icon_path.is_file(),
        "icon_path": str(icon_path),
        "pdf_engines": engines or ["Unavailable"],
    }
    logging.info("Runtime self-check: %s", json.dumps(info, indent=2))
    return info


def append_history(entry: dict):
    reports_dir = ensure_reports_dir()
    history_path = reports_dir / "scan_history.json"
    try:
        existing = []
        if history_path.exists():
            existing = json.loads(history_path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
        entry_key = (
            entry.get("completed_at"),
            entry.get("target"),
            entry.get("health_status"),
            entry.get("health_risk_score"),
        )
        existing = [
            item for item in existing
            if (
                item.get("completed_at"),
                item.get("target"),
                item.get("health_status"),
                item.get("health_risk_score"),
            ) != entry_key
        ]
        existing.insert(0, entry)
        history_path.write_text(json.dumps(existing[:200], indent=2), encoding="utf-8")
    except Exception:
        logging.exception("Failed to write history")


def load_history():
    history_path = ensure_reports_dir() / "scan_history.json"
    try:
        if history_path.exists():
            data = json.loads(history_path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
    except Exception:
        logging.exception("Failed to load history")
    return []


def append_health_history(entry: dict):
    reports_dir = ensure_reports_dir()
    history_path = reports_dir / "health_history.json"
    try:
        existing = []
        if history_path.exists():
            existing = json.loads(history_path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
        existing.insert(0, entry)
        history_path.write_text(json.dumps(existing[:200], indent=2), encoding="utf-8")
    except Exception:
        logging.exception("Failed to write health history")


def load_health_history():
    history_path = ensure_reports_dir() / "health_history.json"
    try:
        if history_path.exists():
            data = json.loads(history_path.read_text(encoding="utf-8"))
            return data if isinstance(data, list) else []
    except Exception:
        logging.exception("Failed to load health history")
    return []


def normalize_drive_root(path):
    if not path:
        return path
    if os.name == "nt":
        drive, _ = os.path.splitdrive(os.path.abspath(path))
        return f"{drive}\\" if drive else path
    return path


def clean_identity_value(value):
    if value is None:
        return ""
    text = str(value).strip()
    if not text or text.lower() in ("unknown", "none", "null", "0"):
        return ""
    return text


def classify_drive_badge(drive_type, metadata):
    meta = metadata or {}
    bus = clean_identity_value(meta.get("BusType") or meta.get("PhysicalBusType")).upper()
    media = clean_identity_value(meta.get("PhysicalMediaType") or meta.get("MediaType")).upper()
    friendly = clean_identity_value(meta.get("PhysicalFriendlyName") or meta.get("FriendlyName") or meta.get("Model")).upper()
    dtype = (drive_type or "").upper()
    combined = f"{bus} {media} {friendly} {dtype}"
    if "NVME" in combined:
        return "NVMe SSD"
    if "USB" in combined:
        if "HDD" in combined or "HARD" in combined:
            return "USB HDD"
        if "SSD" in combined:
            return "USB SSD"
        return "USB Removable" if "REMOVABLE" in combined else "USB Storage"
    if "SD" in combined and ("REMOVABLE" in combined or "CARD" in combined):
        return "SD Card / Removable"
    if "SATA" in combined or "ATA" in combined:
        if "SSD" in combined or "SOLID" in combined:
            return "SATA SSD"
        if "HDD" in combined or "HARD" in combined:
            return "SATA HDD"
        return "SATA Storage"
    if "SSD" in combined or "SOLID" in combined:
        return "SSD"
    if "HDD" in combined or "HARD" in combined:
        return "HDD"
    if "REMOVABLE" in combined:
        return "Removable"
    return drive_type or "Unknown"


def preferred_drive_name(metadata, volume_info):
    meta = metadata or {}
    vol = volume_info or {}
    manufacturer = clean_identity_value(meta.get("Manufacturer"))
    model = clean_identity_value(meta.get("Model"))
    candidates = [
        clean_identity_value(meta.get("PhysicalFriendlyName")),
        clean_identity_value(meta.get("FriendlyName")),
        model,
        f"{manufacturer} {model}".strip() if manufacturer or model else "",
        clean_identity_value(vol.get("volume_name")) if clean_identity_value(vol.get("volume_name")).lower() != "none" else "",
    ]
    for item in candidates:
        if item:
            return item
    return "Unknown Storage Device"


def build_drive_display_name(root, metadata=None, volume_info=None, usage=None, drive_type=None):
    letter = root[:2].upper() if os.name == "nt" and root else root
    name = preferred_drive_name(metadata, volume_info)
    capacity = human_bytes(getattr(usage, "total", 0) if usage else 0)
    badge = classify_drive_badge(drive_type or get_drive_type(root), metadata or {})
    return f"({letter}) {name} — {capacity} — {badge}"


def discover_drive_identities_quick():
    identities = []
    roots = get_windows_drives()
    if not roots and os.name != "nt":
        roots = ["/"]
    for root in roots:
        volume_info = {}
        usage = None
        drive_type = "Unknown"
        warning = ""
        try:
            drive_type = get_drive_type(root)
        except Exception as exc:
            warning = str(exc)
        try:
            volume_info = get_volume_info(root)
        except Exception as exc:
            warning = warning or str(exc)
        try:
            usage = shutil.disk_usage(root)
        except Exception as exc:
            warning = warning or str(exc)
        display = build_drive_display_name(root, {}, volume_info, usage, drive_type)
        identities.append(
            {
                "root": root,
                "display": display,
                "volume_info": volume_info or {},
                "metadata": {},
                "usage": {
                    "total": getattr(usage, "total", 0) if usage else 0,
                    "used": getattr(usage, "used", 0) if usage else 0,
                    "free": getattr(usage, "free", 0) if usage else 0,
                },
                "drive_type": drive_type,
                "badge": classify_drive_badge(drive_type, {}),
                "warning": warning or "Physical disk metadata is still loading.",
                "quick": True,
            }
        )
    return identities


def discover_drive_identities():
    identities = []
    for root in get_windows_drives():
        volume_info = {}
        metadata = {}
        usage = None
        warning = ""
        drive_type = "Unknown"
        try:
            drive_type = get_drive_type(root)
        except Exception as exc:
            warning = str(exc)
        try:
            volume_info = get_volume_info(root)
        except Exception as exc:
            warning = warning or str(exc)
        try:
            usage = shutil.disk_usage(root)
        except Exception as exc:
            warning = warning or str(exc)
        try:
            metadata, meta_warning = get_disk_metadata_for_drive_cached(root)
            warning = warning or (meta_warning or "")
        except Exception as exc:
            metadata = {}
            warning = warning or str(exc)
        display = build_drive_display_name(root, metadata, volume_info, usage, drive_type)
        identities.append(
            {
                "root": root,
                "display": display,
                "volume_info": volume_info or {},
                "metadata": metadata or {},
                "usage": {
                    "total": getattr(usage, "total", 0) if usage else 0,
                    "used": getattr(usage, "used", 0) if usage else 0,
                    "free": getattr(usage, "free", 0) if usage else 0,
                },
                "drive_type": drive_type,
                "badge": classify_drive_badge(drive_type, metadata or {}),
                "warning": warning,
            }
        )
    if not identities and os.name != "nt":
        root = "/"
        try:
            usage = shutil.disk_usage(root)
        except Exception:
            usage = None
        identities.append(
            {
                "root": root,
                "display": build_drive_display_name(root, {}, {}, usage, "Unknown"),
                "volume_info": {},
                "metadata": {},
                "usage": {
                    "total": getattr(usage, "total", 0) if usage else 0,
                    "used": getattr(usage, "used", 0) if usage else 0,
                    "free": getattr(usage, "free", 0) if usage else 0,
                },
                "drive_type": "Unknown",
                "badge": "Unknown",
                "warning": "Windows drive identity metadata is unavailable on this platform.",
            }
        )
    return identities


LAST_HEALTH_SUMMARY = {}


@dataclass
class ScanIssue:
    severity: str
    title: str
    detail: str
    points: int


@dataclass
class BlockRecord:
    index: int
    offset: int
    size: int
    seed: str
    expected_sha256: str = ""
    write_status: str = "pending"
    read_status: str = "pending"
    verification_result: str = "pending"
    timestamp: str = ""
    write_speed_mb_s: float = 0.0
    read_speed_mb_s: float = 0.0
    retries: int = 0
    error_details: str = ""


@dataclass
class ScanResult:
    root: str
    started_at: str = field(default_factory=now_stamp)
    completed_at: str = ""
    status: str = "Unknown"
    risk_score: int = 0
    capacity_reported_bytes: int = 0
    free_bytes: int = 0
    used_bytes: int = 0
    advertised_bytes: int = 0
    drive_type: str = "Unknown"
    volume_info: dict = field(default_factory=dict)
    disk_metadata: dict = field(default_factory=dict)
    metadata_warning: str = ""
    smart_summary: object = None
    smart_warning: str = ""
    write_mb_s: float = 0.0
    read_mb_s: float = 0.0
    speed_variation_percent: float = 0.0
    test_size_bytes: int = 0
    block_size_bytes: int = 0
    total_blocks: int = 0
    blocks_tested: int = 0
    verified_blocks: int = 0
    failed_blocks: int = 0
    corrupted_blocks: int = 0
    processed_blocks: int = 0
    verified_bytes: int = 0
    corrupted_bytes: int = 0
    failed_bytes: int = 0
    processed_bytes: int = 0
    coverage_percent: float = 0.0
    corruption_percent: float = 0.0
    first_corruption_block: int = 0
    first_failure_timestamp: str = ""
    consecutive_corruption_count: int = 0
    max_consecutive_corruption_count: int = 0
    corruption_start_offset: int = 0
    estimated_valid_capacity_bytes: int = 0
    last_successful_block: int = 0
    current_block_index: int = 0
    current_phase: str = "Starting"
    scan_interrupted: bool = False
    interruption_reason: str = ""
    finalization_reason: str = "completed"
    write_failures: int = 0
    read_failures: int = 0
    speed_drops: list = field(default_factory=list)
    fake_capacity_indicators: list = field(default_factory=list)
    issues: list = field(default_factory=list)
    report_path: str = ""
    json_report_path: str = ""
    csv_report_path: str = ""
    html_report_path: str = ""
    pdf_report_path: str = ""
    session_id: str = ""
    session_dir: str = ""
    scan_mode: str = "Balanced Scan"
    flush_policy: str = "Balanced"
    conclusion: str = ""
    health_diagnostics: dict = field(default_factory=dict)


@dataclass
class HealthDiagnosticResult:
    target: str = ""
    started_at: str = field(default_factory=now_stamp)
    completed_at: str = ""
    health_status: str = "Not Checked"
    smart_status: str = "Not Checked"
    windows_health_status: str = "Not Checked"
    temperature: str = "Unknown"
    wear_age: str = "Unknown"
    read_stability_status: str = "Not Checked"
    health_risk_score: int = 0
    recommendation: str = "No health diagnostics have been run yet."
    smart_available: bool = False
    smart_devices: list = field(default_factory=list)
    smart_selected_device: str = ""
    smart_match_confidence: str = "Unknown"
    smart_match_reason: str = ""
    smart_raw_output: str = ""
    smart_parsed: dict = field(default_factory=dict)
    windows_raw: object = None
    windows_parsed: dict = field(default_factory=dict)
    chkdsk_output: str = ""
    surface_results: dict = field(default_factory=dict)
    issues: list = field(default_factory=list)
    report_txt: str = ""
    report_json: str = ""
    report_html: str = ""
    report_pdf: str = ""


@dataclass
class DriveHealthSnapshot:
    root: str = ""
    drive_letter: str = ""
    display_name: str = "Unknown Storage Device"
    volume_label: str = "Unknown"
    model: str = "Unknown"
    manufacturer: str = "Unknown"
    serial: str = "Unknown"
    firmware: str = "Unknown"
    capacity: int = 0
    free: int = 0
    used: int = 0
    filesystem: str = "Unknown"
    drive_type: str = "Unknown"
    bus_type: str = "Unknown"
    media_type: str = "Unknown"
    smart_device: str = ""
    smart_match_confidence: str = "Unknown"
    smart_match_reason: str = ""
    smart_status: str = "Unavailable"
    windows_status: str = "Unknown"
    temperature: str = "Unknown"
    wear: str = "Unknown"
    power_on_hours: str = "Unknown"
    power_cycle_count: str = "Unknown"
    reallocated: int = 0
    pending: int = 0
    uncorrectable: int = 0
    crc_errors: int = 0
    nvme_media_errors: int = 0
    health_score: int = 0
    health_status: str = "UNKNOWN"
    recommendation: str = "Health data is incomplete for this device."
    issues: list = field(default_factory=list)
    raw_smart_preview: str = ""
    smart_parsed: dict = field(default_factory=dict)
    windows_parsed: dict = field(default_factory=dict)
    last_checked: str = field(default_factory=now_stamp)


@dataclass
class ScannerSettings:
    default_scan_mode: str = "Balanced Scan"
    default_block_size_mb: str = "AUTO"
    flush_policy: str = "Balanced"
    retry_count: int = 2
    retry_delay_sec: float = 0.4
    report_formats: list = field(default_factory=lambda: ["Text", "JSON", "CSV", "HTML", "PDF"])
    auto_cleanup_old_sessions: bool = False
    theme: str = "Cyber"
    show_advanced_warnings: bool = True
    exclude_system_drive: bool = True
    enable_smart_checks: bool = True
    enable_powershell_metadata: bool = True
    delayed_verify_seconds: int = 0
    random_recheck_percent: int = 8
    auto_stop_severe_corruption: bool = False
    severe_corruption_blocks: int = 100
    surface_scan_max_mb: int = 512
    surface_scan_chunk_mb: int = 4
    surface_scan_max_seconds: int = 180


class Tooltip:
    def __init__(self, widget, text):
        self.widget = widget
        self.text = text
        self.tip = None
        widget.bind("<Enter>", self.show)
        widget.bind("<Leave>", self.hide)

    def show(self, _event=None):
        if self.tip or not self.text:
            return
        x = self.widget.winfo_rootx() + 16
        y = self.widget.winfo_rooty() + self.widget.winfo_height() + 8
        self.tip = tk.Toplevel(self.widget)
        self.tip.wm_overrideredirect(True)
        self.tip.wm_geometry(f"+{x}+{y}")
        label = tk.Label(
            self.tip,
            text=self.text,
            bg="#07101D",
            fg=CYBER_TEXT,
            relief="solid",
            borderwidth=1,
            font=("Segoe UI", 9),
            padx=8,
            pady=5,
            wraplength=330,
            justify="left",
        )
        label.pack()

    def hide(self, _event=None):
        if self.tip:
            self.tip.destroy()
            self.tip = None


class StorageHealthDiagnostics:
    def __init__(self, target, log_callback=None, status_callback=None, progress_callback=None):
        self.target = target
        self.log = log_callback or (lambda message: None)
        self.status = status_callback or (lambda message: None)
        self.progress = progress_callback or (lambda value: None)
        self.result = HealthDiagnosticResult(target=target)
        self.cancelled = False

    def cancel(self):
        self.cancelled = True

    def disk_root(self):
        try:
            return get_disk_root(self.target)
        except Exception:
            return self.target or "/"

    def add_issue(self, severity, title, detail, points):
        self.result.issues.append({"severity": severity, "title": title, "detail": detail, "points": points})
        self.result.health_risk_score = min(100, self.result.health_risk_score + points)
        self.log(f"[Health/{severity}] {title}: {detail}")

    def run_command_cancelable(self, cmd, timeout=180):
        try:
            proc = subprocess.Popen(
                cmd,
                shell=False,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                creationflags=subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0,
            )
            start = time.perf_counter()
            while proc.poll() is None:
                if self.cancelled:
                    proc.terminate()
                    try:
                        out, err = proc.communicate(timeout=4)
                    except Exception:
                        proc.kill()
                        out, err = proc.communicate()
                    return 998, out or "", (err or "") + "\nCommand cancelled by user."
                if time.perf_counter() - start > timeout:
                    proc.terminate()
                    try:
                        out, err = proc.communicate(timeout=4)
                    except Exception:
                        proc.kill()
                        out, err = proc.communicate()
                    return 997, out or "", (err or "") + "\nCommand timed out."
                time.sleep(0.2)
            out, err = proc.communicate()
            return proc.returncode, (out or "").strip(), (err or "").strip()
        except Exception as exc:
            return 999, "", str(exc)

    def run_all(self, include_chkdsk=False, include_surface=False):
        self.progress(5)
        self.run_smart_check()
        self.progress(40)
        self.run_windows_health_check()
        self.progress(70)
        if include_chkdsk:
            self.run_read_only_chkdsk()
        if include_surface:
            self.run_surface_read_stability_scan()
        self.progress(100)
        return self.finalize()

    def run_smart_check(self):
        self.status("Running SMART check...")
        self.progress(10)
        exe = smartctl_available()
        if not exe:
            self.result.smart_available = False
            self.result.smart_status = "smartctl Missing"
            self.add_issue("Info", "SMART unavailable", "smartctl was not found. Install smartmontools for SMART health analysis.", 0)
            return self.result
        self.result.smart_available = True
        code, out, err = self.run_command_cancelable([exe, "--scan-open"], timeout=12)
        if code != 0 or not out:
            self.result.smart_status = "SMART Scan Failed"
            self.add_issue("Medium", "SMART scan failed", err or out or "smartctl could not enumerate devices.", 8)
            return self.result
        target_meta, meta_warning = ({}, "")
        if os.name == "nt":
            try:
                target_meta, meta_warning = get_disk_metadata_for_drive_cached(self.disk_root())
            except Exception as exc:
                meta_warning = str(exc)
        if meta_warning:
            self.log(f"[Health/Info] SMART target metadata note: {meta_warning}")
        device_results = []
        for line in out.splitlines():
            if self.cancelled:
                break
            parts = line.split()
            if not parts:
                continue
            dev = parts[0].strip()
            code_a, out_a, err_a = self.run_command_cancelable([exe, "-a", dev], timeout=25)
            if self.cancelled:
                break
            code_h, out_h, err_h = self.run_command_cancelable([exe, "-H", dev], timeout=15)
            raw = f"===== {dev} smartctl -H =====\n{out_h or err_h}\n\n===== {dev} smartctl -a =====\n{out_a or err_a}"
            parsed = self.parse_smart_output((out_h or "") + "\n" + (out_a or ""))
            score, reason = self.score_smart_device_match(dev, parsed, raw, target_meta)
            device_results.append({"device": dev, "raw": raw, "parsed": parsed, "score": score, "reason": reason})
            self.progress(min(85, 20 + len(device_results) * 15))
        self.result.smart_devices = [item["device"] for item in device_results]
        selected = self.choose_smart_device(device_results)
        if selected:
            self.result.smart_selected_device = selected["device"]
            self.result.smart_match_reason = selected["reason"]
            self.result.smart_match_confidence = "High" if selected["score"] >= 80 else "Medium" if selected["score"] >= 35 else "Low"
            self.result.smart_raw_output = selected["raw"][:120000]
            self.merge_smart(selected["parsed"])
            if selected["score"] < 35 and len(device_results) > 1:
                self.add_issue(
                    "Info",
                    "SMART device match uncertain",
                    "smartctl returned multiple devices and the selected drive could not be matched confidently. Parsed SMART data is best-effort.",
                    0,
                )
        elif device_results:
            self.result.smart_match_confidence = "Low"
            self.result.smart_match_reason = "No confident mapping; preserving raw output from all devices."
            self.result.smart_raw_output = "\n\n".join(item["raw"] for item in device_results)[:120000]
            for item in device_results:
                self.merge_smart(item["parsed"])
        else:
            self.result.smart_status = "No SMART Devices"
            self.add_issue("Info", "No SMART devices returned", "smartctl did not return usable device entries.", 0)
            return self.result
        self.evaluate_smart_risk()
        return self.result

    def choose_smart_device(self, device_results):
        if not device_results:
            return None
        ranked = sorted(device_results, key=lambda item: item.get("score", 0), reverse=True)
        return ranked[0]

    def score_smart_device_match(self, dev, parsed, raw, target_meta):
        if not target_meta:
            return 10, "No Windows target metadata available; using first/best smartctl device."
        score = 0
        reasons = []
        raw_lower = raw.lower()
        candidates = {
            "serial": [
                target_meta.get("SerialNumber"),
                target_meta.get("PhysicalSerialNumber"),
            ],
            "model": [
                target_meta.get("Model"),
                target_meta.get("FriendlyName"),
                target_meta.get("PhysicalFriendlyName"),
            ],
            "bus": [
                target_meta.get("BusType"),
                target_meta.get("PhysicalBusType"),
            ],
        }
        for serial in candidates["serial"]:
            serial_text = clean_identity_value(serial)
            if serial_text and serial_text.lower().replace(" ", "") in raw_lower.replace(" ", ""):
                score += 70
                reasons.append(f"serial matched ({serial_text})")
                break
        for model in candidates["model"]:
            model_text = clean_identity_value(model)
            if model_text and model_text.lower() in raw_lower:
                score += 30
                reasons.append(f"model matched ({model_text})")
                break
            if model_text:
                model_tokens = [t for t in model_text.lower().replace("-", " ").split() if len(t) >= 4]
                token_hits = sum(1 for token in model_tokens if token in raw_lower)
                if token_hits >= 2:
                    score += 18
                    reasons.append(f"model tokens matched ({token_hits})")
                    break
        for bus in candidates["bus"]:
            bus_text = clean_identity_value(bus)
            if bus_text and bus_text.lower() in raw_lower:
                score += 8
                reasons.append(f"bus matched ({bus_text})")
                break
        if os.name == "nt":
            disk_number = clean_identity_value(target_meta.get("DiskNumber"))
            if disk_number and (f"physicaldrive{disk_number}" in dev.lower() or f"pd{disk_number}" in dev.lower()):
                score += 85
                reasons.append(f"physical drive number matched ({disk_number})")
        return min(100, score), "; ".join(reasons) or "No direct serial/model/bus match found."

    def parse_smart_output(self, text):
        parsed = {}
        lower = text.lower()
        if "smart overall-health self-assessment test result" in lower:
            for line in text.splitlines():
                if "overall-health" in line.lower() or "smart health status" in line.lower():
                    parsed["overall_health"] = line.split(":", 1)[-1].strip() if ":" in line else line.strip()
                    break
        if "smart health status" in lower and "overall_health" not in parsed:
            for line in text.splitlines():
                if "smart health status" in line.lower():
                    parsed["overall_health"] = line.split(":", 1)[-1].strip() if ":" in line else line.strip()
                    break
        attr_names = {
            "Reallocated_Sector_Ct": "reallocated_sector_count",
            "Reallocated_Event_Count": "reallocated_event_count",
            "Current_Pending_Sector": "current_pending_sector_count",
            "Offline_Uncorrectable": "offline_uncorrectable",
            "UDMA_CRC_Error_Count": "udma_crc_error_count",
            "Power_On_Hours": "power_on_hours",
            "Power_Cycle_Count": "power_cycle_count",
            "Temperature_Celsius": "temperature_celsius",
            "Airflow_Temperature_Cel": "temperature_celsius",
            "Percentage Used": "percentage_used",
            "Media and Data Integrity Errors": "nvme_media_data_integrity_errors",
            "Available Spare Threshold": "nvme_available_spare_threshold",
            "Available Spare": "nvme_available_spare",
            "Data Units Read": "nvme_data_units_read",
            "Data Units Written": "nvme_data_units_written",
            "Controller Busy Time": "nvme_controller_busy_time",
            "Host Read Commands": "nvme_host_read_commands",
            "Host Write Commands": "nvme_host_write_commands",
            "Unsafe Shutdowns": "unsafe_shutdowns",
            "Spin_Retry_Count": "spin_retry_count",
            "Seek_Error_Rate": "seek_error_rate",
            "Start_Stop_Count": "start_stop_count",
            "Load_Cycle_Count": "load_cycle_count",
            "Wear_Leveling_Count": "ssd_wear_leveling_count",
            "Media_Wearout_Indicator": "ssd_media_wearout_indicator",
            "Percent_Lifetime_Remain": "ssd_lifetime_remaining",
        }
        for line in text.splitlines():
            stripped = line.strip()
            lower_line = stripped.lower()
            if lower_line.startswith(("device model:", "model number:", "product:")):
                parsed.setdefault("model", stripped.split(":", 1)[-1].strip())
            elif lower_line.startswith(("serial number:", "serial number")) and ":" in stripped:
                parsed.setdefault("serial_number", stripped.split(":", 1)[-1].strip())
            elif lower_line.startswith(("firmware version:", "firmware revision:")):
                parsed.setdefault("firmware", stripped.split(":", 1)[-1].strip())
            elif lower_line.startswith(("user capacity:", "total nvm capacity:", "namespace 1 size/capacity:")):
                capacity_text = stripped.split(":", 1)[-1].split("bytes", 1)[0]
                digits = "".join(ch for ch in capacity_text if ch.isdigit())
                if digits:
                    parsed.setdefault("user_capacity_bytes", safe_int(digits, 0))
            for raw_name, key in attr_names.items():
                if raw_name.lower() in stripped.lower():
                    value = self.extract_last_number(stripped)
                    if value is not None:
                        parsed[key] = value
                    break
            if "temperature:" in stripped.lower() and "temperature_celsius" not in parsed:
                value = self.extract_first_number(stripped)
                if value is not None:
                    parsed["temperature_celsius"] = value
            if "percentage used:" in stripped.lower():
                value = self.extract_first_number(stripped)
                if value is not None:
                    parsed["percentage_used"] = value
        return parsed

    def extract_last_number(self, text):
        nums = []
        current = ""
        for ch in text:
            if ch.isdigit():
                current += ch
            elif current:
                nums.append(current)
                current = ""
        if current:
            nums.append(current)
        return int(nums[-1]) if nums else None

    def extract_first_number(self, text):
        nums = []
        current = ""
        for ch in text:
            if ch.isdigit():
                current += ch
            elif current:
                nums.append(current)
                break
        if current and not nums:
            nums.append(current)
        return int(nums[0]) if nums else None

    def merge_smart(self, parsed):
        for key, value in parsed.items():
            old = self.result.smart_parsed.get(key)
            if isinstance(value, int) and isinstance(old, int):
                self.result.smart_parsed[key] = max(old, value)
            elif key not in self.result.smart_parsed:
                self.result.smart_parsed[key] = value

    def evaluate_smart_risk(self):
        data = self.result.smart_parsed
        health = str(data.get("overall_health", "")).lower()
        if health and not any(word in health for word in ("passed", "ok", "healthy")):
            self.add_issue("High", "SMART health warning", f"SMART overall health is {data.get('overall_health')}.", 30)
        reallocated = int(data.get("reallocated_sector_count", 0) or 0)
        pending = int(data.get("current_pending_sector_count", 0) or 0)
        uncorrectable = int(data.get("offline_uncorrectable", 0) or 0)
        crc = int(data.get("udma_crc_error_count", 0) or 0)
        temp = int(data.get("temperature_celsius", 0) or 0)
        wear = int(data.get("percentage_used", 0) or 0)
        media_errors = int(data.get("nvme_media_data_integrity_errors", 0) or 0)
        if pending > 0:
            self.add_issue("High", "Current pending sectors", f"{pending} pending sector(s) were reported.", 28)
        if uncorrectable > 0:
            self.add_issue("Critical", "Offline uncorrectable sectors", f"{uncorrectable} uncorrectable sector(s) were reported.", 40)
        if reallocated >= 50:
            self.add_issue("High", "High reallocated sector count", f"{reallocated} reallocated sector(s) were reported.", 24)
        elif reallocated > 0:
            self.add_issue("Medium", "Reallocated sectors present", f"{reallocated} reallocated sector(s) were reported.", 12)
        if crc > 0:
            self.add_issue("Warning", "UDMA CRC errors", f"{crc} CRC error(s) may indicate cable, port, bridge, or signal issues.", 6)
        if temp >= 60:
            self.add_issue("High", "High temperature", f"Temperature is {temp} C.", 18)
        elif temp >= 50:
            self.add_issue("Warning", "Elevated temperature", f"Temperature is {temp} C.", 8)
        if wear >= 90:
            self.add_issue("High", "SSD wear high", f"SMART percentage used is {wear}%.", 22)
        elif wear >= 70:
            self.add_issue("Warning", "SSD wear elevated", f"SMART percentage used is {wear}%.", 10)
        if media_errors > 0:
            self.add_issue("Critical", "NVMe media/data integrity errors", f"{media_errors} media/data integrity error(s) were reported.", 35)
        self.result.temperature = f"{temp} C" if temp else self.result.temperature
        self.result.wear_age = f"{wear}% used" if wear else self.result.wear_age
        self.result.smart_status = data.get("overall_health", "SMART Parsed") if data else "SMART Output Collected"
        if self.result.smart_selected_device:
            self.result.smart_status = f"{self.result.smart_status} ({self.result.smart_match_confidence} match)"

    def run_windows_health_check(self):
        self.status("Running Windows health check...")
        self.progress(10)
        if os.name != "nt":
            self.result.windows_health_status = "Non-Windows"
            self.add_issue("Info", "Windows diagnostics unavailable", "Windows health analyzer is available only on Windows.", 0)
            return self.result
        drive_letter = self.disk_root()[0].upper() if self.disk_root() else ""
        script = rf"""
$ErrorActionPreference = 'SilentlyContinue'
$drive = '{drive_letter}'
$vol = Get-Volume -DriveLetter $drive
$part = Get-Partition -DriveLetter $drive
$disk = $part | Get-Disk
$physical = Get-PhysicalDisk | Where-Object {{ $_.DeviceId -eq $disk.Number -or $_.FriendlyName -like "*$($disk.FriendlyName)*" }} | Select-Object -First 1
$reliability = $null
try {{ $reliability = Get-StorageReliabilityCounter -PhysicalDisk $physical }} catch {{ }}
[PSCustomObject]@{{
  Volume = $vol | Select-Object DriveLetter,FileSystemLabel,FileSystemType,HealthStatus,OperationalStatus,Size,SizeRemaining
  Disk = $disk | Select-Object Number,FriendlyName,SerialNumber,HealthStatus,OperationalStatus,BusType,PartitionStyle,Size,IsBoot,IsSystem,IsReadOnly
  PhysicalDisk = $physical | Select-Object FriendlyName,SerialNumber,MediaType,BusType,HealthStatus,OperationalStatus,Size
  Reliability = $reliability | Select-Object Temperature,Wear,ReadErrorsTotal,WriteErrorsTotal,ReadErrorsCorrected,WriteErrorsCorrected,PowerOnHours,StartStopCycleCount
}} | ConvertTo-Json -Depth 6 -Compress
"""
        data, err = run_powershell(script, timeout=25)
        if err:
            self.result.windows_health_status = "PowerShell Failed"
            self.add_issue("Medium", "Windows health command failed", err, 8)
            return self.result
        self.result.windows_raw = data
        self.result.windows_parsed = self.flatten_windows_health(data)
        self.evaluate_windows_risk()
        self.progress(100)
        return self.result

    def flatten_windows_health(self, data):
        parsed = {}
        if isinstance(data, dict):
            for group, value in data.items():
                if isinstance(value, dict):
                    for k, v in value.items():
                        parsed[f"{group}.{k}"] = v
                else:
                    parsed[group] = value
        return parsed

    def evaluate_windows_risk(self):
        data = self.result.windows_parsed
        status_text = " ".join(str(v) for k, v in data.items() if "HealthStatus" in k or "OperationalStatus" in k)
        lower = status_text.lower()
        if any(word in lower for word in ("unhealthy", "warning", "degraded", "lost communication", "predictive failure")):
            self.add_issue("High", "Windows storage health warning", status_text.strip() or "Windows reported a health warning.", 28)
        temp = safe_int(data.get("Reliability.Temperature"), 0)
        wear = safe_int(data.get("Reliability.Wear"), 0)
        read_errors = safe_int(data.get("Reliability.ReadErrorsTotal"), 0)
        write_errors = safe_int(data.get("Reliability.WriteErrorsTotal"), 0)
        if temp:
            self.result.temperature = f"{temp} C"
            if temp >= 60:
                self.add_issue("High", "Windows high temperature", f"Storage reliability temperature is {temp} C.", 18)
            elif temp >= 50:
                self.add_issue("Warning", "Windows elevated temperature", f"Storage reliability temperature is {temp} C.", 8)
        if wear:
            self.result.wear_age = f"{wear}% wear"
            if wear >= 90:
                self.add_issue("High", "Windows wear high", f"Storage reliability wear is {wear}%.", 22)
            elif wear >= 70:
                self.add_issue("Warning", "Windows wear elevated", f"Storage reliability wear is {wear}%.", 10)
        if read_errors:
            self.add_issue("High", "Read errors reported by Windows", f"ReadErrorsTotal={read_errors}.", 20)
        if write_errors:
            self.add_issue("High", "Write errors reported by Windows", f"WriteErrorsTotal={write_errors}.", 20)
        self.result.windows_health_status = status_text.strip() or "Windows Health Parsed"

    def run_read_only_chkdsk(self):
        self.status("Running read-only CHKDSK...")
        self.progress(10)
        if os.name != "nt":
            self.result.chkdsk_output = "CHKDSK preview is available only on Windows."
            return self.result
        root = self.disk_root()
        cmd = ["chkdsk", root]
        self.log(f"Running safe read-only command: {' '.join(cmd)}")
        code, out, err = self.run_command_cancelable(cmd, timeout=240)
        text = (out or "") + ("\n" + err if err else "")
        self.result.chkdsk_output = text[:160000] if text else f"CHKDSK returned code {code} with no output."
        lower = self.result.chkdsk_output.lower()
        if "windows has scanned the file system and found no problems" in lower or "no further action is required" in lower:
            pass
        elif any(word in lower for word in ("bad sectors", "corrupt", "errors found", "failed", "cannot continue")):
            self.add_issue("Warning", "CHKDSK preview reported possible filesystem issues", "Read-only CHKDSK output contains warnings or error terms.", 10)
        self.progress(100)
        return self.result

    def run_surface_read_stability_scan(self, max_bytes=512 * 1024 * 1024, chunk_size=4 * 1024 * 1024, max_seconds=180):
        self.status("Running surface read stability scan...")
        self.progress(5)
        root = Path(self.target)
        if not root.exists():
            self.add_issue("High", "Surface scan target missing", "The selected target path does not exist.", 18)
            return self.result
        total = 0
        samples = []
        failures = []
        slow = []
        files_seen = 0
        inaccessible = 0
        started = time.perf_counter()
        for path in self.iter_readable_files(root):
            if self.cancelled or total >= max_bytes or (time.perf_counter() - started) >= max_seconds:
                break
            files_seen += 1
            try:
                with open(path, "rb", buffering=1024 * 1024) as fh:
                    while total < max_bytes and not self.cancelled and (time.perf_counter() - started) < max_seconds:
                        t0 = time.perf_counter()
                        data = fh.read(chunk_size)
                        elapsed = max(time.perf_counter() - t0, 0.0001)
                        if not data:
                            break
                        total += len(data)
                        mb_s = (len(data) / 1024 / 1024) / elapsed
                        sample = {"file": str(path), "offset_sample_bytes": total, "bytes": len(data), "seconds": round(elapsed, 4), "mb_s": round(mb_s, 2)}
                        samples.append(sample)
                        self.progress(min(95, (total / max(1, max_bytes)) * 100))
                        if elapsed > 3.0 or mb_s < 2.0:
                            slow.append(sample)
            except Exception as exc:
                inaccessible += 1
                failures.append({"file": str(path), "error": f"{type(exc).__name__}: {exc}"})
                if len(failures) >= 20:
                    break
        elapsed_total = max(time.perf_counter() - started, 0.0001)
        avg = (total / 1024 / 1024) / elapsed_total if total else 0
        status = "Stable"
        if failures:
            status = "Read Error"
            self.add_issue("High", "Read errors during surface scan", f"{len(failures)} file read error(s) occurred.", 24)
        elif len(slow) >= 3:
            status = "Slow / Weak Region"
            self.add_issue("Warning", "Read stability slow regions", f"{len(slow)} slow read sample(s) were detected.", 12)
        elif not samples:
            status = "No readable sample"
            self.add_issue(
                "Info",
                "No readable files sampled",
                "The read stability scan is intentionally read-only and found no existing files to sample. Empty free space is not read through raw disk access.",
                0,
            )
        self.result.read_stability_status = status
        self.result.surface_results = {
            "status": status,
            "sampled_bytes": total,
            "sampled_human": human_bytes(total),
            "average_mb_s": round(avg, 2),
            "files_seen": files_seen,
            "inaccessible_files": inaccessible,
            "slow_samples": slow[:50],
            "read_failures": failures[:50],
            "samples_preview": samples[:100],
            "read_only_scope": "Existing readable files only; raw disk regions and unused free space are not read.",
            "max_seconds": max_seconds,
            "cancelled": self.cancelled,
            "recommendation": "Needs Backup / Replacement Recommended" if status == "Read Error" else status,
        }
        self.progress(100)
        return self.result

    def iter_readable_files(self, root):
        if root.is_file():
            yield root
            return
        skip_parts = {TEST_DIR_NAME.lower(), "$recycle.bin", "system volume information"}
        for current, dirs, files in os.walk(root):
            dirs[:] = [d for d in dirs if d.lower() not in skip_parts]
            for name in files:
                path = Path(current) / name
                try:
                    if path.stat().st_size > 0:
                        yield path
                except Exception:
                    continue

    def finalize(self):
        self.result.completed_at = now_stamp()
        self.result.health_risk_score = min(100, max(0, self.result.health_risk_score))
        if self.cancelled:
            self.result.health_status = "Diagnostic Cancelled"
            self.result.recommendation = "Diagnostic was cancelled before completion"
            return self.result
        score = self.result.health_risk_score
        if score >= 75:
            self.result.health_status = "Critical Health Risk"
            self.result.recommendation = "Do not rely on this device for important data"
        elif score >= 50:
            self.result.health_status = "High Health Risk"
            self.result.recommendation = "Replacement recommended"
        elif score >= 25:
            self.result.health_status = "Monitor"
            self.result.recommendation = "Backup recommended"
        elif score > 0:
            self.result.health_status = "Minor Warnings"
            self.result.recommendation = "Monitor this device"
        else:
            self.result.health_status = "No Major Health Issues Detected"
            self.result.recommendation = "No major health issues detected"
        return self.result

    def to_dict(self):
        return asdict(self.result)


def smart_status_is_good(status):
    text = str(status or "").lower()
    return bool(text) and any(word in text for word in ("passed", "ok", "healthy", "normal", "good"))


def health_status_color(status):
    text = str(status or "").upper()
    if "CRITICAL" in text:
        return CYBER_RED
    if "WARNING" in text:
        return CYBER_ORANGE
    if "HEALTHY" in text or "GOOD" in text:
        return CYBER_GREEN
    return CYBER_CYAN


def _device_context_text(*values):
    return " ".join(clean_identity_value(value) for value in values if clean_identity_value(value)).upper()


def is_nvme_drive(bus_type="", media_type="", model="", raw=""):
    return "NVME" in _device_context_text(bus_type, media_type, model, raw)


def is_hdd_drive(bus_type="", media_type="", model="", raw="", drive_type=""):
    text = _device_context_text(bus_type, media_type, model, raw, drive_type)
    return any(token in text for token in ("HDD", "HARD DISK", "HARD DRIVE", "ROTATIONAL", "SPIN"))


def is_ssd_drive(bus_type="", media_type="", model="", raw=""):
    text = _device_context_text(bus_type, media_type, model, raw)
    return "NVME" in text or "SSD" in text or "SOLID" in text


def is_usb_bridge_device(bus_type="", media_type="", model="", raw="", drive_type="", smart_status=""):
    text = _device_context_text(bus_type, media_type, model, raw, drive_type, smart_status)
    return "USB" in text or "REMOVABLE" in text or "BRIDGE" in text


def supports_wear_metrics(bus_type="", media_type="", model="", raw=""):
    return is_ssd_drive(bus_type, media_type, model, raw)


def supports_temperature_metrics(bus_type="", media_type="", model="", raw="", drive_type="", smart_status=""):
    if is_usb_bridge_device(bus_type, media_type, model, raw, drive_type, smart_status) and "UNAVAILABLE" in str(smart_status or "").upper():
        return False
    return True


def effective_wear_value(smart_parsed=None, windows_parsed=None):
    smart_parsed = smart_parsed or {}
    windows_parsed = windows_parsed or {}
    for key in ("percentage_used", "ssd_wear_leveling_count"):
        value = safe_int(smart_parsed.get(key), 0)
        if value:
            return value, "% used" if key == "percentage_used" else "wear level"
    value = safe_int(windows_parsed.get("Reliability.Wear"), 0)
    if value:
        return value, "% wear"
    remaining = safe_int(smart_parsed.get("ssd_lifetime_remaining"), 0)
    if remaining:
        return remaining, "life remaining"
    media_wearout = safe_int(smart_parsed.get("ssd_media_wearout_indicator"), 0)
    if media_wearout:
        return media_wearout, "life remaining"
    return 0, ""


def format_wear_metric(smart_parsed=None, windows_parsed=None, bus_type="", media_type="", model="", raw="", drive_type="", smart_status=""):
    smart_parsed = smart_parsed or {}
    windows_parsed = windows_parsed or {}
    value, kind = effective_wear_value(smart_parsed, windows_parsed)
    if value:
        if kind == "life remaining":
            return f"Life Remaining: {value}%"
        if kind == "wear level":
            return f"Wear Level: {value}"
        return f"{value}{kind}"
    if is_hdd_drive(bus_type, media_type, model, raw, drive_type):
        return "N/A (Mechanical HDD)"
    if is_usb_bridge_device(bus_type, media_type, model, raw, drive_type, smart_status) and not supports_wear_metrics(bus_type, media_type, model, raw):
        return "Not Exposed"
    if supports_wear_metrics(bus_type, media_type, model, raw):
        return "Not Reported"
    return "Unsupported"


def format_temperature_metric(smart_parsed=None, windows_parsed=None, bus_type="", media_type="", model="", raw="", drive_type="", smart_status=""):
    smart_parsed = smart_parsed or {}
    windows_parsed = windows_parsed or {}
    temp = safe_int(smart_parsed.get("temperature_celsius") or windows_parsed.get("Reliability.Temperature"), 0)
    if temp:
        return f"{temp} C"
    if is_usb_bridge_device(bus_type, media_type, model, raw, drive_type, smart_status):
        return "USB Bridge Hidden"
    if supports_temperature_metrics(bus_type, media_type, model, raw, drive_type, smart_status):
        return "Not Exposed"
    return "Unavailable"


def normalize_health_recommendation(base, health_status, smart_status, bus_type="", media_type="", model="", raw="", drive_type="", issues=None):
    if str(health_status or "").upper() in ("CRITICAL", "WARNING") or issues:
        if any(i.get("points", 0) > 0 for i in (issues or [])):
            return base
    if is_hdd_drive(bus_type, media_type, model, raw, drive_type):
        return "Mechanical HDD operating normally" if smart_status_is_good(smart_status) or base == "No major health issues detected" else base
    if is_ssd_drive(bus_type, media_type, model, raw):
        return "SSD wear remains within normal range" if base == "No major health issues detected" else base
    if is_usb_bridge_device(bus_type, media_type, model, raw, drive_type, smart_status) and "unavailable" in str(smart_status or "").lower():
        return "SMART data partially unavailable"
    return base


def collect_smartctl_device_results(log_callback=None, timeout_per_device=28):
    log = log_callback or (lambda _message: None)
    exe = smartctl_available()
    if not exe:
        return [], "smartctl not found. Install smartmontools for SMART health analysis."
    code, out, err = run_command([exe, "--scan-open"], timeout=14)
    if code != 0 or not out:
        return [], err or out or "smartctl could not enumerate storage devices."
    parser = StorageHealthDiagnostics("")
    devices = []
    for line in out.splitlines():
        parts = line.split()
        if not parts:
            continue
        dev = parts[0].strip()
        if not dev:
            continue
        code_h, out_h, err_h = run_command([exe, "-H", dev], timeout=18)
        code_a, out_a, err_a = run_command([exe, "-a", dev], timeout=timeout_per_device)
        raw = f"===== {dev} smartctl -H =====\n{out_h or err_h}\n\n===== {dev} smartctl -a =====\n{out_a or err_a}"
        parsed = parser.parse_smart_output((out_h or "") + "\n" + (out_a or ""))
        devices.append(
            {
                "device": dev,
                "scan_line": line,
                "raw": raw,
                "parsed": parsed,
                "returncode_health": code_h,
                "returncode_all": code_a,
            }
        )
        log(f"SMART dashboard collected read-only data for {dev}.")
    return devices, ""


def collect_windows_health_for_root(root):
    if os.name != "nt":
        return {}, "Windows health metadata is unavailable on this platform."
    drive_letter = (root or "")[0].upper()
    if not drive_letter:
        return {}, "No drive letter available for Windows health metadata."
    script = rf"""
$ErrorActionPreference = 'SilentlyContinue'
$drive = '{drive_letter}'
$vol = Get-Volume -DriveLetter $drive
$part = Get-Partition -DriveLetter $drive
$disk = $part | Get-Disk
$physical = Get-PhysicalDisk | Where-Object {{ $_.DeviceId -eq $disk.Number -or $_.FriendlyName -like "*$($disk.FriendlyName)*" }} | Select-Object -First 1
$reliability = $null
try {{ $reliability = Get-StorageReliabilityCounter -PhysicalDisk $physical }} catch {{ }}
[PSCustomObject]@{{
  Volume = $vol | Select-Object DriveLetter,FileSystemLabel,FileSystemType,HealthStatus,OperationalStatus,Size,SizeRemaining
  Disk = $disk | Select-Object Number,FriendlyName,SerialNumber,Manufacturer,Model,FirmwareVersion,HealthStatus,OperationalStatus,BusType,PartitionStyle,Size,IsBoot,IsSystem,IsReadOnly
  PhysicalDisk = $physical | Select-Object DeviceId,FriendlyName,SerialNumber,FirmwareVersion,MediaType,BusType,HealthStatus,OperationalStatus,Size
  Reliability = $reliability | Select-Object Temperature,Wear,ReadErrorsTotal,WriteErrorsTotal,ReadErrorsCorrected,WriteErrorsCorrected,PowerOnHours,StartStopCycleCount
}} | ConvertTo-Json -Depth 6 -Compress
"""
    data, err = run_powershell(script, timeout=24)
    if err:
        return {}, err
    return StorageHealthDiagnostics(root).flatten_windows_health(data), ""


def drive_health_risk_from_values(smart_parsed=None, windows_parsed=None, smart_status="", windows_status=""):
    smart_parsed = smart_parsed or {}
    windows_parsed = windows_parsed or {}
    risk = 0
    issues = []

    def add(severity, title, detail, points):
        nonlocal risk
        issues.append({"severity": severity, "title": title, "detail": detail, "points": points})
        risk = min(100, risk + points)

    health_text = str(smart_status or smart_parsed.get("overall_health", "")).lower()
    if health_text and not smart_status_is_good(health_text) and "unavailable" not in health_text and "missing" not in health_text:
        add("Critical", "SMART overall health warning", f"SMART reports: {smart_status or smart_parsed.get('overall_health')}", 45)
    pending = safe_int(smart_parsed.get("current_pending_sector_count"), 0)
    uncorrectable = safe_int(smart_parsed.get("offline_uncorrectable"), 0)
    reallocated = safe_int(smart_parsed.get("reallocated_sector_count"), 0)
    crc = safe_int(smart_parsed.get("udma_crc_error_count"), 0)
    temp = safe_int(smart_parsed.get("temperature_celsius") or windows_parsed.get("Reliability.Temperature"), 0)
    wear, wear_kind = effective_wear_value(smart_parsed, windows_parsed)
    nvme_errors = safe_int(smart_parsed.get("nvme_media_data_integrity_errors"), 0)
    read_errors = safe_int(windows_parsed.get("Reliability.ReadErrorsTotal"), 0)
    write_errors = safe_int(windows_parsed.get("Reliability.WriteErrorsTotal"), 0)
    windows_text = " ".join(
        str(value)
        for key, value in windows_parsed.items()
        if "HealthStatus" in key or "OperationalStatus" in key
    ) or str(windows_status or "")
    lower_windows = windows_text.lower()

    if pending > 0:
        add("High", "Current pending sectors", f"{pending} pending sector(s) reported.", 28)
    if uncorrectable > 0:
        add("Critical", "Offline uncorrectable sectors", f"{uncorrectable} uncorrectable sector(s) reported.", 40)
    if reallocated >= 50:
        add("High", "High reallocated sector count", f"{reallocated} reallocated sector(s) reported.", 24)
    elif reallocated > 0:
        add("Warning", "Reallocated sectors present", f"{reallocated} reallocated sector(s) reported.", 12)
    if crc > 0:
        add("Warning", "CRC errors reported", f"{crc} CRC error(s) may indicate cable, bridge, or signal issues.", 6)
    if temp >= 60:
        add("High", "High temperature", f"Temperature is {temp} C.", 18)
    elif temp >= 50:
        add("Warning", "Elevated temperature", f"Temperature is {temp} C.", 8)
    if wear_kind in ("% used", "% wear"):
        if wear >= 90:
            add("High", "SSD wear high", f"SSD wear metric is {wear} ({wear_kind}).", 22)
        elif wear >= 70:
            add("Warning", "SSD wear elevated", f"SSD wear metric is {wear} ({wear_kind}).", 10)
    elif wear_kind == "life remaining":
        if wear <= 10:
            add("High", "SSD life remaining low", f"SSD life remaining is {wear}%.", 22)
        elif wear <= 30:
            add("Warning", "SSD life remaining reduced", f"SSD life remaining is {wear}%.", 10)
    if nvme_errors > 0:
        add("Critical", "NVMe media/data integrity errors", f"{nvme_errors} media/data integrity error(s) reported.", 35)
    if read_errors:
        add("High", "Windows read errors", f"ReadErrorsTotal={read_errors}.", 20)
    if write_errors:
        add("High", "Windows write errors", f"WriteErrorsTotal={write_errors}.", 20)
    if any(word in lower_windows for word in ("unhealthy", "warning", "degraded", "lost communication", "predictive failure", "failed")):
        add("High", "Windows storage health warning", windows_text.strip() or "Windows reported a health warning.", 28)

    health_score = max(0, 100 - risk)
    has_health_data = bool(smart_parsed or windows_parsed or smart_status or windows_status)
    if not has_health_data:
        status = "UNKNOWN"
        recommendation = "Health data is incomplete for this device."
    elif risk >= 75:
        status = "CRITICAL"
        recommendation = "Do not rely on this device for important data"
    elif risk >= 50:
        status = "CRITICAL"
        recommendation = "Replacement recommended"
    elif risk >= 25:
        status = "WARNING"
        recommendation = "Backup recommended"
    elif risk > 0:
        status = "WARNING"
        recommendation = "Monitor this device"
    else:
        status = "GOOD"
        recommendation = "No major health issues detected"
    return health_score, status, recommendation, issues


def build_drive_health_snapshot(root, smart_results=None, smart_warning=""):
    smart_results = smart_results or []
    volume_info = {}
    metadata = {}
    usage = None
    drive_type = "Unknown"
    windows_parsed = {}
    warnings = []
    try:
        drive_type = get_drive_type(root)
    except Exception as exc:
        warnings.append(str(exc))
    try:
        volume_info = get_volume_info(root)
    except Exception as exc:
        warnings.append(str(exc))
    try:
        usage = shutil.disk_usage(root)
    except Exception as exc:
        warnings.append(str(exc))
    try:
        metadata, meta_warning = get_disk_metadata_for_drive_cached(root)
        if meta_warning:
            warnings.append(meta_warning)
    except Exception as exc:
        metadata = {}
        warnings.append(str(exc))
    try:
        windows_parsed, windows_warning = collect_windows_health_for_root(root)
        if windows_warning:
            warnings.append(windows_warning)
    except Exception as exc:
        windows_parsed = {}
        warnings.append(str(exc))

    parser = StorageHealthDiagnostics(root)
    ranked = []
    for item in smart_results:
        parsed = item.get("parsed", {})
        raw = item.get("raw", "")
        score, reason = parser.score_smart_device_match(item.get("device", ""), parsed, raw, metadata)
        smart_capacity = safe_int(parsed.get("user_capacity_bytes"), 0)
        actual_capacity = getattr(usage, "total", 0) if usage else 0
        if smart_capacity and actual_capacity:
            diff_ratio = abs(smart_capacity - actual_capacity) / max(smart_capacity, actual_capacity)
            if diff_ratio <= 0.05:
                score = min(100, score + 10)
                reason = f"{reason}; capacity similar" if reason else "capacity similar"
        ranked.append((score, reason, item))
    ranked.sort(key=lambda row: row[0], reverse=True)
    best_score, best_reason, best = ranked[0] if ranked else (0, "", None)
    smart_parsed = dict(best.get("parsed", {})) if best else {}
    smart_raw = best.get("raw", "") if best else ""
    smart_device = best.get("device", "") if best else ""
    confidence = "High" if best_score >= 80 else "Medium" if best_score >= 35 else "Low" if best else "Unavailable"
    smart_status = smart_parsed.get("overall_health", "")
    if not smart_status:
        if smart_warning:
            smart_status = "Unavailable"
            warnings.append(smart_warning)
        elif smart_results:
            smart_status = "SMART output collected"
        else:
            smart_status = "Unavailable"
    if best and best_score < 35:
        warnings.append("SMART Match: Low confidence. Windows health data is still shown.")

    manufacturer = clean_identity_value(metadata.get("Manufacturer")) or "Unknown"
    model = (
        clean_identity_value(metadata.get("PhysicalFriendlyName"))
        or clean_identity_value(metadata.get("FriendlyName"))
        or clean_identity_value(metadata.get("Model"))
        or clean_identity_value(smart_parsed.get("model"))
        or "Unknown"
    )
    serial = (
        clean_identity_value(metadata.get("PhysicalSerialNumber"))
        or clean_identity_value(metadata.get("SerialNumber"))
        or clean_identity_value(smart_parsed.get("serial_number"))
        or "Unknown"
    )
    firmware = (
        clean_identity_value(metadata.get("FirmwareVersion"))
        or clean_identity_value(metadata.get("PhysicalFirmwareVersion"))
        or clean_identity_value(smart_parsed.get("firmware"))
        or clean_identity_value(windows_parsed.get("Disk.FirmwareVersion"))
        or clean_identity_value(windows_parsed.get("PhysicalDisk.FirmwareVersion"))
        or "Unknown"
    )
    bus_type = (
        clean_identity_value(metadata.get("BusType"))
        or clean_identity_value(metadata.get("PhysicalBusType"))
        or clean_identity_value(windows_parsed.get("Disk.BusType"))
        or clean_identity_value(windows_parsed.get("PhysicalDisk.BusType"))
        or "Unknown"
    )
    media_type = (
        clean_identity_value(metadata.get("PhysicalMediaType"))
        or clean_identity_value(windows_parsed.get("PhysicalDisk.MediaType"))
        or classify_drive_badge(drive_type, metadata)
        or "Unknown"
    )
    windows_status = (
        clean_identity_value(metadata.get("HealthStatus"))
        or clean_identity_value(metadata.get("PhysicalHealthStatus"))
        or clean_identity_value(windows_parsed.get("Disk.HealthStatus"))
        or clean_identity_value(windows_parsed.get("PhysicalDisk.HealthStatus"))
        or "Unknown"
    )
    display_name = build_drive_display_name(root, metadata, volume_info, usage, drive_type)
    health_score, health_status, recommendation, issues = drive_health_risk_from_values(
        smart_parsed=smart_parsed,
        windows_parsed=windows_parsed,
        smart_status=smart_status,
        windows_status=windows_status,
    )
    for warning in warnings:
        if warning:
            issues.append({"severity": "Info", "title": "Collection note", "detail": str(warning), "points": 0})
    temperature_text = format_temperature_metric(smart_parsed, windows_parsed, bus_type, media_type, model, smart_raw, drive_type, smart_status)
    wear_text = format_wear_metric(smart_parsed, windows_parsed, bus_type, media_type, model, smart_raw, drive_type, smart_status)
    recommendation = normalize_health_recommendation(
        recommendation,
        health_status,
        smart_status,
        bus_type=bus_type,
        media_type=media_type,
        model=model,
        raw=smart_raw,
        drive_type=drive_type,
        issues=issues,
    )

    return DriveHealthSnapshot(
        root=root,
        drive_letter=root[:2].upper() if os.name == "nt" and root else root,
        display_name=display_name,
        volume_label=volume_info.get("volume_name", "Unknown") or "Unknown",
        model=model,
        manufacturer=manufacturer,
        serial=serial,
        firmware=firmware,
        capacity=getattr(usage, "total", 0) if usage else 0,
        free=getattr(usage, "free", 0) if usage else 0,
        used=getattr(usage, "used", 0) if usage else 0,
        filesystem=volume_info.get("filesystem", "Unknown") or "Unknown",
        drive_type=drive_type,
        bus_type=bus_type,
        media_type=media_type,
        smart_device=smart_device,
        smart_match_confidence=confidence,
        smart_match_reason=best_reason or ("No smartctl match available." if not best else "No direct match details."),
        smart_status=smart_status,
        windows_status=windows_status,
        temperature=temperature_text,
        wear=wear_text,
        power_on_hours=str(safe_int(smart_parsed.get("power_on_hours") or windows_parsed.get("Reliability.PowerOnHours"), 0) or "Not Reported"),
        power_cycle_count=str(safe_int(smart_parsed.get("power_cycle_count") or windows_parsed.get("Reliability.StartStopCycleCount"), 0) or "Not Reported"),
        reallocated=safe_int(smart_parsed.get("reallocated_sector_count"), 0),
        pending=safe_int(smart_parsed.get("current_pending_sector_count"), 0),
        uncorrectable=safe_int(smart_parsed.get("offline_uncorrectable"), 0),
        crc_errors=safe_int(smart_parsed.get("udma_crc_error_count"), 0),
        nvme_media_errors=safe_int(smart_parsed.get("nvme_media_data_integrity_errors"), 0),
        health_score=health_score,
        health_status=health_status,
        recommendation=recommendation,
        issues=issues,
        raw_smart_preview=smart_raw[:16000] if smart_raw else ("SMART unavailable through USB bridge or smartctl not installed." if smart_warning else ""),
        smart_parsed=smart_parsed,
        windows_parsed=windows_parsed,
        last_checked=now_stamp(),
    )


def collect_all_drive_health_snapshots(log_callback=None, roots=None):
    log = log_callback or (lambda _message: None)
    roots = roots or get_windows_drives() or (["/"] if os.name != "nt" else [])
    smart_results, smart_warning = collect_smartctl_device_results(log_callback=log)
    snapshots = []
    for root in roots:
        try:
            snapshots.append(build_drive_health_snapshot(root, smart_results, smart_warning))
        except Exception as exc:
            logging.exception("Failed to build drive health snapshot for %s", root)
            snapshots.append(
                DriveHealthSnapshot(
                    root=root,
                    drive_letter=root[:2].upper() if os.name == "nt" and root else root,
                    display_name=f"({root[:2].upper()}) Unknown Storage Device" if os.name == "nt" and root else "Unknown Storage Device",
                    health_status="UNKNOWN",
                    health_score=0,
                    recommendation="Health data could not be collected for this device.",
                    issues=[{"severity": "Info", "title": "Collection failed", "detail": f"{type(exc).__name__}: {exc}", "points": 0}],
                    last_checked=now_stamp(),
                )
            )
    return snapshots


class StorageScanner:
    def __init__(
        self,
        root,
        advertised_gb,
        test_size_mb,
        block_size_mb,
        scan_mode,
        flush_policy,
        settings: ScannerSettings,
        log_callback,
        progress_callback,
        metric_callback,
        resume_session=None,
        recheck_all=False,
    ):
        self.root = root
        self.advertised_gb = advertised_gb
        self.test_size_mb = test_size_mb
        self.block_size_mb = block_size_mb
        self.scan_mode = scan_mode
        self.flush_policy = flush_policy
        self.settings = settings
        self.log = log_callback
        self.progress = progress_callback
        self.metric = metric_callback
        self.resume_session = resume_session
        self.recheck_all = recheck_all
        self.cancelled = False
        self.paused = False
        self.emergency_stop = False
        self.stop_reason = ""
        self.session = {}
        self.blocks = []
        self.test_file = None
        self.logger = logging.getLogger(APP_NAME)

    def cancel(self):
        self.cancelled = True
        self.stop_reason = self.stop_reason or "manual cancellation"

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False

    def emergency(self):
        self.emergency_stop = True
        self.cancelled = True
        self.stop_reason = "emergency stop"

    def wait_if_paused(self):
        while self.paused and not self.cancelled and not self.emergency_stop:
            self.metric({"phase": "Paused"})
            time.sleep(0.2)

    def add_issue(self, result: ScanResult, severity, title, detail, points):
        issue = ScanIssue(severity, title, detail, points)
        result.issues.append(issue)
        result.risk_score += points
        self.log(f"[{severity}] {title}: {detail}")
        if severity in ("Critical", "High"):
            result.fake_capacity_indicators.append(title)

    def has_issue(self, result: ScanResult, title: str) -> bool:
        return any(getattr(issue, "title", "") == title for issue in result.issues)

    def refresh_result_counts(self, result: ScanResult):
        written = [b for b in self.blocks if b.write_status == "written"]
        ok = [b for b in self.blocks if b.verification_result == "ok"]
        corrupt = [b for b in self.blocks if b.verification_result == "corrupt"]
        read_failed = [b for b in self.blocks if b.verification_result == "read_failed"]
        write_failed = [b for b in self.blocks if b.write_status == "failed"]
        failed = corrupt + read_failed + write_failed
        processed = [b for b in self.blocks if b.verification_result in ("ok", "corrupt", "read_failed") or b.write_status == "failed"]

        result.blocks_tested = len(written)
        result.verified_blocks = len(ok)
        result.corrupted_blocks = len(corrupt)
        result.failed_blocks = len(failed)
        result.write_failures = len(write_failed)
        result.read_failures = len(read_failed)
        result.processed_blocks = len(processed)
        result.verified_bytes = sum(b.size for b in ok)
        result.corrupted_bytes = sum(b.size for b in corrupt)
        result.failed_bytes = sum(b.size for b in failed)
        result.processed_bytes = sum(b.size for b in processed)
        result.coverage_percent = (result.processed_bytes / max(1, result.capacity_reported_bytes)) * 100 if result.capacity_reported_bytes else 0.0
        result.corruption_percent = (result.corrupted_bytes / max(1, result.processed_bytes)) * 100 if result.processed_bytes else 0.0

        first_failure = min(failed, key=lambda b: b.index, default=None)
        first_corrupt = min(corrupt, key=lambda b: b.index, default=None)
        last_ok = max(ok, key=lambda b: b.index, default=None)
        result.first_corruption_block = first_corrupt.index + 1 if first_corrupt else 0
        result.corruption_start_offset = first_corrupt.offset if first_corrupt else 0
        result.estimated_valid_capacity_bytes = first_corrupt.offset if first_corrupt else result.verified_bytes
        result.first_failure_timestamp = first_failure.timestamp if first_failure else ""
        result.last_successful_block = last_ok.index + 1 if last_ok else 0

        current_run = 0
        max_run = 0
        for block in sorted(self.blocks, key=lambda b: b.index):
            if block.verification_result == "corrupt":
                current_run += 1
                max_run = max(max_run, current_run)
            elif block.verification_result in ("ok", "read_failed") or block.write_status == "failed":
                current_run = 0
        result.consecutive_corruption_count = current_run
        result.max_consecutive_corruption_count = max_run

    def emit_telemetry(self, result: ScanResult, phase: str, block: BlockRecord = None, extra=None):
        self.refresh_result_counts(result)
        if block:
            result.current_block_index = block.index + 1
        result.current_phase = phase
        metrics = {
            "phase": phase,
            "block": result.current_block_index,
            "total_blocks": result.total_blocks,
            "verified_blocks": result.verified_blocks,
            "failed_blocks": result.failed_blocks,
            "corrupted_blocks": result.corrupted_blocks,
            "read_failures": result.read_failures,
            "write_failures": result.write_failures,
            "risk_score": min(100, max(0, result.risk_score)),
            "coverage_percent": result.coverage_percent,
            "test_coverage_percent": (result.test_size_bytes / max(1, result.capacity_reported_bytes)) * 100 if result.capacity_reported_bytes else 0.0,
            "verified_bytes": result.verified_bytes,
            "corrupted_bytes": result.corrupted_bytes,
            "failed_bytes": result.failed_bytes,
            "processed_bytes": result.processed_bytes,
            "test_size_bytes": result.test_size_bytes,
            "corruption_percent": result.corruption_percent,
            "first_corruption_block": result.first_corruption_block,
            "consecutive_corruption_count": result.consecutive_corruption_count,
            "estimated_valid_capacity_bytes": result.estimated_valid_capacity_bytes,
        }
        if block:
            metrics["current_offset"] = block.offset
            metrics["block_size"] = block.size
        if extra:
            metrics.update(extra)
        self.metric(metrics)

    def mark_interrupted(self, result: ScanResult, reason: str):
        result.scan_interrupted = True
        result.interruption_reason = reason
        result.finalization_reason = reason
        self.stop_reason = self.stop_reason or reason

    def run(self) -> ScanResult:
        result = ScanResult(root=self.root, scan_mode=self.scan_mode, flush_policy=self.flush_policy)
        try:
            self.progress(2)
            self.log(f"Initializing {self.scan_mode} for {self.root}")
            root_path = Path(self.root)
            if not root_path.exists():
                self.add_issue(result, "Critical", "Path not found", "Selected drive or folder does not exist.", 45)
                return self.finalize(result)

            disk_root = get_disk_root(self.root)
            usage = shutil.disk_usage(disk_root)
            result.capacity_reported_bytes = usage.total
            result.free_bytes = usage.free
            result.used_bytes = usage.used
            result.drive_type = get_drive_type(disk_root)
            result.volume_info = get_volume_info(disk_root)
            self.progress(8)

            self.log(f"Windows reported capacity: {human_bytes(usage.total)}")
            self.log(f"Free space available: {human_bytes(usage.free)}")
            self.log(f"Drive type: {result.drive_type}")

            if self.advertised_gb > 0:
                result.advertised_bytes = gb_to_bytes(self.advertised_gb)
                self.evaluate_advertised_capacity(result)

            if self.settings.enable_powershell_metadata:
                self.log("Collecting filesystem and physical disk metadata...")
                meta, warning = get_disk_metadata_for_drive_cached(disk_root)
                result.disk_metadata = meta
                result.metadata_warning = warning or ""
                if warning:
                    self.log(f"[Info] Metadata warning: {warning}")
            else:
                result.metadata_warning = "PowerShell metadata checks disabled in settings."
            self.evaluate_metadata(result)
            self.progress(16)

            if self.settings.enable_smart_checks:
                self.log("Checking optional SMART/health information...")
                smart_data, smart_warn = collect_smartctl_summary()
                result.smart_summary = smart_data
                result.smart_warning = smart_warn or ""
                if smart_warn:
                    self.log(f"[Info] {smart_warn}")
            else:
                result.smart_warning = "SMART checks disabled in settings."
            self.evaluate_health(result)
            self.progress(23)

            if self.scan_mode == "Quick Health":
                result.test_size_bytes = 0
                result.block_size_bytes = 0
                self.log("Quick Health mode completed metadata and health checks without test writes.")
                return self.finalize(result)

            self.prepare_session(result, root_path, disk_root, usage)
            if not self.validate_session_identity(result, disk_root, usage):
                return self.finalize(result)

            self.perform_integrity_test(result)
            self.progress(92)
            self.evaluate_speed(result)
            self.evaluate_capacity_risk(result)
            self.evaluate_block_findings(result)
            self.progress(96)

        except Exception as exc:
            self.add_issue(result, "Critical", "Scanner exception", f"{type(exc).__name__}: {exc}", 40)
            result.finalization_reason = "scanner exception"
            self.log(traceback.format_exc())
            self.logger.exception("Scanner exception")
        finally:
            if self.cancelled and not result.scan_interrupted:
                self.mark_interrupted(result, self.stop_reason or "manual cancellation")
            if self.blocks:
                self.refresh_result_counts(result)
        final_result = self.finalize(result)
        self.finish_session(final_result)
        return final_result

    def evaluate_advertised_capacity(self, result):
        diff = result.advertised_bytes - result.capacity_reported_bytes
        diff_pct = (abs(diff) / result.advertised_bytes) * 100 if result.advertised_bytes else 0
        self.log(f"Advertised capacity entered: {self.advertised_gb:.2f} GB")
        if diff > result.advertised_bytes * 0.08:
            self.add_issue(
                result,
                "High",
                "Advertised capacity mismatch",
                f"Advertised capacity is higher than Windows reported capacity by {diff_pct:.1f}%.",
                28,
            )
        elif diff_pct > 3:
            self.add_issue(
                result,
                "Medium",
                "Capacity difference noticed",
                f"Advertised capacity differs from reported capacity by {diff_pct:.1f}%. Some GB/GiB difference is normal.",
                10,
            )

    def prepare_session(self, result, root_path: Path, disk_root: str, usage):
        test_dir = root_path / TEST_DIR_NAME
        test_dir.mkdir(parents=True, exist_ok=True)

        if self.resume_session:
            self.session = self.load_checkpoint(Path(self.resume_session))
            session_dir = Path(self.session.get("session_dir", self.resume_session))
            self.blocks = [BlockRecord(**b) for b in self.session.get("blocks", [])]
            self.test_file = Path(self.session.get("test_file", session_dir / "storage_probe.bin"))
            result.session_id = self.session.get("session_id", session_dir.name.replace(SESSION_PREFIX, ""))
            result.session_dir = str(session_dir)
            self.log(f"Loaded resume session: {result.session_id}")
        else:
            session_id = f"{file_stamp()}_{random.randint(1000, 9999)}"
            session_dir = test_dir / f"{SESSION_PREFIX}{session_id}"
            session_dir.mkdir(parents=True, exist_ok=True)
            self.test_file = session_dir / "storage_probe.bin"
            result.session_id = session_id
            result.session_dir = str(session_dir)
            self.session = {
                "app": APP_NAME,
                "version": APP_VERSION,
                "session_id": session_id,
                "session_dir": str(session_dir),
                "test_file": str(self.test_file),
                "created_at": now_stamp(),
                "updated_at": now_stamp(),
                "status": "active",
                "target_root": self.root,
                "disk_root": disk_root,
                "volume_serial": result.volume_info.get("serial"),
                "filesystem": result.volume_info.get("filesystem"),
                "capacity_reported_bytes": usage.total,
                "drive_type": result.drive_type,
                "scan_mode": self.scan_mode,
                "flush_policy": self.flush_policy,
                "blocks": [],
            }

        available_for_test = max(0, usage.free - (512 * 1024 * 1024))
        if self.resume_session and self.session.get("test_size_bytes"):
            test_bytes = int(self.session.get("test_size_bytes"))
            block_bytes = int(self.session.get("block_size_bytes"))
        else:
            test_bytes, block_bytes = self.auto_scale_parameters(usage.total, usage.free)
            if self.test_size_mb > 0:
                test_bytes = min(mb_to_bytes(self.test_size_mb), available_for_test)
            if self.block_size_mb > 0:
                block_bytes = mb_to_bytes(self.block_size_mb)
            test_bytes = min(test_bytes, available_for_test)

        if test_bytes < 16 * 1024 * 1024:
            self.add_issue(
                result,
                "High",
                "Insufficient free space for verification",
                "Less than 16 MB available for safe write/read testing after preserving a free-space buffer.",
                24,
            )
            return

        result.test_size_bytes = int(test_bytes)
        result.block_size_bytes = int(max(1024 * 1024, block_bytes))
        result.total_blocks = max(1, math.ceil(result.test_size_bytes / result.block_size_bytes))
        self.session["test_size_bytes"] = result.test_size_bytes
        self.session["block_size_bytes"] = result.block_size_bytes
        self.session["total_blocks"] = result.total_blocks
        self.session["scan_mode"] = self.scan_mode
        self.session["flush_policy"] = self.flush_policy

        if not self.blocks:
            self.blocks = self.build_block_plan(result)
            self.session["blocks"] = [asdict(b) for b in self.blocks]
        result.total_blocks = len(self.blocks)
        self.save_checkpoint()
        self.log(f"Session folder: {result.session_dir}")
        self.log(f"Test size: {human_bytes(result.test_size_bytes)}, block size: {human_bytes(result.block_size_bytes)}")
        if result.test_size_bytes / max(1, result.capacity_reported_bytes) < 0.03 and result.capacity_reported_bytes > 128 * 1024 ** 3:
            self.log("[Warning] Coverage is small for a large device. Deep or full validation gives stronger fake-capacity evidence.")

    def auto_scale_parameters(self, total_bytes, free_bytes):
        total_gb = total_bytes / (1024 ** 3)
        free_mb = free_bytes / (1024 ** 2)
        safe_free_mb = max(16, free_mb - 512)

        if total_gb >= 1024:
            block_mb = 64
        elif total_gb >= 256:
            block_mb = 32
        elif total_gb >= 64:
            block_mb = 16
        else:
            block_mb = 8

        if self.scan_mode == "Quick Scan":
            test_mb = min(safe_free_mb, max(512, total_gb * 48))
        elif self.scan_mode == "Balanced Scan":
            test_mb = min(safe_free_mb, max(2048, min(68_000, total_gb * 256)))
        elif self.scan_mode == "Deep Scan":
            test_mb = min(safe_free_mb, max(8192, min(140_000, total_gb * 512)))
        elif self.scan_mode == "Full Capacity Validation":
            test_mb = safe_free_mb
        elif self.scan_mode == "Fake-Capacity Boundary":
            target_gb = 0
            for boundary in BOUNDARY_PRESETS:
                if total_gb > boundary:
                    target_gb = boundary + 2
            test_mb = min(safe_free_mb, max(2048, target_gb * 1024 if target_gb else total_gb * 512))
        else:
            test_mb = min(safe_free_mb, max(512, total_gb * 32))

        if self.flush_policy == "Deep":
            block_mb = min(block_mb, 16)
        return int(test_mb * 1024 ** 2), int(block_mb * 1024 ** 2)

    def build_block_plan(self, result):
        blocks = []
        offset = 0
        for i in range(result.total_blocks):
            size = min(result.block_size_bytes, result.test_size_bytes - offset)
            if size <= 0:
                break
            seed_text = f"{APP_NAME}|{result.session_id}|{i}|{offset}|{size}|{random.getrandbits(64)}"
            blocks.append(BlockRecord(index=i, offset=offset, size=size, seed=seed_text))
            offset += size
        return blocks

    def load_checkpoint(self, session_dir: Path):
        checkpoint = session_dir / CHECKPOINT_NAME
        if not checkpoint.exists():
            raise FileNotFoundError(f"Checkpoint not found: {checkpoint}")
        return json.loads(checkpoint.read_text(encoding="utf-8"))

    def save_checkpoint(self):
        if not self.session:
            return
        self.session["updated_at"] = now_stamp()
        self.session["blocks"] = [asdict(b) for b in self.blocks]
        session_dir = Path(self.session["session_dir"])
        tmp = session_dir / f"{CHECKPOINT_NAME}.tmp"
        final = session_dir / CHECKPOINT_NAME
        tmp.write_text(json.dumps(self.session, indent=2), encoding="utf-8")
        tmp.replace(final)

    def validate_session_identity(self, result, disk_root, usage):
        if not self.session:
            return False
        expected_serial = self.session.get("volume_serial")
        expected_capacity = int(self.session.get("capacity_reported_bytes") or 0)
        expected_fs = self.session.get("filesystem")
        current_serial = result.volume_info.get("serial")
        current_fs = result.volume_info.get("filesystem")
        if self.resume_session:
            mismatches = []
            if expected_serial and current_serial and expected_serial != current_serial:
                mismatches.append(f"volume serial changed ({expected_serial} -> {current_serial})")
            if expected_fs and current_fs and expected_fs != current_fs:
                mismatches.append(f"filesystem changed ({expected_fs} -> {current_fs})")
            if expected_capacity and abs(expected_capacity - usage.total) > max(128 * 1024 ** 2, expected_capacity * 0.01):
                mismatches.append("reported capacity changed")
            if not self.test_file.exists():
                mismatches.append("test file is missing")
            if mismatches:
                self.add_issue(
                    result,
                    "High",
                    "Resume identity validation failed",
                    "The saved session may not belong to the selected device: " + "; ".join(mismatches),
                    30,
                )
                return False
        return True

    def stream_pattern(self, seed: str, size: int, chunk_size=1024 * 1024):
        seed_bytes = seed.encode("utf-8", errors="replace")
        counter = 0
        remaining = size
        while remaining > 0:
            out = bytearray()
            target = min(chunk_size, remaining)
            while len(out) < target:
                out.extend(hashlib.sha256(seed_bytes + counter.to_bytes(8, "little")).digest())
                counter += 1
            chunk = bytes(out[:target])
            remaining -= len(chunk)
            yield chunk

    def write_block(self, fh, block: BlockRecord):
        hasher = hashlib.sha256()
        t0 = time.perf_counter()
        fh.seek(block.offset)
        for chunk in self.stream_pattern(block.seed, block.size):
            fh.write(chunk)
            hasher.update(chunk)
            if self.emergency_stop:
                raise RuntimeError("Emergency stop requested")
        if self.should_flush(block.index):
            fh.flush()
            os.fsync(fh.fileno())
        elapsed = max(time.perf_counter() - t0, 0.0001)
        block.expected_sha256 = hasher.hexdigest()
        block.write_status = "written"
        block.timestamp = now_stamp()
        block.write_speed_mb_s = (block.size / 1024 / 1024) / elapsed
        block.error_details = ""

    def read_verify_block(self, fh, block: BlockRecord):
        expected = hashlib.sha256()
        actual = hashlib.sha256()
        t0 = time.perf_counter()
        fh.seek(block.offset)
        remaining = block.size
        for expected_chunk in self.stream_pattern(block.seed, block.size):
            data = fh.read(len(expected_chunk))
            if len(data) != len(expected_chunk):
                raise IOError(f"Short read: expected {len(expected_chunk)}, got {len(data)}")
            expected.update(expected_chunk)
            actual.update(data)
            remaining -= len(data)
            if self.emergency_stop:
                raise RuntimeError("Emergency stop requested")
        elapsed = max(time.perf_counter() - t0, 0.0001)
        expected_digest = block.expected_sha256 or expected.hexdigest()
        actual_digest = actual.hexdigest()
        block.read_status = "read"
        block.read_speed_mb_s = (block.size / 1024 / 1024) / elapsed
        block.timestamp = now_stamp()
        if actual_digest == expected_digest:
            block.verification_result = "ok"
            block.error_details = ""
        else:
            block.verification_result = "corrupt"
            block.error_details = f"SHA256 mismatch expected={expected_digest} actual={actual_digest}"

    def should_flush(self, index):
        policy = self.flush_policy
        if policy == "Deep":
            return True
        if policy == "Balanced":
            return index % 4 == 0
        return index % 16 == 0

    def retry_io(self, action, block):
        last_exc = None
        for attempt in range(self.settings.retry_count + 1):
            try:
                action()
                block.retries += attempt
                return True
            except Exception as exc:
                last_exc = exc
                if self.emergency_stop or self.cancelled:
                    break
                time.sleep(self.settings.retry_delay_sec)
        block.error_details = f"{type(last_exc).__name__}: {last_exc}"
        return False

    def perform_integrity_test(self, result: ScanResult):
        if not result.test_size_bytes or not self.blocks:
            return
        self.log("Starting resumable block write phase.")
        mode = "r+b" if self.test_file.exists() else "w+b"
        written_bytes = sum(b.size for b in self.blocks if b.write_status == "written" and not self.recheck_all)
        verified_bytes = sum(b.size for b in self.blocks if b.verification_result == "ok" and not self.recheck_all)
        processed_bytes = sum(b.size for b in self.blocks if b.verification_result in ("ok", "corrupt", "read_failed") or b.write_status == "failed")
        write_speeds = []
        read_speeds = []
        write_started = time.perf_counter()
        verify_started = None
        total_plan_bytes = sum(b.size for b in self.blocks)

        with open(self.test_file, mode, buffering=1024 * 1024) as fh:
            for block in self.blocks:
                self.wait_if_paused()
                if self.cancelled:
                    self.mark_interrupted(result, self.stop_reason or "manual cancellation")
                    self.log("Scan stopped. Session checkpoint was preserved for resume and partial reports.")
                    break
                if block.write_status == "written" and block.expected_sha256 and not self.recheck_all:
                    continue
                ok = self.retry_io(lambda b=block: self.write_block(fh, b), block)
                if not ok:
                    block.write_status = "failed"
                    self.refresh_result_counts(result)
                    self.log(f"[High] Write failure at block {block.index + 1}: {block.error_details}")
                    self.save_checkpoint()
                    self.emit_telemetry(result, "Writing", block, {"write_speed": 0.0})
                    continue
                written_bytes += block.size
                write_speeds.append(block.write_speed_mb_s)
                self.save_checkpoint()
                pct = 23 + int((written_bytes / max(1, result.test_size_bytes)) * 34)
                self.progress(min(57, pct))
                elapsed = max(time.perf_counter() - write_started, 0.001)
                eta = ((total_plan_bytes - written_bytes) / max(1, written_bytes)) * elapsed if written_bytes else 0
                self.emit_telemetry(result, "Writing", block, {"write_speed": block.write_speed_mb_s, "eta_seconds": eta})
                if block.index % 4 == 0 or block.index == len(self.blocks) - 1:
                    self.log(f"Written {human_bytes(written_bytes)} / {human_bytes(result.test_size_bytes)}")

            try:
                fh.flush()
                os.fsync(fh.fileno())
            except Exception:
                pass

            if self.settings.delayed_verify_seconds > 0 and not self.cancelled:
                self.log(f"Delayed verification wait: {self.settings.delayed_verify_seconds} seconds")
                for _ in range(self.settings.delayed_verify_seconds * 5):
                    self.wait_if_paused()
                    if self.cancelled:
                        break
                    time.sleep(0.2)

            verify_plan = [b for b in self.blocks if b.write_status == "written"]
            if self.scan_mode == "Random Spot Check":
                sample = max(1, int(len(verify_plan) * 0.35))
                verify_plan = sorted(random.sample(verify_plan, min(sample, len(verify_plan))), key=lambda b: b.index)

            self.log("Starting read verification phase.")
            verify_started = time.perf_counter()
            for block in verify_plan:
                self.wait_if_paused()
                if self.cancelled:
                    self.mark_interrupted(result, self.stop_reason or "manual cancellation")
                    self.log("Scan stopped. Session checkpoint was preserved for resume and partial reports.")
                    break
                if block.verification_result == "ok" and not self.recheck_all:
                    continue
                ok = self.retry_io(lambda b=block: self.read_verify_block(fh, b), block)
                if not ok:
                    block.read_status = "failed"
                    block.verification_result = "read_failed"
                    self.refresh_result_counts(result)
                    self.log(f"[High] Read failure at block {block.index + 1}: {block.error_details}")
                elif block.verification_result == "corrupt":
                    if not self.has_issue(result, "Data corruption detected"):
                        self.add_issue(
                            result,
                            "Critical",
                            "Data corruption detected",
                            "One or more blocks changed after writing. This is a strong counterfeit/failing-device signal.",
                            60,
                        )
                    self.refresh_result_counts(result)
                    self.log(f"[Critical] Data corruption detected at block {block.index + 1}")
                else:
                    verified_bytes += block.size
                    read_speeds.append(block.read_speed_mb_s)
                    self.refresh_result_counts(result)
                processed_bytes = result.processed_bytes
                self.save_checkpoint()
                pct = 57 + int((processed_bytes / max(1, result.test_size_bytes)) * 31)
                self.progress(min(88, pct))
                elapsed = max(time.perf_counter() - verify_started, 0.001)
                eta = ((result.test_size_bytes - processed_bytes) / max(1, processed_bytes)) * elapsed if processed_bytes else 0
                self.emit_telemetry(result, "Verifying", block, {"read_speed": block.read_speed_mb_s, "eta_seconds": eta})
                if block.index % 4 == 0 or block.index == verify_plan[-1].index:
                    self.log(
                        f"Verified {human_bytes(result.verified_bytes)} | "
                        f"Corrupted {human_bytes(result.corrupted_bytes)} | "
                        f"Processed {human_bytes(result.processed_bytes)} / {human_bytes(result.test_size_bytes)}"
                    )
                if (
                    self.settings.auto_stop_severe_corruption
                    and result.max_consecutive_corruption_count >= self.settings.severe_corruption_blocks
                ):
                    self.mark_interrupted(result, f"corruption threshold exceeded ({result.max_consecutive_corruption_count} consecutive blocks)")
                    self.cancelled = True
                    self.log(f"[Critical] Auto-stopping after {result.max_consecutive_corruption_count} consecutive corrupted blocks.")
                    break

            self.random_recheck(fh, result, read_speeds)

        self.refresh_result_counts(result)
        if write_speeds:
            result.write_mb_s = sum(write_speeds) / len(write_speeds)
        else:
            prior = [b.write_speed_mb_s for b in self.blocks if b.write_speed_mb_s > 0]
            result.write_mb_s = sum(prior) / len(prior) if prior else 0
        all_read = [b.read_speed_mb_s for b in self.blocks if b.read_speed_mb_s > 0]
        result.read_mb_s = sum(all_read) / len(all_read) if all_read else 0
        self.detect_speed_anomalies(result)

        if result.write_failures and not self.has_issue(result, "Write failure detected"):
            self.add_issue(result, "High", "Write failure detected", "The device failed during temporary test data writing.", 32)
        if result.corrupted_blocks and not self.has_issue(result, "Data corruption detected"):
            self.add_issue(
                result,
                "Critical",
                "Data corruption detected",
                f"{result.corrupted_blocks} block(s) changed after writing. This is a strong counterfeit/failing-device signal.",
                60,
            )
        if result.read_failures and not self.has_issue(result, "Read failure detected"):
            self.add_issue(
                result,
                "High",
                "Read failure detected",
                f"{result.read_failures} block(s) could not be read back correctly.",
                35,
            )

    def random_recheck(self, fh, result, read_speeds):
        candidates = [b for b in self.blocks if b.verification_result == "ok"]
        if not candidates or self.settings.random_recheck_percent <= 0 or self.cancelled:
            return
        count = max(1, int(len(candidates) * self.settings.random_recheck_percent / 100))
        self.log(f"Running random post-write recheck on {count} block(s).")
        for block in random.sample(candidates, min(count, len(candidates))):
            self.wait_if_paused()
            if self.cancelled:
                break
            previous = block.verification_result
            if self.retry_io(lambda b=block: self.read_verify_block(fh, b), block):
                read_speeds.append(block.read_speed_mb_s)
                if block.verification_result != "ok":
                    self.refresh_result_counts(result)
                    if not self.has_issue(result, "Data corruption detected"):
                        self.add_issue(
                            result,
                            "Critical",
                            "Data corruption detected",
                            "One or more blocks changed after writing. This is a strong counterfeit/failing-device signal.",
                            60,
                        )
                    self.log(f"[Critical] Random recheck failed at block {block.index + 1}")
            else:
                block.verification_result = "read_failed"
                self.refresh_result_counts(result)
            if previous != block.verification_result:
                self.save_checkpoint()
                self.emit_telemetry(result, "Random Recheck", block, {"read_speed": block.read_speed_mb_s})

    def detect_speed_anomalies(self, result):
        speeds = [(b.offset, b.write_speed_mb_s, "write") for b in self.blocks if b.write_speed_mb_s > 0]
        speeds += [(b.offset, b.read_speed_mb_s, "read") for b in self.blocks if b.read_speed_mb_s > 0]
        values = [s[1] for s in speeds]
        if values:
            avg = sum(values) / len(values)
            variance = sum((s - avg) ** 2 for s in values) / len(values)
            result.speed_variation_percent = min(999.0, (math.sqrt(variance) / max(avg, 0.0001)) * 100)
            for offset, speed, phase in speeds:
                if avg > 0 and speed < avg * 0.25 and offset > result.block_size_bytes:
                    drop = {"phase": phase, "offset": offset, "speed_mb_s": round(speed, 2), "average_mb_s": round(avg, 2)}
                    result.speed_drops.append(drop)
        boundaries = [b * 1024 ** 3 for b in BOUNDARY_PRESETS]
        for block in self.blocks:
            if block.verification_result in ("corrupt", "read_failed") or block.write_status == "failed":
                for boundary in boundaries:
                    if abs(block.offset - boundary) <= max(result.block_size_bytes * 2, 256 * 1024 ** 2):
                        result.fake_capacity_indicators.append(f"Failure near {human_bytes(boundary)} boundary")

    def evaluate_metadata(self, result: ScanResult):
        vi = result.volume_info
        fs = str(vi.get("filesystem", "Unknown")).upper()
        if fs in ("FAT", "FAT32") and result.capacity_reported_bytes > 64 * 1024 ** 3:
            self.add_issue(
                result,
                "Medium",
                "Large drive using FAT/FAT32",
                "Large removable media with FAT/FAT32 is common on low-cost devices and deserves deeper validation.",
                8,
            )
        meta = result.disk_metadata or {}
        serial = str(meta.get("SerialNumber", "Unknown"))
        model = str(meta.get("Model", meta.get("FriendlyName", "Unknown")))
        bus = str(meta.get("BusType", meta.get("PhysicalBusType", "Unknown")))
        friendly = str(meta.get("FriendlyName", ""))
        unknown_fields = sum(1 for value in (serial, model, bus) if not value or value.strip().lower() in ("unknown", "none", "null"))
        if unknown_fields >= 2:
            self.add_issue(result, "Medium", "Limited device identity metadata", "Model, serial, or bus type could not be reliably collected.", 8)
        generic_words = ("generic", "usb device", "mass storage", "flash disk", "vendorco", "unknown")
        if any(word in (model + " " + friendly).lower() for word in generic_words):
            self.add_issue(result, "Medium", "Generic model identity", "The device reports a generic model name, which is common on commodity or counterfeit removable media.", 8)
        if result.drive_type == "Removable" and result.capacity_reported_bytes >= 2 * 1024 ** 4:
            self.add_issue(result, "High", "Very large removable capacity", "A removable device reporting 2 TB or more should be tested deeply, especially if it was low-cost.", 24)
        disk_size = safe_int(meta.get("Size"), 0)
        volume_size = safe_int(meta.get("VolumeSize"), 0)
        if disk_size and volume_size and abs(disk_size - volume_size) > max(8 * 1024 ** 3, disk_size * 0.08):
            self.add_issue(result, "Medium", "Disk and volume size mismatch", "Windows disk and volume metadata report noticeably different sizes.", 12)

    def evaluate_health(self, result: ScanResult):
        meta = result.disk_metadata or {}
        status = f"{meta.get('HealthStatus', '')} {meta.get('PhysicalHealthStatus', '')} {meta.get('OperationalStatus', '')}"
        lower = status.lower()
        if any(word in lower for word in ("unhealthy", "warning", "degraded", "lost communication", "pred fail")):
            self.add_issue(result, "High", "Health status warning", f"Windows reported health/operational warning: {status.strip()}", 30)

    def evaluate_speed(self, result: ScanResult):
        if result.test_size_bytes == 0:
            return
        if result.write_mb_s <= 0 or result.read_mb_s <= 0:
            self.add_issue(result, "High", "Invalid speed result", "Read/write speed could not be measured successfully.", 25)
            return
        if result.write_mb_s < 2:
            self.add_issue(result, "Medium", "Very low write speed", f"Average write speed was only {result.write_mb_s:.2f} MB/s.", 12)
        if result.read_mb_s < 5:
            self.add_issue(result, "Medium", "Very low read speed", f"Average read speed was only {result.read_mb_s:.2f} MB/s.", 10)
        if result.speed_variation_percent > 120:
            self.add_issue(result, "Medium", "Highly inconsistent speed", f"Speed variation was {result.speed_variation_percent:.1f}%.", 14)
        if result.speed_drops:
            self.add_issue(result, "Medium", "Speed collapse detected", f"{len(result.speed_drops)} block speed drop(s) were recorded.", 12)

    def evaluate_capacity_risk(self, result: ScanResult):
        if result.capacity_reported_bytes <= 0:
            return
        tested_ratio = result.test_size_bytes / result.capacity_reported_bytes
        if tested_ratio < 0.01 and result.capacity_reported_bytes > 128 * 1024 ** 3:
            self.add_issue(
                result,
                "Info",
                "Limited capacity coverage",
                f"Only {tested_ratio * 100:.2f}% of reported capacity was tested. Increase test size for stronger fake-capacity detection.",
                0,
            )
        elif tested_ratio < 0.08 and self.scan_mode in ("Quick Scan", "Balanced Scan") and result.capacity_reported_bytes > 512 * 1024 ** 3:
            self.add_issue(result, "Info", "Needs deeper testing for large capacity", "Large drives need broad coverage before trusting full advertised capacity.", 0)

    def evaluate_block_findings(self, result):
        if any("boundary" in str(x).lower() for x in result.fake_capacity_indicators):
            self.add_issue(result, "High", "Boundary failure indicator", "A failure occurred near a common fake-capacity boundary.", 28)

    def finish_session(self, result):
        if not self.session:
            return
        if result.scan_interrupted:
            session_status = "interrupted"
        elif result.failed_blocks:
            session_status = "completed_with_findings"
        else:
            session_status = "completed"
        self.session["status"] = session_status
        self.session["result_status"] = result.status
        self.session["finalization_reason"] = result.finalization_reason
        self.session["interruption_reason"] = result.interruption_reason
        self.session["report_path"] = result.report_path
        self.session["json_report_path"] = result.json_report_path
        self.session["csv_report_path"] = result.csv_report_path
        self.session["html_report_path"] = result.html_report_path
        self.session["pdf_report_path"] = result.pdf_report_path
        try:
            self.save_checkpoint()
            self.write_session_block_csv(Path(self.session["session_dir"]) / BLOCK_REPORT_NAME)
            if self.cancelled:
                self.log("Resume mode active: unfinished test files were preserved and partial reports were generated.")
        except Exception as exc:
            self.log(f"[Warning] Could not update session checkpoint: {exc}")

    def finalize(self, result: ScanResult):
        result.completed_at = now_stamp()
        if self.blocks:
            self.refresh_result_counts(result)
        if self.cancelled and not result.scan_interrupted:
            self.mark_interrupted(result, self.stop_reason or "manual cancellation")
        result.risk_score = min(100, max(0, result.risk_score))
        critical = any(i.severity == "Critical" for i in result.issues)
        high_count = sum(1 for i in result.issues if i.severity == "High")
        if result.scan_interrupted and not critical and result.risk_score < 45:
            result.status = "SCAN INTERRUPTED - PARTIAL RESULTS"
        elif critical or result.risk_score >= 70:
            result.status = "Likely Fake or Failing"
        elif high_count >= 1 or result.risk_score >= 45:
            result.status = "Suspicious"
        elif result.risk_score >= 18:
            result.status = "Needs Deeper Testing"
        elif result.test_size_bytes == 0 or self.cancelled:
            result.status = "Inconclusive"
        else:
            result.status = "No Major Issues Found"
        if result.scan_interrupted and not result.status.startswith("SCAN INTERRUPTED"):
            result.status = f"SCAN INTERRUPTED - PARTIAL RESULTS ({result.status})"
        result.conclusion = self.make_conclusion(result)
        result.health_diagnostics = dict(LAST_HEALTH_SUMMARY) if isinstance(LAST_HEALTH_SUMMARY, dict) else {}
        try:
            self.generate_reports(result)
            append_history(
                {
                    "completed_at": result.completed_at,
                    "target": result.root,
                    "status": result.status,
                    "risk_score": result.risk_score,
                    "scan_mode": result.scan_mode,
                    "test_size": human_bytes(result.test_size_bytes),
                    "report_path": result.report_path,
                    "html_report_path": result.html_report_path,
                    "pdf_report_path": result.pdf_report_path,
                    "session_dir": result.session_dir,
                }
            )
        except Exception as exc:
            self.log(f"[Warning] Report generation failed: {exc}")
            self.logger.exception("Report generation failed")
        self.progress(100)
        self.emit_telemetry(result, result.status)
        self.log(f"Scan finalized. Final status: {result.status}")
        return result

    def make_conclusion(self, result):
        if result.status == "Likely Fake or Failing":
            return "Strong evidence was found, such as corruption, failed reads/writes, capacity mismatch, or serious health/metadata warnings. Do not trust this device with important data."
        if result.status == "Suspicious":
            return "The scan found warning signs. Run a deeper or full-capacity validation before trusting the device."
        if result.status == "Needs Deeper Testing":
            return "No decisive failure was found, but the warning level or scan coverage is not enough for a confident authenticity decision."
        if result.status == "Inconclusive":
            return "The scan did not gather enough write/read evidence to make a storage authenticity verdict."
        if result.status.startswith("SCAN INTERRUPTED"):
            return "The scan was interrupted before full completion. Current evidence was preserved and reports contain partial verified, corrupted, and failed ranges."
        return "No major issues were found in the tested range. This does not prove the entire device is genuine unless full capacity was validated."

    def write_session_block_csv(self, path):
        with open(path, "w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(asdict(self.blocks[0]).keys()) if self.blocks else ["index"])
            writer.writeheader()
            for block in self.blocks:
                writer.writerow(asdict(block))

    def generate_reports(self, result: ScanResult):
        reports_dir = ensure_reports_dir()
        clean_root = result.root.replace("\\", "_").replace("/", "_").replace(":", "")
        base = reports_dir / f"storage_report_{clean_root}_{file_stamp()}"
        enabled = set(REPORT_FORMATS if self.settings.report_formats is None else self.settings.report_formats)
        if "CSV" in enabled:
            result.csv_report_path = str(base.with_suffix(".csv"))
        if "JSON" in enabled:
            result.json_report_path = str(base.with_suffix(".json"))
        if "Text" in enabled:
            result.report_path = str(base.with_suffix(".txt"))
        if "HTML" in enabled:
            result.html_report_path = str(base.with_suffix(".html"))
        if "PDF" in enabled:
            result.pdf_report_path = str(base.with_suffix(".pdf"))
        if result.csv_report_path:
            self.write_session_block_csv(Path(result.csv_report_path))
        if result.report_path:
            Path(result.report_path).write_text(self.text_report(result), encoding="utf-8")
        if result.html_report_path:
            Path(result.html_report_path).write_text(self.html_report(result), encoding="utf-8")
        if result.pdf_report_path:
            self.write_pdf_report(result)
        data = self.result_to_dict(result)
        if result.json_report_path:
            Path(result.json_report_path).write_text(json.dumps(data, indent=2), encoding="utf-8")

    def result_to_dict(self, result):
        data = asdict(result)
        data["issues"] = [asdict(i) if hasattr(i, "__dataclass_fields__") else i for i in result.issues]
        data["blocks"] = [asdict(b) for b in self.blocks]
        data["corruption_ranges"] = self.block_ranges(lambda b: b.verification_result == "corrupt")
        data["verified_ranges"] = self.block_ranges(lambda b: b.verification_result == "ok")
        data["failed_ranges"] = self.block_ranges(lambda b: b.verification_result in ("corrupt", "read_failed") or b.write_status == "failed")
        data["sha256_mismatch_evidence"] = [
            {"block": b.index + 1, "offset": b.offset, "size": b.size, "details": b.error_details}
            for b in self.blocks
            if b.verification_result == "corrupt"
        ]
        return data

    def write_pdf_report(self, result: ScanResult):
        if not result.pdf_report_path:
            return False
        html_content = self.html_report(result, for_pdf=True)
        try:
            from weasyprint import HTML
            HTML(string=html_content, base_url=str(ensure_reports_dir())).write_pdf(result.pdf_report_path)
            return True
        except Exception as exc:
            self.log(f"[Info] WeasyPrint PDF export unavailable: {exc}")
        try:
            import pdfkit
            pdfkit.from_string(html_content, result.pdf_report_path)
            return True
        except Exception as exc:
            self.log(f"[Info] pdfkit/wkhtmltopdf PDF export unavailable: {exc}")
        result.pdf_report_path = ""
        self.log("[Info] PDF report was not generated. Install WeasyPrint or pdfkit with wkhtmltopdf to enable PDF export.")
        return False

    def block_ranges(self, predicate):
        selected = sorted([b for b in self.blocks if predicate(b)], key=lambda b: b.index)
        ranges = []
        if not selected:
            return ranges
        start = prev = selected[0]
        for block in selected[1:]:
            if block.index == prev.index + 1 and block.offset == prev.offset + prev.size:
                prev = block
                continue
            ranges.append(self.range_dict(start, prev))
            start = prev = block
        ranges.append(self.range_dict(start, prev))
        return ranges

    def range_dict(self, start: BlockRecord, end: BlockRecord):
        end_offset = end.offset + end.size
        return {
            "start_block": start.index + 1,
            "end_block": end.index + 1,
            "start_offset": start.offset,
            "end_offset": end_offset,
            "bytes": end_offset - start.offset,
            "human_start_offset": human_bytes(start.offset),
            "human_end_offset": human_bytes(end_offset),
            "human_size": human_bytes(end_offset - start.offset),
        }

    def ranges_text(self, title, ranges):
        lines = [title, "-" * 78]
        if not ranges:
            lines.append("None recorded.")
            return lines
        for item in ranges:
            lines.append(
                f"Blocks {item['start_block']}-{item['end_block']} | "
                f"{item['human_start_offset']} to {item['human_end_offset']} | {item['human_size']}"
            )
        return lines

    def text_report(self, result: ScanResult) -> str:
        lines = [
            "=" * 78,
            f"{APP_NAME} v{APP_VERSION} - Storage Authenticity Report",
            "=" * 78,
            f"Started:   {result.started_at}",
            f"Completed: {result.completed_at}",
            f"Target:    {result.root}",
            f"Session:   {result.session_id}",
            "",
            "FINAL RESULT",
            "-" * 78,
            f"Status:     {result.status}",
            f"Finalization Reason: {result.finalization_reason}",
            f"Scan Interrupted: {'Yes' if result.scan_interrupted else 'No'}",
            f"Interruption Reason: {result.interruption_reason or 'None'}",
            f"Risk Score: {result.risk_score}/100",
            f"Conclusion: {result.conclusion}",
            "",
            "SCAN SETTINGS",
            "-" * 78,
            f"Mode:         {result.scan_mode}",
            f"Flush Policy: {result.flush_policy}",
            f"Test Size:    {human_bytes(result.test_size_bytes)}",
            f"Block Size:   {human_bytes(result.block_size_bytes)}",
            f"Total Blocks: {result.total_blocks}",
            "",
            "CAPACITY",
            "-" * 78,
            f"Windows Reported Capacity: {human_bytes(result.capacity_reported_bytes)}",
            f"Used Space:                 {human_bytes(result.used_bytes)}",
            f"Free Space:                 {human_bytes(result.free_bytes)}",
        ]
        if result.advertised_bytes:
            lines.append(f"Advertised Capacity Input:  {human_bytes(result.advertised_bytes)}")
        lines += [
            "",
            "READ/WRITE VERIFICATION",
            "-" * 78,
            f"Blocks Written:       {result.blocks_tested}",
            f"Processed Blocks:     {result.processed_blocks}",
            f"Verified Blocks:      {result.verified_blocks}",
            f"Failed Blocks:        {result.failed_blocks}",
            f"Verified Bytes:       {human_bytes(result.verified_bytes)}",
            f"Corrupted Bytes:      {human_bytes(result.corrupted_bytes)}",
            f"Failed Bytes:         {human_bytes(result.failed_bytes)}",
            f"Processed Bytes:      {human_bytes(result.processed_bytes)}",
            f"Test Coverage:        {result.coverage_percent:.4f}% of reported capacity",
            f"Average Write Speed:  {result.write_mb_s:.2f} MB/s",
            f"Average Read Speed:   {result.read_mb_s:.2f} MB/s",
            f"Speed Variation:      {result.speed_variation_percent:.1f}%",
            f"Write Failures:       {result.write_failures}",
            f"Read Failures:        {result.read_failures}",
            f"Corrupted Blocks:     {result.corrupted_blocks}",
            f"Corruption Percent:   {result.corruption_percent:.2f}% of processed bytes",
            f"First Corruption Block: {result.first_corruption_block or 'None'}",
            f"First Failure Timestamp: {result.first_failure_timestamp or 'None'}",
            f"Last Successful Verified Block: {result.last_successful_block or 'None'}",
            f"Consecutive Corruption Count: {result.consecutive_corruption_count}",
            f"Max Consecutive Corruption Count: {result.max_consecutive_corruption_count}",
            f"Corruption Start Offset: {human_bytes(result.corruption_start_offset) if result.first_corruption_block else 'None'}",
            f"Estimated Authentic Usable Capacity: {human_bytes(result.estimated_valid_capacity_bytes)}",
            "",
            "SPEED DROPS",
            "-" * 78,
        ]
        lines += [json.dumps(d) for d in result.speed_drops] or ["None recorded."]
        lines += [""] + self.ranges_text("VERIFIED RANGES", self.block_ranges(lambda b: b.verification_result == "ok"))
        lines += [""] + self.ranges_text("FAILED / CORRUPTED RANGES", self.block_ranges(lambda b: b.verification_result in ("corrupt", "read_failed") or b.write_status == "failed"))
        lines += [""] + self.ranges_text("CORRUPTION RANGES", self.block_ranges(lambda b: b.verification_result == "corrupt"))
        mismatch_evidence = [b for b in self.blocks if b.verification_result == "corrupt"]
        lines += ["", "SHA256 MISMATCH EVIDENCE", "-" * 78]
        if mismatch_evidence:
            for block in mismatch_evidence[:200]:
                lines.append(f"Block {block.index + 1} offset {human_bytes(block.offset)}: {block.error_details}")
        else:
            lines.append("None recorded.")
        lines += ["", "FAKE-CAPACITY INDICATORS", "-" * 78]
        lines += result.fake_capacity_indicators or ["No strong fake-capacity indicators recorded."]
        lines += ["", "DEVICE / FILESYSTEM METADATA", "-" * 78, f"Drive Type: {result.drive_type}"]
        for k, v in (result.volume_info or {}).items():
            lines.append(f"{k}: {v}")
        for k, v in (result.disk_metadata or {}).items():
            lines.append(f"{k}: {v}")
        if result.metadata_warning:
            lines.append(f"Metadata Warning: {result.metadata_warning}")
        lines += ["", "SMART SUMMARY", "-" * 78]
        if result.smart_summary:
            lines.append(json.dumps(result.smart_summary, indent=2))
        else:
            lines.append("Unavailable.")
        if result.smart_warning:
            lines.append(f"SMART Note: {result.smart_warning}")
        lines += ["", "FINDINGS", "-" * 78]
        if result.issues:
            for issue in result.issues:
                lines.append(f"[{issue.severity}] {issue.title}")
                lines.append(f"  {issue.detail}")
        else:
            lines.append("No major suspicious findings were detected during this scan.")
        lines += self.health_report_lines(result.health_diagnostics)
        lines += [
            "",
            "LIMITATIONS",
            "-" * 78,
            "The tool writes only normal test files in the selected folder. It does not overwrite raw disks.",
            "A partial scan cannot prove an entire large-capacity device is genuine. Full validation is strongest.",
            "=" * 78,
        ]
        return "\n".join(lines)

    def health_report_lines(self, health):
        lines = ["", "STORAGE HEALTH & DIAGNOSTICS", "-" * 78]
        if not health:
            lines.append("No Storage Health & Diagnostics run has been attached to this report.")
            return lines
        lines.extend(
            [
                f"Health Status: {health.get('health_status', 'Unknown')}",
                f"Health Risk Score: {health.get('health_risk_score', 0)}/100",
                f"Recommendation: {health.get('recommendation', 'N/A')}",
                f"SMART Status: {health.get('smart_status', 'N/A')}",
                f"Windows Health Status: {health.get('windows_health_status', 'N/A')}",
                f"Temperature: {health.get('temperature', 'Unknown')}",
                f"Wear / Age: {health.get('wear_age', 'Unknown')}",
                f"Read Stability: {health.get('read_stability_status', 'N/A')}",
                "",
                "SMART Parsed Results:",
                json.dumps(health.get("smart_parsed", {}), indent=2),
                "",
                "Windows Health Results:",
                json.dumps(health.get("windows_parsed", {}), indent=2),
                "",
                "Surface Read Stability Results:",
                json.dumps(health.get("surface_results", {}), indent=2),
                "",
                "Read-only CHKDSK Output:",
                str(health.get("chkdsk_output", "Not run"))[:12000],
            ]
        )
        issues = health.get("issues") or []
        lines += ["", "Health Findings:"]
        if issues:
            for item in issues:
                lines.append(f"[{item.get('severity')}] {item.get('title')}: {item.get('detail')}")
        else:
            lines.append("No health-specific findings recorded.")
        return lines

    def report_log_preview(self, max_lines=60):
        log_path = ensure_reports_dir() / LOG_FILE_NAME
        try:
            if log_path.exists():
                return "\n".join(log_path.read_text(encoding="utf-8", errors="replace").splitlines()[-max_lines:])
        except Exception:
            pass
        return "N/A"

    def html_table_rows_for_ranges(self, ranges):
        if not ranges:
            return "<tr><td colspan=\"5\">N/A</td></tr>"
        return "".join(
            "<tr>"
            f"<td>{item['start_block']}</td>"
            f"<td>{item['end_block']}</td>"
            f"<td>{html.escape(item['human_start_offset'])}</td>"
            f"<td>{html.escape(item['human_end_offset'])}</td>"
            f"<td>{html.escape(item['human_size'])}</td>"
            "</tr>"
            for item in ranges
        )

    def html_health_section(self, health):
        if not health:
            return "<div class=\"panel\" style=\"margin-top:8px\"><h2>Storage Health & Diagnostics</h2><p>No health diagnostics run has been attached to this report.</p></div>"
        issues = health.get("issues") or []
        issue_rows = "".join(
            f"<tr><td>{html.escape(str(i.get('severity', '')))}</td><td>{html.escape(str(i.get('title', '')))}</td><td>{html.escape(str(i.get('detail', '')))}</td></tr>"
            for i in issues
        ) or "<tr><td colspan=\"3\">No health-specific findings recorded.</td></tr>"
        parsed = html.escape(json.dumps(health.get("smart_parsed", {}), indent=2))
        windows = html.escape(json.dumps(health.get("windows_parsed", {}), indent=2))
        surface = html.escape(json.dumps(health.get("surface_results", {}), indent=2))
        chkdsk = html.escape(str(health.get("chkdsk_output", "Not run"))[:14000])
        return f"""
<div class="panel" style="margin-top:8px"><h2>Storage Health & Diagnostics</h2>
<div class="grid metrics">
<div class="metric"><small>Health Status</small><b>{html.escape(str(health.get('health_status', 'Unknown')))}</b></div>
<div class="metric"><small>SMART Status</small><b>{html.escape(str(health.get('smart_status', 'Unknown')))}</b></div>
<div class="metric"><small>Windows Health</small><b>{html.escape(str(health.get('windows_health_status', 'Unknown')))}</b></div>
<div class="metric"><small>Temperature</small><b>{html.escape(str(health.get('temperature', 'Unknown')))}</b></div>
<div class="metric"><small>Health Risk</small><b>{html.escape(str(health.get('health_risk_score', 0)))} / 100</b></div>
</div>
<p><b>Recommendation:</b> {html.escape(str(health.get('recommendation', 'N/A')))}</p>
<h3>Health Findings</h3><table><tr><th>Severity</th><th>Finding</th><th>Detail</th></tr>{issue_rows}</table>
<h3>SMART Parsed Results</h3><pre>{parsed}</pre>
<h3>Windows Health Results</h3><pre>{windows}</pre>
<h3>Surface Read Stability Results</h3><pre>{surface}</pre>
<h3>Read-only CHKDSK Output</h3><pre>{chkdsk}</pre>
</div>"""

    def html_report(self, result: ScanResult, for_pdf=False) -> str:
        verified_ranges_raw = self.block_ranges(lambda b: b.verification_result == "ok")
        failed_ranges_raw = self.block_ranges(lambda b: b.verification_result in ("corrupt", "read_failed") or b.write_status == "failed")
        corruption_ranges_raw = self.block_ranges(lambda b: b.verification_result == "corrupt")
        cap = max(1, result.capacity_reported_bytes or result.test_size_bytes or result.processed_bytes or 1)
        verified_pct = max(0.6 if result.verified_bytes else 0, min(100, result.verified_bytes / cap * 100))
        failed_bytes = max(result.failed_bytes, result.corrupted_bytes)
        failed_pct = max(0.6 if failed_bytes else 0, min(100, failed_bytes / cap * 100))
        untested_pct = max(0, 100 - verified_pct - failed_pct)
        risk_class = "danger" if result.risk_score >= 70 or result.corrupted_blocks else "warn" if result.risk_score >= 30 else "good"
        status_text = html.escape(result.status or "N/A")
        warning_text = "DO NOT TRUST THIS DEVICE WITH IMPORTANT DATA" if result.risk_score >= 70 or result.corrupted_blocks or result.failed_blocks else "Review coverage before trusting this device"
        issues = "".join(
            f"<li><b>{html.escape(i.severity)} - {html.escape(i.title)}</b><span>{html.escape(i.detail)}</span></li>"
            for i in result.issues
        ) or "<li><b>No major findings</b><span>No suspicious findings were recorded in the tested range.</span></li>"
        indicators = result.fake_capacity_indicators or []
        risk_indicators = "".join(f"<li>{html.escape(str(item))}</li>" for item in indicators) or "<li>N/A</li>"
        speed_drops = "".join(f"<li>{html.escape(json.dumps(d))}</li>" for d in result.speed_drops) or "<li>None recorded.</li>"
        mismatch_blocks = [b for b in self.blocks if b.verification_result == "corrupt"]
        mismatch_rows = "".join(
            "<tr>"
            f"<td>{b.index + 1}</td>"
            f"<td>{html.escape(human_bytes(b.offset))}</td>"
            f"<td>{html.escape(b.expected_sha256 or 'N/A')}</td>"
            f"<td>{html.escape((b.error_details or 'N/A')[-96:])}</td>"
            f"<td class=\"bad\">MISMATCH</td>"
            "</tr>"
            for b in mismatch_blocks[:120]
        ) or "<tr><td colspan=\"5\">N/A</td></tr>"
        block_rows = "".join(
            "<tr>"
            f"<td>{b.index + 1}</td>"
            f"<td>{html.escape(human_bytes(b.offset))}</td>"
            f"<td>{html.escape(human_bytes(b.size))}</td>"
            f"<td>{html.escape(b.write_status)}</td>"
            f"<td>{html.escape(b.verification_result)}</td>"
            f"<td>{b.write_speed_mb_s:.2f}</td>"
            f"<td>{b.read_speed_mb_s:.2f}</td>"
            f"<td>{html.escape(b.error_details or '')}</td>"
            "</tr>"
            for b in self.blocks[:500]
        ) or "<tr><td colspan=\"8\">N/A</td></tr>"
        log_preview = html.escape(self.report_log_preview())
        forensic_summary = (
            f"Corruption begins at {human_bytes(result.corruption_start_offset)}. "
            f"Estimated authentic usable capacity is {human_bytes(result.estimated_valid_capacity_bytes)}. "
            f"{result.corruption_percent:.2f}% of processed bytes are corrupted."
            if result.first_corruption_block
            else "No corruption boundary was recorded in the tested range."
        )
        pdf_css = "@page { size: A3 landscape; margin: 10mm; }" if for_pdf else ""
        return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{APP_NAME} Report</title>
<style>
{pdf_css}
:root {{
  --bg:#050912; --panel:#07111f; --panel2:#0a1728; --line:#163657; --cyan:#00e5ff;
  --green:#39ff88; --red:#ff244f; --orange:#ff9f1c; --yellow:#ffd166; --text:#d7f7ff; --muted:#8ab4c8;
}}
* {{ box-sizing:border-box; }}
body {{ margin:0; background:radial-gradient(circle at 50% -10%, #0b2640 0, var(--bg) 38%, #02050b 100%); color:var(--text); font-family:Segoe UI,Arial,sans-serif; }}
.wrap {{ padding:18px; }}
.shell {{ border:1px solid #9aa5ad; padding:10px; background:rgba(2,7,14,.92); box-shadow:0 0 32px rgba(0,229,255,.12) inset; }}
.topbar {{ display:flex; justify-content:space-between; align-items:flex-start; gap:18px; margin-bottom:10px; }}
h1 {{ margin:0; color:var(--cyan); font:800 30px Consolas,monospace; letter-spacing:0; }}
.subtitle {{ color:white; font-weight:600; font-size:12px; margin-top:6px; }}
.status-pill {{ color:{'#39ff88' if not result.failed_blocks and not result.corrupted_blocks else '#ff244f'}; font:800 14px Consolas,monospace; text-align:right; }}
.grid {{ display:grid; gap:8px; }}
.metrics {{ grid-template-columns:repeat(5, 1fr); }}
.middle {{ grid-template-columns:1.2fr 1.55fr 1.1fr; margin-top:8px; }}
.bottom {{ grid-template-columns:1fr 1fr 1fr; margin-top:8px; }}
.panel,.metric {{ background:linear-gradient(135deg, rgba(9,23,39,.98), rgba(3,11,20,.98)); border:1px solid var(--line); padding:12px; }}
.metric small,.label {{ display:block; color:#c0c7d1; font:700 12px Segoe UI,Arial; text-transform:uppercase; margin-bottom:6px; }}
.metric b {{ display:block; color:var(--cyan); font:800 18px Consolas,monospace; overflow-wrap:anywhere; }}
.metric .red,.bad {{ color:var(--red); }} .metric .green,.good {{ color:var(--green); }} .metric .yellow,.warn {{ color:var(--yellow); }}
h2 {{ color:var(--cyan); font:800 16px Consolas,monospace; margin:0 0 10px; text-transform:uppercase; }}
p {{ margin:4px 0; }} .tiny {{ color:var(--muted); font-size:12px; }}
table {{ width:100%; border-collapse:collapse; font-size:12px; }}
th,td {{ border:1px solid var(--line); padding:6px; text-align:left; vertical-align:top; }}
th {{ background:#0d1d31; color:var(--cyan); }}
pre {{ white-space:pre-wrap; overflow-wrap:anywhere; font:11px Consolas,monospace; margin:0; color:#dcefff; }}
ul {{ margin:0; padding-left:18px; }} li {{ margin:7px 0; }} li span {{ display:block; color:#dce6ed; }}
.map {{ border:1px solid #3d617d; background:#121820; height:78px; display:flex; margin-top:8px; overflow:hidden; }}
.seg {{ display:flex; align-items:center; justify-content:center; min-width:10px; text-align:center; font:800 12px Consolas,monospace; color:white; padding:4px; }}
.seg-ok {{ width:{verified_pct:.4f}%; background:linear-gradient(135deg,#0f8a37,#123f23); border-right:1px solid #35ff7d; }}
.seg-bad {{ width:{failed_pct:.4f}%; background:linear-gradient(135deg,#8e0017,#250006); border-right:1px solid #ff244f; }}
.seg-untested {{ width:{untested_pct:.4f}%; background:linear-gradient(135deg,#2f3842,#111820); color:#d0d6dc; }}
.legend {{ display:flex; gap:20px; margin-top:8px; font:12px Consolas,monospace; color:#dcefff; }}
.dot {{ display:inline-block; width:18px; height:9px; margin-right:6px; border:1px solid #566; }}
.okdot {{ background:#13883d; }} .baddot {{ background:#8e0017; }} .graydot {{ background:#3a424c; }}
.warning {{ background:linear-gradient(135deg,#9d0018,#2a0007); border:1px solid #ff365f; text-align:center; padding:18px; color:white; }}
.warning h2 {{ color:#ff365f; font-size:22px; }}
.warning strong {{ display:block; color:white; font-size:20px; margin-top:10px; }}
.evidence-icons {{ display:grid; grid-template-columns:repeat(2,1fr); gap:8px; }}
.evidence-icons div {{ border:1px solid #273e5e; padding:10px; min-height:54px; background:#091522; }}
.evidence-icons b {{ color:var(--red); }}
.footer-note {{ color:#cbd5df; border-top:1px solid var(--line); margin-top:10px; padding-top:8px; font-size:12px; }}
</style></head><body><div class="wrap"><div class="shell">
<div class="topbar"><div><h1>CYBER STORAGE VERIFIER <span style="font-size:16px">v{APP_VERSION}</span></h1>
<div class="subtitle">Counterfeit capacity | Integrity validation | Metadata inspection | Resumable block verification</div></div>
<div class="status-pill">{status_text}</div></div>
<div class="grid metrics">
<div class="metric"><small>Reported Capacity</small><b>{human_bytes(result.capacity_reported_bytes)}</b></div>
<div class="metric"><small>Free Space</small><b class="green">{human_bytes(result.free_bytes)}</b></div>
<div class="metric"><small>Test Coverage</small><b class="yellow">{result.coverage_percent:.4f}%</b></div>
<div class="metric"><small>Current / Final Phase</small><b>{html.escape(result.current_phase or result.status or 'N/A')}</b></div>
<div class="metric"><small>Risk Score</small><b class="{risk_class}">{result.risk_score} / 100</b></div>
<div class="metric"><small>Processed Data</small><b>{human_bytes(result.processed_bytes)}</b></div>
<div class="metric"><small>Verified Data</small><b class="green">{human_bytes(result.verified_bytes)}</b></div>
<div class="metric"><small>Corrupted Data</small><b class="red">{human_bytes(result.corrupted_bytes)}</b></div>
<div class="metric"><small>Failed Blocks</small><b class="yellow">{result.failed_blocks}</b></div>
<div class="metric"><small>Read / Write Speed</small><b>{result.read_mb_s:.2f} / {result.write_mb_s:.2f} MB/s</b></div>
</div>
<div class="grid middle">
<div class="panel"><h2>Scan Summary</h2>
<p><span class="label">Started</span>{html.escape(result.started_at or 'N/A')}</p>
<p><span class="label">Completed</span>{html.escape(result.completed_at or 'N/A')}</p>
<p><span class="label">Target</span>{html.escape(result.root or 'N/A')}</p>
<p><span class="label">Session</span>{html.escape(result.session_id or 'N/A')}</p>
<p><span class="label">Interrupted</span>{'Yes' if result.scan_interrupted else 'No'} - {html.escape(result.interruption_reason or 'None')}</p></div>
<div class="panel"><h2>Final Result</h2><p><b class="{risk_class}">{status_text}</b></p>
<p>{html.escape(result.conclusion or 'N/A')}</p><p class="tiny">Finalization reason: {html.escape(result.finalization_reason or 'N/A')}</p></div>
<div class="panel"><h2>Capacity Comparison</h2>
<p>Windows reported: <b>{human_bytes(result.capacity_reported_bytes)}</b></p>
<p>Advertised input: <b>{human_bytes(result.advertised_bytes) if result.advertised_bytes else 'N/A'}</b></p>
<p>Estimated authentic usable capacity: <b class="green">{human_bytes(result.estimated_valid_capacity_bytes)}</b></p>
<p>Corruption start offset: <b class="red">{human_bytes(result.corruption_start_offset) if result.first_corruption_block else 'N/A'}</b></p></div>
</div>
<div class="panel" style="margin-top:8px"><h2>Storage Map</h2>
<div class="tiny">Green = verified/authentic range | Red = corrupted/failed range | Grey = untested/reported capacity</div>
<div class="map"><div class="seg seg-ok">VERIFIED<br>{human_bytes(result.verified_bytes)}</div><div class="seg seg-bad">CORRUPTED / FAILED<br>{human_bytes(failed_bytes)}</div><div class="seg seg-untested">UNTESTED REPORTED CAPACITY<br>{human_bytes(max(0, cap - result.processed_bytes))}</div></div>
<div class="legend"><span><i class="dot okdot"></i>Verified ranges</span><span><i class="dot baddot"></i>Corrupted / failed ranges</span><span><i class="dot graydot"></i>Untested reported capacity</span></div></div>
<div class="grid middle">
<div class="panel"><h2>Read/Write Verification</h2>
<p>Blocks written: {result.blocks_tested}</p><p>Processed blocks: {result.processed_blocks}</p><p>Verified blocks: {result.verified_blocks}</p><p>Corrupted blocks: <b class="bad">{result.corrupted_blocks}</b></p>
<p>Read failures: {result.read_failures}</p><p>Write failures: {result.write_failures}</p><p>Corruption percentage: {result.corruption_percent:.2f}%</p></div>
<div class="panel"><h2>Key Findings</h2><ul>{issues}</ul></div>
<div class="panel"><h2>Visual Corruption Evidence</h2><div class="evidence-icons">
<div><b>Corrupted Files</b><br>{result.corrupted_blocks} corrupted blocks</div><div><b>Broken Photos</b><br>SHA256 mismatch evidence</div>
<div><b>Read/Write Errors</b><br>{result.read_failures + result.write_failures} I/O failures</div><div><b>Damaged Sectors</b><br>{result.failed_blocks} failed blocks</div>
</div></div></div>
<div class="grid bottom">
<div class="panel"><h2>Verified Ranges</h2><table><tr><th>Start Block</th><th>End Block</th><th>Start</th><th>End</th><th>Size</th></tr>{self.html_table_rows_for_ranges(verified_ranges_raw)}</table></div>
<div class="panel"><h2>Failed / Corrupted Ranges</h2><table><tr><th>Start Block</th><th>End Block</th><th>Start</th><th>End</th><th>Size</th></tr>{self.html_table_rows_for_ranges(failed_ranges_raw)}</table></div>
<div class="panel"><h2>Corruption Ranges</h2><table><tr><th>Start Block</th><th>End Block</th><th>Start</th><th>End</th><th>Size</th></tr>{self.html_table_rows_for_ranges(corruption_ranges_raw)}</table></div>
</div>
<div class="panel" style="margin-top:8px"><h2>SHA256 Mismatch Evidence</h2><table><tr><th>Block</th><th>Offset</th><th>Expected SHA256</th><th>Actual / Evidence Details</th><th>Result</th></tr>{mismatch_rows}</table></div>
<div class="grid bottom">
<div class="panel"><h2>Live Activity Log Preview</h2><pre>{log_preview}</pre></div>
<div class="panel"><h2>Risk Indicators</h2><ul>{risk_indicators}</ul><h2 style="margin-top:12px">Speed Drops</h2><ul>{speed_drops}</ul></div>
<div class="panel"><h2>Forensic Analysis Summary</h2><p>{html.escape(forensic_summary)}</p>
<p>Device metadata:</p><pre>{html.escape(json.dumps(result.disk_metadata or {}, indent=2))}</pre></div>
</div>
<div class="panel" style="margin-top:8px"><h2>Block Report Preview</h2><table><tr><th>#</th><th>Offset</th><th>Size</th><th>Write</th><th>Verify</th><th>Write MB/s</th><th>Read MB/s</th><th>Error</th></tr>{block_rows}</table></div>
{self.html_health_section(result.health_diagnostics)}
<div class="warning" style="margin-top:8px"><h2>FINAL WARNING</h2><p>{html.escape(result.conclusion or 'N/A')}</p><strong>{html.escape(warning_text)}</strong></div>
<div class="footer-note">Generated by {APP_NAME} v{APP_VERSION}. TXT, JSON, CSV, HTML, and optional PDF reports preserve the same scan evidence without modifying scan logic.</div>
</div></div></body></html>"""


class CyberStorageVerifierApp(tk.Tk):
    def __init__(self):
        super().__init__()
        self.title(f"{APP_NAME} v{APP_VERSION}")
        self.geometry("1360x860")
        self.minsize(1120, 740)
        self.configure(bg=CYBER_BG)
        self.log_queue = queue.Queue()
        self.progress_queue = queue.Queue()
        self.metric_queue = queue.Queue()
        self.health_queue = queue.Queue()
        self.scan_thread = None
        self.health_thread = None
        self.drive_health_thread = None
        self.scanner = None
        self.health_runner = None
        self.last_health_result = None
        self.drive_health_snapshots = []
        self.selected_drive_health_root = ""
        self.drive_health_loading = False
        self.drive_health_card_widgets = {}
        self.drive_detail_windows = {}
        self.drive_display_map = {}
        self.drive_identity_map = {}
        self.drive_refresh_queue = queue.Queue()
        self.drive_refresh_thread = None
        self.drive_refresh_generation = 0
        self.last_result = None
        self.settings = ScannerSettings()
        self.resume_session_path = None
        self.setup_logging()
        self.runtime_info = check_packaged_runtime()
        self.apply_app_icon()
        self.load_app_settings()
        self.setup_style()
        self.create_ui()
        self.refresh_drives()
        self.refresh_sessions()
        self.refresh_history()
        self.after(450, self.refresh_all_drive_health)
        self.after(100, self.process_queues)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

    def load_app_settings(self):
        try:
            settings_path = ensure_reports_dir() / "app_settings.json"
            if settings_path.exists():
                data = json.loads(settings_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    for key, value in data.items():
                        if hasattr(self.settings, key):
                            setattr(self.settings, key, value)
        except Exception:
            logging.exception("Failed to load app settings")

    def save_app_settings(self):
        try:
            settings_path = ensure_reports_dir() / "app_settings.json"
            settings_path.write_text(json.dumps(asdict(self.settings), indent=2), encoding="utf-8")
        except Exception:
            logging.exception("Failed to save app settings")

    def setup_logging(self):
        reports_dir = ensure_reports_dir()
        log_path = reports_dir / LOG_FILE_NAME
        try:
            logging.basicConfig(
                filename=str(log_path),
                level=logging.INFO,
                format="%(asctime)s %(levelname)s %(message)s",
                force=True,
            )
            logging.info("Logging initialized at %s", log_path)
        except Exception:
            fallback_dir = Path(tempfile.gettempdir()) / REPORT_DIR_NAME
            fallback_dir.mkdir(parents=True, exist_ok=True)
            fallback_path = fallback_dir / LOG_FILE_NAME
            logging.basicConfig(
                filename=str(fallback_path),
                level=logging.INFO,
                format="%(asctime)s %(levelname)s %(message)s",
                force=True,
            )
            logging.warning("Primary log path unavailable; using %s", fallback_path)

    def apply_app_icon(self):
        try:
            icon_path = Path(APP_ICON_PATH)
            if icon_path.is_file():
                self.iconbitmap(str(icon_path))
                logging.info("Application icon loaded from %s", icon_path)
            else:
                logging.info("Application icon not found at %s", icon_path)
        except Exception as exc:
            logging.info("Application icon could not be applied: %s", exc)

    def setup_style(self):
        self.style = ttk.Style()
        try:
            self.style.theme_use("clam")
        except Exception:
            pass
        try:
            self.tk.call("tk", "scaling", max(1.0, float(self.tk.call("tk", "scaling"))))
        except Exception:
            pass

        self.option_add("*TCombobox*Listbox.background", INPUT_BG)
        self.option_add("*TCombobox*Listbox.foreground", INPUT_FG)
        self.option_add("*TCombobox*Listbox.selectBackground", INPUT_SELECT_BG)
        self.option_add("*TCombobox*Listbox.selectForeground", INPUT_SELECT_FG)
        self.option_add("*TCombobox*Listbox.font", ("Segoe UI", 10))
        self.option_add("*TCombobox*Listbox.borderWidth", 1)
        self.option_add("*TCombobox*Listbox.relief", "solid")
        self.option_add("*Entry.background", INPUT_BG)
        self.option_add("*Entry.foreground", INPUT_FG)
        self.option_add("*Entry.insertBackground", CYBER_CYAN)
        self.option_add("*Text.background", "#07101D")
        self.option_add("*Text.foreground", CYBER_TEXT)
        self.option_add("*selectBackground", INPUT_SELECT_BG)
        self.option_add("*selectForeground", INPUT_SELECT_FG)

        self.style.configure("Cyber.TFrame", background=CYBER_BG)
        self.style.configure("Panel.TFrame", background=CYBER_PANEL)
        self.style.configure("Cyber.TNotebook", background=CYBER_BG, borderwidth=0)
        self.style.configure("Cyber.TNotebook.Tab", background=CYBER_PANEL_2, foreground=CYBER_TEXT, padding=(14, 8))
        self.style.map("Cyber.TNotebook.Tab", background=[("selected", CYBER_PANEL)], foreground=[("selected", CYBER_CYAN)])
        self.style.configure("Cyber.TLabel", background=CYBER_BG, foreground=CYBER_TEXT, font=("Segoe UI", 10))
        self.style.configure("Panel.TLabel", background=CYBER_PANEL, foreground=CYBER_TEXT, font=("Segoe UI", 10))
        self.style.configure("Muted.TLabel", background=CYBER_PANEL, foreground=CYBER_MUTED, font=("Segoe UI", 9))
        self.style.configure(
            "Cyber.TButton",
            background=CYBER_PANEL_2,
            foreground=CYBER_TEXT,
            bordercolor=CYBER_BORDER,
            lightcolor=CYBER_BORDER,
            darkcolor=CYBER_BG,
            font=("Segoe UI Semibold", 10),
            padding=7,
        )
        self.style.map(
            "Cyber.TButton",
            background=[("disabled", INPUT_DISABLED_BG), ("pressed", INPUT_BG_FOCUS), ("active", "#142A46")],
            foreground=[("disabled", INPUT_DISABLED_FG), ("pressed", INPUT_FG), ("active", CYBER_CYAN)],
            bordercolor=[("focus", INPUT_BORDER_FOCUS), ("active", CYBER_CYAN), ("disabled", "#202A36")],
        )
        self.style.configure("Neon.Horizontal.TProgressbar", troughcolor="#07101D", background=CYBER_CYAN, bordercolor=CYBER_BORDER)
        self.style.configure(
            "Cyber.TCombobox",
            fieldbackground=INPUT_BG,
            background=INPUT_BG,
            foreground=INPUT_FG,
            selectbackground=INPUT_SELECT_BG,
            selectforeground=INPUT_SELECT_FG,
            insertcolor=CYBER_CYAN,
            arrowcolor=CYBER_CYAN,
            bordercolor=INPUT_BORDER,
            lightcolor=INPUT_BORDER,
            darkcolor=CYBER_BG,
            relief="flat",
            borderwidth=1,
            arrowsize=16,
            padding=(10, 7, 8, 7),
            font=("Segoe UI Semibold", 10),
        )
        self.style.map(
            "Cyber.TCombobox",
            fieldbackground=[
                ("disabled", INPUT_DISABLED_BG),
                ("readonly", INPUT_BG),
                ("focus", INPUT_BG_FOCUS),
                ("active", INPUT_BG_HOVER),
            ],
            background=[
                ("disabled", INPUT_DISABLED_BG),
                ("pressed", INPUT_BG_FOCUS),
                ("focus", INPUT_BG_FOCUS),
                ("active", INPUT_BG_HOVER),
                ("readonly", INPUT_BG),
            ],
            foreground=[
                ("disabled", INPUT_DISABLED_FG),
                ("readonly", INPUT_FG),
                ("focus", "#FFFFFF"),
                ("active", "#FFFFFF"),
            ],
            selectbackground=[("readonly", INPUT_SELECT_BG), ("focus", INPUT_SELECT_BG)],
            selectforeground=[("readonly", INPUT_SELECT_FG), ("focus", INPUT_SELECT_FG)],
            arrowcolor=[("disabled", INPUT_DISABLED_FG), ("pressed", "#FFFFFF"), ("focus", "#FFFFFF"), ("active", CYBER_GREEN), ("readonly", CYBER_CYAN)],
            bordercolor=[("disabled", "#202A36"), ("pressed", CYBER_GREEN), ("focus", INPUT_BORDER_FOCUS), ("active", CYBER_CYAN), ("readonly", INPUT_BORDER)],
            lightcolor=[("focus", INPUT_BORDER_FOCUS), ("active", CYBER_CYAN)],
            darkcolor=[("focus", INPUT_BORDER_FOCUS), ("active", CYBER_CYAN)],
        )
        self.style.configure(
            "Cyber.Vertical.TScrollbar",
            background=CYBER_PANEL_2,
            troughcolor="#07101D",
            arrowcolor=CYBER_CYAN,
            bordercolor=CYBER_BORDER,
            lightcolor=CYBER_BORDER,
            darkcolor=CYBER_BG,
        )
        self.style.map(
            "Cyber.Vertical.TScrollbar",
            background=[("active", INPUT_BG_HOVER), ("pressed", INPUT_BG_FOCUS), ("disabled", INPUT_DISABLED_BG)],
            arrowcolor=[("active", "#FFFFFF"), ("pressed", CYBER_GREEN), ("disabled", INPUT_DISABLED_FG)],
        )

    def create_ui(self):
        self.grid_columnconfigure(0, weight=1)
        self.grid_rowconfigure(1, weight=1)
        header = tk.Frame(self, bg=CYBER_BG, padx=22, pady=14)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        self.header_title = tk.Label(header, text="CYBER STORAGE VERIFIER", bg=CYBER_BG, fg=CYBER_CYAN, font=("Consolas", 26, "bold"))
        self.header_title.grid(row=0, column=0, sticky="w")
        subtitle = tk.Label(header, text="Counterfeit capacity | Integrity validation | Metadata inspection | Resumable block verification", bg=CYBER_BG, fg=CYBER_MUTED, font=("Segoe UI", 11))
        subtitle.grid(row=1, column=0, sticky="w")
        self.header_status = tk.Label(header, text="READY", bg=CYBER_BG, fg=CYBER_GREEN, font=("Consolas", 12, "bold"))
        self.header_status.grid(row=0, column=1, sticky="e", padx=10)

        self.notebook = ttk.Notebook(self, style="Cyber.TNotebook")
        self.notebook.grid(row=1, column=0, sticky="nsew", padx=16, pady=(0, 16))
        self.tabs = {}
        for name in ("Dashboard", "Scan Controls", "Active Scan", "Device Metadata", "Findings", "Reports", "Scan History", "Health History", "Settings", "Storage Health & Diagnostics", "Help Center"):
            frame = tk.Frame(self.notebook, bg=CYBER_BG)
            self.tabs[name] = frame
            self.notebook.add(frame, text=name)
        self.create_dashboard_tab()
        self.create_controls_tab()
        self.create_active_scan_tab()
        self.create_metadata_tab()
        self.create_findings_tab()
        self.create_reports_tab()
        self.create_history_tab()
        self.create_health_history_tab()
        self.create_settings_tab()
        self.create_health_diagnostics_tab()
        self.create_help_tab()
        self.bind_keyboard_shortcuts()

    def make_panel(self, parent):
        return tk.Frame(parent, bg=CYBER_PANEL, highlightbackground=CYBER_BORDER, highlightcolor=CYBER_CYAN, highlightthickness=1, bd=0)

    def section_title(self, parent, text):
        return tk.Label(parent, text=text, bg=CYBER_PANEL, fg=CYBER_CYAN, font=("Consolas", 12, "bold"))

    def neon_entry(self, parent, variable):
        entry = tk.Entry(
            parent,
            textvariable=variable,
            bg=INPUT_BG,
            fg=INPUT_FG,
            disabledbackground=INPUT_DISABLED_BG,
            disabledforeground=INPUT_DISABLED_FG,
            insertbackground=CYBER_CYAN,
            selectbackground=INPUT_SELECT_BG,
            selectforeground=INPUT_SELECT_FG,
            relief="flat",
            highlightthickness=1,
            highlightbackground=INPUT_BORDER,
            highlightcolor=INPUT_BORDER_FOCUS,
            font=("Segoe UI Semibold", 10),
            bd=0,
        )
        self.bind_input_glow(entry)
        return entry

    def cyber_combo(self, parent, variable=None, values=None, state="readonly"):
        combo = ttk.Combobox(
            parent,
            values=values or (),
            textvariable=variable,
            style="Cyber.TCombobox",
            state=state,
            font=("Segoe UI Semibold", 10),
        )
        combo.configure(takefocus=True)
        self.bind_combo_glow(combo)
        return combo

    def cyber_checkbutton(self, parent, text, variable):
        return tk.Checkbutton(
            parent,
            text=text,
            variable=variable,
            bg=CYBER_PANEL,
            fg=INPUT_FG,
            disabledforeground=INPUT_DISABLED_FG,
            selectcolor=INPUT_BG,
            activebackground=CYBER_PANEL,
            activeforeground="#FFFFFF",
            highlightthickness=1,
            highlightbackground=CYBER_PANEL,
            highlightcolor=INPUT_BORDER_FOCUS,
            font=("Segoe UI", 10),
            bd=0,
        )

    def bind_input_glow(self, widget):
        def focus_in(_event):
            widget.configure(bg=INPUT_BG_FOCUS, highlightbackground=INPUT_BORDER_FOCUS)

        def focus_out(_event):
            widget.configure(bg=INPUT_BG, highlightbackground=INPUT_BORDER)

        def enter(_event):
            if str(widget.cget("state")) != "disabled" and widget.focus_get() is not widget:
                widget.configure(bg=INPUT_BG_HOVER, highlightbackground=CYBER_CYAN)

        def leave(_event):
            if str(widget.cget("state")) != "disabled" and widget.focus_get() is not widget:
                widget.configure(bg=INPUT_BG, highlightbackground=INPUT_BORDER)

        widget.bind("<FocusIn>", focus_in, add="+")
        widget.bind("<FocusOut>", focus_out, add="+")
        widget.bind("<Enter>", enter, add="+")
        widget.bind("<Leave>", leave, add="+")

    def bind_combo_glow(self, combo):
        def set_hover(_event=None):
            if str(combo.cget("state")) != "disabled":
                combo.state(["active"])

        def clear_hover(_event=None):
            if str(combo.cget("state")) != "disabled":
                combo.state(["!active"])

        def focus_in(_event=None):
            if str(combo.cget("state")) != "disabled":
                combo.state(["focus"])

        def focus_out(_event=None):
            if str(combo.cget("state")) != "disabled":
                combo.state(["!focus", "!active"])

        combo.bind("<Enter>", set_hover, add="+")
        combo.bind("<Leave>", clear_hover, add="+")
        combo.bind("<FocusIn>", focus_in, add="+")
        combo.bind("<FocusOut>", focus_out, add="+")

    def create_dashboard_tab(self):
        tab = self.tabs["Dashboard"]
        tab.grid_columnconfigure(0, weight=1)
        cards = tk.Frame(tab, bg=CYBER_BG)
        cards.grid(row=0, column=0, sticky="ew", padx=8, pady=8)
        for i in range(5):
            cards.grid_columnconfigure(i, weight=1)
        self.cards = {}
        specs = [
            ("Selected Drive", "None", CYBER_CYAN),
            ("Reported Capacity", "Unknown", CYBER_PURPLE),
            ("Free Space", "Unknown", CYBER_GREEN),
            ("Test Coverage", "0%", CYBER_YELLOW),
            ("Current Phase", "Idle", CYBER_CYAN),
            ("ETA", "Unknown", CYBER_MUTED),
            ("Write Speed", "0 MB/s", CYBER_YELLOW),
            ("Read Speed", "0 MB/s", CYBER_BLUE),
            ("Processed", "0 B", CYBER_CYAN),
            ("Verified", "0 B", CYBER_GREEN),
            ("Corrupted", "0 B", CYBER_RED),
            ("Corrupted Blocks", "0", CYBER_RED),
            ("Failed Blocks", "0", CYBER_ORANGE),
            ("Read Failures", "0", CYBER_ORANGE),
            ("Current Block", "0 / 0", CYBER_CYAN),
            ("Risk Score", "0 / 100", CYBER_GREEN),
        ]
        for idx, (title, value, color) in enumerate(specs):
            card = self.make_card(cards, title, value, color)
            card.grid(row=idx // 5, column=idx % 5, sticky="ew", padx=6, pady=6)
            self.cards[title] = card
        lower = self.make_panel(tab)
        lower.grid(row=1, column=0, sticky="nsew", padx=8, pady=8)
        tab.grid_rowconfigure(1, weight=1)
        lower.grid_columnconfigure(0, weight=1)
        lower.grid_rowconfigure(1, weight=1)
        self.section_title(lower, "LIVE ACTIVITY LOG").grid(row=0, column=0, sticky="w", padx=14, pady=(12, 8))
        self.log_text = self.make_text(lower, height=20)
        self.log_text.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))

    def make_card(self, parent, title, value, accent):
        frame = tk.Frame(parent, bg=CYBER_PANEL, highlightbackground=CYBER_BORDER, highlightthickness=1, padx=12, pady=10)
        title_lbl = tk.Label(frame, text=title.upper(), bg=CYBER_PANEL, fg=CYBER_MUTED, font=("Segoe UI", 8, "bold"))
        title_lbl.pack(anchor="w")
        value_lbl = tk.Label(frame, text=value, bg=CYBER_PANEL, fg=accent, font=("Consolas", 14, "bold"), wraplength=210, justify="left")
        value_lbl.pack(anchor="w", pady=(5, 0))
        frame.value_label = value_lbl
        return frame

    def create_controls_tab(self):
        tab = self.tabs["Scan Controls"]
        tab.grid_columnconfigure(0, weight=1)
        panel = self.make_panel(tab)
        panel.grid(row=0, column=0, sticky="new", padx=8, pady=8)
        panel.grid_columnconfigure(1, weight=1)
        r = 0
        self.section_title(panel, "SCAN CONTROLS").grid(row=r, column=0, columnspan=3, sticky="w", padx=18, pady=(18, 12))
        r += 1
        tk.Label(panel, text="Target Drive / Path", bg=CYBER_PANEL, fg=CYBER_MUTED).grid(row=r, column=0, sticky="w", padx=18, pady=5)
        self.drive_var = tk.StringVar()
        self.drive_combo = self.cyber_combo(panel, variable=self.drive_var)
        self.drive_combo.grid(row=r, column=1, sticky="ew", padx=8, pady=5, ipady=4)
        self.drive_combo.bind("<<ComboboxSelected>>", lambda _event: self.update_drive_details_panel(), add="+")
        target_buttons = tk.Frame(panel, bg=CYBER_PANEL)
        target_buttons.grid(row=r, column=2, sticky="ew", padx=18, pady=5)
        target_buttons.grid_columnconfigure((0, 1), weight=1)
        ttk.Button(target_buttons, text="Browse", style="Cyber.TButton", command=self.browse_path).grid(row=0, column=0, sticky="ew", padx=(0, 4))
        ttk.Button(target_buttons, text="Refresh", style="Cyber.TButton", command=self.refresh_drives).grid(row=0, column=1, sticky="ew", padx=(4, 0))
        r += 1
        self.drive_details_var = tk.StringVar(value="Drive details will appear after discovery.")
        tk.Label(
            panel,
            textvariable=self.drive_details_var,
            bg=INPUT_BG,
            fg=INPUT_FG,
            font=("Consolas", 9),
            justify="left",
            anchor="w",
            wraplength=1000,
            padx=10,
            pady=8,
            highlightbackground=INPUT_BORDER,
            highlightthickness=1,
        ).grid(row=r, column=0, columnspan=3, sticky="ew", padx=18, pady=(0, 10))
        r += 1
        tk.Label(panel, text="Advertised GB", bg=CYBER_PANEL, fg=CYBER_MUTED).grid(row=r, column=0, sticky="w", padx=18, pady=5)
        self.advertised_var = tk.StringVar(value="")
        self.neon_entry(panel, self.advertised_var).grid(row=r, column=1, sticky="ew", padx=8, pady=5)
        r += 1
        tk.Label(panel, text="Test Size MB", bg=CYBER_PANEL, fg=CYBER_MUTED).grid(row=r, column=0, sticky="w", padx=18, pady=5)
        self.test_size_var = tk.StringVar(value="AUTO")
        self.neon_entry(panel, self.test_size_var).grid(row=r, column=1, sticky="ew", padx=8, pady=5)
        r += 1
        tk.Label(panel, text="Block Size MB", bg=CYBER_PANEL, fg=CYBER_MUTED).grid(row=r, column=0, sticky="w", padx=18, pady=5)
        self.block_size_var = tk.StringVar(value="AUTO")
        self.neon_entry(panel, self.block_size_var).grid(row=r, column=1, sticky="ew", padx=8, pady=5)
        r += 1
        tk.Label(panel, text="Scan Mode", bg=CYBER_PANEL, fg=CYBER_MUTED).grid(row=r, column=0, sticky="w", padx=18, pady=5)
        self.scan_mode_var = tk.StringVar(value=self.settings.default_scan_mode)
        mode_combo = self.cyber_combo(panel, variable=self.scan_mode_var, values=SCAN_MODES)
        mode_combo.grid(row=r, column=1, sticky="ew", padx=8, pady=5, ipady=4)
        Tooltip(mode_combo, "Quick is lightweight; Balanced is the default; Deep and Full write much more data; Boundary targets common fake-capacity thresholds.")
        r += 1
        tk.Label(panel, text="Flush Policy", bg=CYBER_PANEL, fg=CYBER_MUTED).grid(row=r, column=0, sticky="w", padx=18, pady=5)
        self.flush_policy_var = tk.StringVar(value=self.settings.flush_policy)
        self.cyber_combo(panel, variable=self.flush_policy_var, values=FLUSH_POLICIES).grid(row=r, column=1, sticky="ew", padx=8, pady=5, ipady=4)
        r += 1
        self.recheck_all_var = tk.BooleanVar(value=False)
        self.cyber_checkbutton(panel, "Recheck all blocks when resuming", self.recheck_all_var).grid(row=r, column=1, sticky="w", padx=8, pady=5)
        r += 1
        buttons = tk.Frame(panel, bg=CYBER_PANEL)
        buttons.grid(row=r, column=0, columnspan=3, sticky="ew", padx=18, pady=14)
        for i in range(5):
            buttons.grid_columnconfigure(i, weight=1)
        self.scan_btn = ttk.Button(buttons, text="START SCAN", style="Cyber.TButton", command=self.start_scan)
        self.scan_btn.grid(row=0, column=0, sticky="ew", padx=4)
        Tooltip(self.scan_btn, "Start the selected scan mode. Deep and full scans may write large temporary test files.")
        self.resume_btn = ttk.Button(buttons, text="RESUME PREVIOUS SCAN", style="Cyber.TButton", command=self.resume_previous_scan)
        self.resume_btn.grid(row=0, column=1, sticky="ew", padx=4)
        Tooltip(self.resume_btn, "Continue a checkpointed session after cancellation, crash, or interruption.")
        self.pause_btn = ttk.Button(buttons, text="PAUSE", style="Cyber.TButton", command=self.pause_scan)
        self.pause_btn.grid(row=0, column=2, sticky="ew", padx=4)
        Tooltip(self.pause_btn, "Temporarily pause the active background scan without deleting the session.")
        self.continue_btn = ttk.Button(buttons, text="CONTINUE", style="Cyber.TButton", command=self.continue_scan)
        self.continue_btn.grid(row=0, column=3, sticky="ew", padx=4)
        Tooltip(self.continue_btn, "Resume a paused scan in the current application session.")
        self.cancel_btn = ttk.Button(buttons, text="CANCEL", style="Cyber.TButton", command=self.cancel_scan)
        self.cancel_btn.grid(row=0, column=4, sticky="ew", padx=4)
        Tooltip(self.cancel_btn, "Stop the scan and preserve checkpoint files for later resume.")
        r += 1
        emergency_btn = ttk.Button(panel, text="EMERGENCY STOP", style="Cyber.TButton", command=self.emergency_stop)
        emergency_btn.grid(row=r, column=0, columnspan=2, sticky="ew", padx=18, pady=(0, 16))
        Tooltip(emergency_btn, "Request an immediate stop. Use when a drive becomes unstable or disconnected.")
        help_btn = ttk.Button(panel, text="WHAT DOES THIS MODE DO?", style="Cyber.TButton", command=self.show_scan_mode_help)
        help_btn.grid(row=r, column=2, sticky="ew", padx=18, pady=(0, 16))
        Tooltip(help_btn, "Open a focused explanation for the currently selected scan mode.")

    def create_active_scan_tab(self):
        tab = self.tabs["Active Scan"]
        tab.grid_columnconfigure(0, weight=1)
        panel = self.make_panel(tab)
        panel.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        tab.grid_rowconfigure(0, weight=1)
        panel.grid_columnconfigure(1, weight=1)
        labels = [("Overall progress", "overall"), ("Write phase progress", "write"), ("Read verification progress", "read"), ("Current block progress", "block")]
        self.progress_vars = {}
        r = 0
        self.section_title(panel, "ACTIVE SCAN").grid(row=r, column=0, columnspan=2, sticky="w", padx=18, pady=(18, 12))
        r += 1
        for text, key in labels:
            tk.Label(panel, text=text, bg=CYBER_PANEL, fg=CYBER_MUTED).grid(row=r, column=0, sticky="w", padx=18, pady=8)
            var = tk.DoubleVar(value=0)
            self.progress_vars[key] = var
            ttk.Progressbar(panel, variable=var, maximum=100, style="Neon.Horizontal.TProgressbar").grid(row=r, column=1, sticky="ew", padx=18, pady=8)
            r += 1
        self.progress_label = tk.Label(panel, text="0%", bg=CYBER_PANEL, fg=CYBER_CYAN, font=("Consolas", 11, "bold"))
        self.progress_label.grid(row=r, column=1, sticky="w", padx=18, pady=8)
        r += 1
        self.warning_banner_var = tk.StringVar(value="")
        self.warning_banner = tk.Label(panel, textvariable=self.warning_banner_var, bg=CYBER_PANEL, fg=CYBER_RED, font=("Consolas", 11, "bold"), wraplength=900, justify="left")
        self.warning_banner.grid(row=r, column=0, columnspan=2, sticky="ew", padx=18, pady=(4, 8))
        r += 1
        self.scan_viz = tk.Canvas(panel, height=96, bg="#07101D", highlightthickness=1, highlightbackground=CYBER_BORDER)
        self.scan_viz.grid(row=r, column=0, columnspan=2, sticky="ew", padx=18, pady=8)
        r += 1
        self.processed_summary_var = tk.StringVar(value="Processed: 0 B | Verified: 0 B | Corrupted: 0 B")
        tk.Label(panel, textvariable=self.processed_summary_var, bg=CYBER_PANEL, fg=CYBER_TEXT, font=("Consolas", 11)).grid(row=r, column=0, columnspan=2, sticky="w", padx=18, pady=(4, 8))
        r += 1
        self.speed_trend_var = tk.StringVar(value="Speed trend: idle")
        tk.Label(panel, textvariable=self.speed_trend_var, bg=CYBER_PANEL, fg=CYBER_TEXT, font=("Consolas", 11)).grid(row=r, column=0, columnspan=2, sticky="w", padx=18, pady=12)

    def create_metadata_tab(self):
        tab = self.tabs["Device Metadata"]
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        panel = self.make_panel(tab)
        panel.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)
        self.section_title(panel, "DEVICE SNAPSHOT").grid(row=0, column=0, sticky="w", padx=14, pady=(12, 8))
        self.device_text = self.make_text(panel)
        self.device_text.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
        self.set_text(self.device_text, "Select a drive and start a scan...\n")

    def create_findings_tab(self):
        tab = self.tabs["Findings"]
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)
        panel = self.make_panel(tab)
        panel.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        panel.grid_columnconfigure(0, weight=1)
        panel.grid_rowconfigure(1, weight=1)
        top = tk.Frame(panel, bg=CYBER_PANEL)
        top.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 8))
        top.grid_columnconfigure(0, weight=1)
        self.section_title(top, "FINDINGS").grid(row=0, column=0, sticky="w")
        ttk.Button(top, text="WHAT DOES THIS MEAN?", style="Cyber.TButton", command=self.show_context_help).grid(row=0, column=1, sticky="e")
        self.findings_text = self.make_text(panel)
        self.findings_text.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))

    def create_reports_tab(self):
        tab = self.tabs["Reports"]
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        toolbar = self.make_panel(tab)
        toolbar.grid(row=0, column=0, sticky="ew", padx=8, pady=8)
        toolbar.grid_columnconfigure(tuple(range(6)), weight=1)
        self.section_title(toolbar, "FORENSIC REPORT DASHBOARD").grid(row=0, column=0, columnspan=6, sticky="w", padx=14, pady=(12, 8))
        ttk.Button(toolbar, text="Open Text Report", style="Cyber.TButton", command=lambda: self.open_path("report_path")).grid(row=1, column=0, sticky="ew", padx=6, pady=(0, 12))
        ttk.Button(toolbar, text="Open JSON Report", style="Cyber.TButton", command=lambda: self.open_path("json_report_path")).grid(row=1, column=1, sticky="ew", padx=6, pady=(0, 12))
        ttk.Button(toolbar, text="Open CSV Block Report", style="Cyber.TButton", command=lambda: self.open_path("csv_report_path")).grid(row=1, column=2, sticky="ew", padx=6, pady=(0, 12))
        ttk.Button(toolbar, text="Open HTML Report", style="Cyber.TButton", command=lambda: self.open_path("html_report_path")).grid(row=1, column=3, sticky="ew", padx=6, pady=(0, 12))
        ttk.Button(toolbar, text="Open PDF Report", style="Cyber.TButton", command=self.open_pdf_report).grid(row=1, column=4, sticky="ew", padx=6, pady=(0, 12))
        ttk.Button(toolbar, text="Open Reports Folder", style="Cyber.TButton", command=lambda: self.open_file(str(ensure_reports_dir()))).grid(row=1, column=5, sticky="ew", padx=6, pady=(0, 12))

        outer = self.make_panel(tab)
        outer.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        outer.grid_columnconfigure(0, weight=1)
        outer.grid_rowconfigure(0, weight=1)
        canvas = tk.Canvas(outer, bg=CYBER_BG, highlightthickness=0)
        scroll = ttk.Scrollbar(outer, orient="vertical", command=canvas.yview, style="Cyber.Vertical.TScrollbar")
        self.reports_dashboard = tk.Frame(canvas, bg=CYBER_BG)
        self.reports_canvas_window = canvas.create_window((0, 0), window=self.reports_dashboard, anchor="nw")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        self.bind_mousewheel(canvas, canvas)
        self.bind_mousewheel(self.reports_dashboard, canvas)
        self.reports_canvas = canvas

        def resize_dashboard(_event=None):
            canvas.itemconfigure(self.reports_canvas_window, width=canvas.winfo_width())
            canvas.configure(scrollregion=canvas.bbox("all"))

        self.reports_dashboard.bind("<Configure>", resize_dashboard)
        canvas.bind("<Configure>", resize_dashboard)
        self.build_report_dashboard_widgets()
        self.refresh_report_dashboard()

    def report_panel(self, parent, title):
        panel = self.make_panel(parent)
        self.section_title(panel, title).pack(anchor="w", padx=12, pady=(10, 6))
        return panel

    def report_metric(self, parent, title, value="N/A", color=CYBER_CYAN):
        frame = self.make_card(parent, title, value, color)
        return frame

    def build_report_dashboard_widgets(self):
        root = self.reports_dashboard
        root.grid_columnconfigure((0, 1, 2, 3, 4), weight=1)
        self.report_cards = {}
        metrics = [
            ("Selected Drive", CYBER_CYAN),
            ("Reported Capacity", CYBER_PURPLE),
            ("Free Space", CYBER_GREEN),
            ("Test Coverage", CYBER_YELLOW),
            ("Current Phase", CYBER_CYAN),
            ("Risk Score", CYBER_RED),
            ("Processed", CYBER_CYAN),
            ("Verified", CYBER_GREEN),
            ("Corrupted Bytes", CYBER_RED),
            ("Failed Blocks", CYBER_ORANGE),
        ]
        for idx, (title, color) in enumerate(metrics):
            card = self.report_metric(root, title, "N/A", color)
            card.grid(row=0 + idx // 5, column=idx % 5, sticky="ew", padx=5, pady=5)
            self.report_cards[title] = card

        summary = self.report_panel(root, "SCAN SUMMARY")
        summary.grid(row=2, column=0, sticky="nsew", padx=5, pady=5)
        self.report_summary_text = self.make_text(summary, height=9)
        self.report_summary_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        result_panel = self.report_panel(root, "FINAL RESULT")
        result_panel.grid(row=2, column=1, columnspan=2, sticky="nsew", padx=5, pady=5)
        self.report_result_text = self.make_text(result_panel, height=9)
        self.report_result_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        capacity = self.report_panel(root, "CAPACITY COMPARISON")
        capacity.grid(row=2, column=3, sticky="nsew", padx=5, pady=5)
        self.report_capacity_text = self.make_text(capacity, height=9)
        self.report_capacity_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        findings = self.report_panel(root, "KEY FINDINGS")
        findings.grid(row=2, column=4, sticky="nsew", padx=5, pady=5)
        self.report_findings_text = self.make_text(findings, height=9)
        self.report_findings_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        storage = self.report_panel(root, "STORAGE MAP")
        storage.grid(row=3, column=0, columnspan=5, sticky="ew", padx=5, pady=5)
        self.report_storage_canvas = tk.Canvas(storage, height=130, bg="#07101D", highlightthickness=1, highlightbackground=CYBER_BORDER)
        self.report_storage_canvas.pack(fill="x", padx=12, pady=(0, 12))

        verification = self.report_panel(root, "READ/WRITE VERIFICATION")
        verification.grid(row=4, column=0, sticky="nsew", padx=5, pady=5)
        self.report_verification_text = self.make_text(verification, height=12)
        self.report_verification_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        evidence = self.report_panel(root, "SHA256 MISMATCH EVIDENCE")
        evidence.grid(row=4, column=1, columnspan=3, sticky="nsew", padx=5, pady=5)
        self.report_evidence_text = self.make_text(evidence, height=12)
        self.report_evidence_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        visual = self.report_panel(root, "VISUAL CORRUPTION / RISK INDICATORS")
        visual.grid(row=4, column=4, sticky="nsew", padx=5, pady=5)
        self.report_risk_text = self.make_text(visual, height=12)
        self.report_risk_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        log_panel = self.report_panel(root, "LIVE ACTIVITY LOG PREVIEW")
        log_panel.grid(row=5, column=0, columnspan=2, sticky="nsew", padx=5, pady=5)
        self.report_log_preview = self.make_text(log_panel, height=10)
        self.report_log_preview.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        ranges = self.report_panel(root, "VERIFIED / FAILED / CORRUPTION RANGES")
        ranges.grid(row=5, column=2, columnspan=2, sticky="nsew", padx=5, pady=5)
        self.report_ranges_text = self.make_text(ranges, height=10)
        self.report_ranges_text.pack(fill="both", expand=True, padx=12, pady=(0, 12))

        warning = self.make_panel(root)
        warning.grid(row=5, column=4, sticky="nsew", padx=5, pady=5)
        tk.Label(warning, text="FINAL WARNING", bg=CYBER_PANEL, fg=CYBER_RED, font=("Consolas", 18, "bold")).pack(anchor="center", padx=12, pady=(18, 8))
        self.report_warning_var = tk.StringVar(value="Run or open a scan report to review forensic evidence.")
        tk.Label(warning, textvariable=self.report_warning_var, bg="#240006", fg="#FFFFFF", font=("Consolas", 14, "bold"), wraplength=260, justify="center", padx=12, pady=14).pack(fill="x", padx=12, pady=(0, 18))

    def report_card_set(self, name, value, color=None):
        if hasattr(self, "report_cards") and name in self.report_cards:
            self.report_cards[name].value_label.config(text=value)
            if color:
                self.report_cards[name].value_label.config(fg=color)

    def refresh_report_dashboard(self):
        if not hasattr(self, "report_cards"):
            return
        res = self.last_result
        if not res:
            self.set_text(self.report_summary_text, "No scan report loaded yet.\nRun a scan or open a report after completion.")
            self.set_text(self.report_result_text, "Final result: N/A")
            self.set_text(self.report_capacity_text, "Capacity data: N/A")
            self.set_text(self.report_findings_text, "Findings: N/A")
            self.set_text(self.report_verification_text, "Verification data: N/A")
            self.set_text(self.report_evidence_text, "SHA256 mismatch evidence: N/A")
            self.set_text(self.report_risk_text, "Risk indicators: N/A")
            self.set_text(self.report_log_preview, "Live activity log preview: N/A")
            self.set_text(self.report_ranges_text, "Ranges: N/A")
            self.draw_report_storage_map(None)
            return

        risk_color = CYBER_RED if res.risk_score >= 70 or res.corrupted_blocks else CYBER_ORANGE if res.risk_score >= 30 else CYBER_GREEN
        self.report_card_set("Selected Drive", res.root or "N/A", CYBER_CYAN)
        self.report_card_set("Reported Capacity", human_bytes(res.capacity_reported_bytes), CYBER_PURPLE)
        self.report_card_set("Free Space", human_bytes(res.free_bytes), CYBER_GREEN)
        self.report_card_set("Test Coverage", f"{res.coverage_percent:.4f}%", CYBER_YELLOW)
        self.report_card_set("Current Phase", res.current_phase or res.status or "N/A", CYBER_CYAN)
        self.report_card_set("Risk Score", f"{res.risk_score} / 100", risk_color)
        self.report_card_set("Processed", human_bytes(res.processed_bytes), CYBER_CYAN)
        self.report_card_set("Verified", human_bytes(res.verified_bytes), CYBER_GREEN)
        self.report_card_set("Corrupted Bytes", human_bytes(res.corrupted_bytes), CYBER_RED)
        self.report_card_set("Failed Blocks", str(res.failed_blocks), CYBER_ORANGE)

        self.set_text(
            self.report_summary_text,
            "\n".join(
                [
                    f"Started: {res.started_at or 'N/A'}",
                    f"Completed: {res.completed_at or 'N/A'}",
                    f"Target: {res.root or 'N/A'}",
                    f"Session: {res.session_id or 'N/A'}",
                    f"Scan Interrupted: {'Yes' if res.scan_interrupted else 'No'}",
                    f"Interruption Reason: {res.interruption_reason or 'None'}",
                ]
            ),
        )
        self.set_text(
            self.report_result_text,
            "\n".join(
                [
                    f"Status: {res.status or 'N/A'}",
                    f"Finalization Reason: {res.finalization_reason or 'N/A'}",
                    f"Risk Score: {res.risk_score}/100",
                    "",
                    res.conclusion or "N/A",
                ]
            ),
        )
        self.set_text(
            self.report_capacity_text,
            "\n".join(
                [
                    f"Windows Reported Capacity: {human_bytes(res.capacity_reported_bytes)}",
                    f"Advertised Capacity Input: {human_bytes(res.advertised_bytes) if res.advertised_bytes else 'N/A'}",
                    f"Used Space: {human_bytes(res.used_bytes)}",
                    f"Free Space: {human_bytes(res.free_bytes)}",
                    f"Estimated Authentic Usable Capacity: {human_bytes(res.estimated_valid_capacity_bytes)}",
                    f"Corruption Start Offset: {human_bytes(res.corruption_start_offset) if res.first_corruption_block else 'N/A'}",
                ]
            ),
        )
        findings = []
        if res.issues:
            for issue in res.issues[:8]:
                findings.append(f"[{issue.severity}] {issue.title}")
                findings.append(f"  {issue.detail}")
        else:
            findings.append("No major suspicious findings were detected.")
        self.set_text(self.report_findings_text, "\n".join(findings))
        self.set_text(
            self.report_verification_text,
            "\n".join(
                [
                    f"Blocks Written: {res.blocks_tested}",
                    f"Processed Blocks: {res.processed_blocks}",
                    f"Verified Blocks: {res.verified_blocks}",
                    f"Failed Blocks: {res.failed_blocks}",
                    f"Verified Bytes: {human_bytes(res.verified_bytes)}",
                    f"Corrupted Bytes: {human_bytes(res.corrupted_bytes)}",
                    f"Failed Bytes: {human_bytes(res.failed_bytes)}",
                    f"Processed Bytes: {human_bytes(res.processed_bytes)}",
                    f"Read Speed: {res.read_mb_s:.2f} MB/s",
                    f"Write Speed: {res.write_mb_s:.2f} MB/s",
                    f"Speed Variation: {res.speed_variation_percent:.1f}%",
                    f"Read Failures: {res.read_failures}",
                    f"Write Failures: {res.write_failures}",
                    f"Corruption Percent: {res.corruption_percent:.2f}%",
                ]
            ),
        )
        mismatches = [b for b in (self.scanner.blocks if self.scanner else []) if b.verification_result == "corrupt"]
        evidence_lines = ["Block | Offset | Evidence"]
        evidence_lines += [
            f"{b.index + 1} | {human_bytes(b.offset)} | {(b.error_details or 'SHA256 mismatch')[:160]}"
            for b in mismatches[:80]
        ] or ["N/A"]
        self.set_text(self.report_evidence_text, "\n".join(evidence_lines))
        risk_lines = [
            "Visual evidence indicators:",
            f"- Corrupted files: {res.corrupted_blocks} corrupted blocks",
            f"- Read/write errors: {res.read_failures + res.write_failures}",
            f"- Damaged sectors: {res.failed_blocks} failed blocks",
            "",
            "Risk indicators:",
        ]
        risk_lines += [f"- {x}" for x in res.fake_capacity_indicators] or ["- N/A"]
        self.set_text(self.report_risk_text, "\n".join(risk_lines))
        self.set_text(self.report_log_preview, self.text_widget(self.log_text).get("1.0", tk.END).strip()[-4000:] or "N/A")
        self.set_text(self.report_ranges_text, self.format_report_ranges_for_ui(res))
        warning = "DO NOT TRUST THIS DEVICE WITH IMPORTANT DATA" if res.risk_score >= 70 or res.corrupted_blocks or res.failed_blocks else "Review coverage before trusting this device"
        self.report_warning_var.set(warning)
        self.draw_report_storage_map(res)

    def format_report_ranges_for_ui(self, res):
        blocks = self.scanner.blocks if self.scanner else []
        if not blocks:
            return "N/A"
        scanner = self.scanner
        sections = []
        for title, predicate in (
            ("VERIFIED RANGES", lambda b: b.verification_result == "ok"),
            ("FAILED / CORRUPTED RANGES", lambda b: b.verification_result in ("corrupt", "read_failed") or b.write_status == "failed"),
            ("CORRUPTION RANGES", lambda b: b.verification_result == "corrupt"),
        ):
            sections.append(title)
            ranges = scanner.block_ranges(predicate)
            if ranges:
                for item in ranges[:20]:
                    sections.append(f"  Blocks {item['start_block']}-{item['end_block']} | {item['human_start_offset']} to {item['human_end_offset']} | {item['human_size']}")
            else:
                sections.append("  N/A")
            sections.append("")
        return "\n".join(sections)

    def draw_report_storage_map(self, res):
        if not hasattr(self, "report_storage_canvas"):
            return
        c = self.report_storage_canvas
        c.delete("all")
        width = max(1, c.winfo_width() or 1000)
        pad = 24
        x = pad
        y = 42
        h = 42
        w = max(1, width - pad * 2)
        if not res:
            c.create_text(pad, 18, anchor="w", fill=CYBER_MUTED, font=("Consolas", 10), text="Storage map unavailable until a scan report exists.")
            c.create_rectangle(x, y, x + w, y + h, outline=CYBER_BORDER, fill="#111820")
            return
        cap = max(1, res.capacity_reported_bytes or res.test_size_bytes or res.processed_bytes or 1)
        verified_w = w * min(1.0, res.verified_bytes / cap)
        failed_w = w * min(1.0, max(res.failed_bytes, res.corrupted_bytes) / cap)
        if res.verified_bytes and verified_w < 8:
            verified_w = 8
        if max(res.failed_bytes, res.corrupted_bytes) and failed_w < 8:
            failed_w = 8
        if verified_w + failed_w > w:
            scale = w / (verified_w + failed_w)
            verified_w *= scale
            failed_w *= scale
        untested_w = max(0, w - verified_w - failed_w)
        c.create_text(x, 18, anchor="w", fill=CYBER_CYAN, font=("Consolas", 11, "bold"), text=f"STORAGE MAP - TEST COVERAGE {res.coverage_percent:.4f}% OF REPORTED CAPACITY")
        c.create_rectangle(x, y, x + verified_w, y + h, outline=CYBER_GREEN, fill="#0B6B31")
        c.create_text(x + verified_w / 2, y + h / 2, fill="white", font=("Consolas", 9, "bold"), text=f"VERIFIED\n{human_bytes(res.verified_bytes)}")
        x2 = x + verified_w
        c.create_rectangle(x2, y, x2 + failed_w, y + h, outline=CYBER_RED, fill="#790012")
        c.create_text(x2 + failed_w / 2, y + h / 2, fill="white", font=("Consolas", 9, "bold"), text=f"CORRUPTED / FAILED\n{human_bytes(max(res.failed_bytes, res.corrupted_bytes))}")
        x3 = x2 + failed_w
        c.create_rectangle(x3, y, x3 + untested_w, y + h, outline="#475569", fill="#202833")
        c.create_text(x3 + untested_w / 2, y + h / 2, fill="#E5E7EB", font=("Consolas", 9, "bold"), text=f"UNTESTED\n{human_bytes(max(0, cap - res.processed_bytes))}")
        c.create_text(x, y + h + 24, anchor="w", fill=CYBER_GREEN, font=("Consolas", 9), text="Green = verified/authentic range")
        c.create_text(x + 270, y + h + 24, anchor="w", fill=CYBER_RED, font=("Consolas", 9), text="Red = corrupted/failed range")
        c.create_text(x + 575, y + h + 24, anchor="w", fill=CYBER_MUTED, font=("Consolas", 9), text="Grey = untested/reported capacity")

    def create_history_tab(self):
        tab = self.tabs["Scan History"]
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        top = tk.Frame(tab, bg=CYBER_BG)
        top.grid(row=0, column=0, sticky="ew", padx=8, pady=8)
        ttk.Button(top, text="Refresh History", style="Cyber.TButton", command=self.refresh_history).pack(side="left", padx=(0, 8))
        ttk.Button(top, text="Discard Selected Session", style="Cyber.TButton", command=self.discard_selected_session).pack(side="left", padx=8)
        ttk.Button(top, text="Cleanup Old Temp Files", style="Cyber.TButton", command=self.cleanup_old_temp_files).pack(side="left", padx=8)
        self.history_text = self.make_text(tab)
        self.history_text.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self.session_var = tk.StringVar(value="")
        self.session_combo = self.cyber_combo(tab, variable=self.session_var)
        self.session_combo.grid(row=2, column=0, sticky="ew", padx=8, pady=(0, 8), ipady=4)

    def create_health_history_tab(self):
        tab = self.tabs["Health History"]
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(1, weight=1)
        top = tk.Frame(tab, bg=CYBER_BG)
        top.grid(row=0, column=0, sticky="ew", padx=8, pady=8)
        ttk.Button(top, text="Refresh Health History", style="Cyber.TButton", command=self.refresh_health_history).pack(side="left", padx=(0, 8))
        ttk.Button(top, text="Open Reports Folder", style="Cyber.TButton", command=lambda: self.open_file(str(ensure_reports_dir()))).pack(side="left", padx=8)
        self.health_history_text = self.make_text(tab)
        self.health_history_text.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        self.refresh_health_history()

    def create_health_diagnostics_tab(self):
        tab = self.tabs["Storage Health & Diagnostics"]
        tab.grid_columnconfigure(0, weight=1)
        tab.grid_rowconfigure(0, weight=1)

        self.health_tab_canvas = tk.Canvas(tab, bg=CYBER_BG, highlightthickness=0, bd=0)
        self.health_tab_scrollbar = ttk.Scrollbar(tab, orient="vertical", command=self.health_tab_canvas.yview, style="Cyber.Vertical.TScrollbar")
        self.health_tab_canvas.configure(yscrollcommand=self.health_tab_scrollbar.set)
        self.health_tab_canvas.grid(row=0, column=0, sticky="nsew")
        self.health_tab_scrollbar.grid(row=0, column=1, sticky="ns")
        body = tk.Frame(self.health_tab_canvas, bg=CYBER_BG)
        self.health_tab_body = body
        self.health_tab_window = self.health_tab_canvas.create_window((0, 0), window=body, anchor="nw")
        body.grid_columnconfigure(0, weight=1)
        body.bind("<Configure>", self._update_health_tab_scroll_region)
        self.health_tab_canvas.bind("<Configure>", self.on_health_tab_resize)
        self.bind_mousewheel(self.health_tab_canvas, self.health_tab_canvas)
        self.bind_mousewheel(body, self.health_tab_canvas)

        warning = self.make_panel(body)
        warning.grid(row=0, column=0, sticky="ew", padx=8, pady=(8, 6))
        warning.grid_columnconfigure(0, weight=1)
        tk.Label(
            warning,
            text="STORAGE HEALTH & DIAGNOSTICS",
            bg=CYBER_PANEL,
            fg=CYBER_CYAN,
            font=("Consolas", 16, "bold"),
        ).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 2))
        tk.Label(
            warning,
            text="Automatic read-only health overview for all detected storage devices. Diagnostics only: no repair, no formatting, no firmware operations, and no destructive disk actions.",
            bg=CYBER_PANEL,
            fg=INPUT_FG,
            font=("Segoe UI", 10),
            wraplength=1180,
            justify="left",
        ).grid(row=1, column=0, sticky="ew", padx=14, pady=(0, 12))

        summary = tk.Frame(body, bg=CYBER_BG)
        summary.grid(row=1, column=0, sticky="ew", padx=8, pady=6)
        self.drive_health_summary_frame = summary
        self.drive_health_summary_cards = {}
        self.drive_health_summary_items = []
        for idx, (title, value, color) in enumerate(
            [
                ("Total Drives", "0", CYBER_CYAN),
                ("Healthy", "0", CYBER_GREEN),
                ("Warning", "0", CYBER_YELLOW),
                ("Critical", "0", CYBER_RED),
                ("Unknown", "0", CYBER_BLUE),
            ]
        ):
            card = self.make_card(summary, title, value, color)
            card.grid(row=0, column=idx, sticky="ew", padx=4, pady=4)
            card.grid_propagate(False)
            card.configure(width=190, height=86)
            self.drive_health_summary_cards[title] = card
            self.drive_health_summary_items.append(card)

        dashboard_actions = self.make_panel(body)
        dashboard_actions.grid(row=2, column=0, sticky="ew", padx=8, pady=6)
        dashboard_actions.grid_columnconfigure(0, weight=1)
        dashboard_actions.grid_columnconfigure(1, weight=0)
        self.drive_health_status_var = tk.StringVar(value="Drive health dashboard is loading...")
        tk.Label(
            dashboard_actions,
            textvariable=self.drive_health_status_var,
            bg=CYBER_PANEL,
            fg=CYBER_CYAN,
            font=("Consolas", 11, "bold"),
            wraplength=760,
            justify="left",
        ).grid(row=0, column=0, sticky="w", padx=14, pady=12)
        btns = tk.Frame(dashboard_actions, bg=CYBER_PANEL)
        self.drive_health_dashboard_buttons_frame = btns
        btns.grid(row=0, column=1, sticky="e", padx=12, pady=8)
        self.drive_health_dashboard_buttons = []
        for idx, (label, command) in enumerate(
            [
                ("Refresh All Drives", self.refresh_all_drive_health),
                ("Rescan Selected Drive", self.rescan_selected_drive_health),
                ("Export Health Report", self.export_health_report),
            ]
        ):
            btn = ttk.Button(btns, text=label, style="Cyber.TButton", command=command)
            btn.grid(row=0, column=idx, sticky="ew", padx=4)
            Tooltip(btn, "Safe read-only dashboard action. No repair, format, firmware, or low-level disk operation is performed.")
            self.drive_health_dashboard_buttons.append(btn)

        dash = tk.Frame(body, bg=CYBER_BG)
        dash.grid(row=3, column=0, sticky="nsew", padx=8, pady=6)
        self.health_dashboard_region = dash
        dash.grid_columnconfigure(0, weight=3)
        dash.grid_columnconfigure(1, weight=2)
        dash.grid_rowconfigure(0, weight=1)

        cards_shell = tk.Frame(dash, bg=INPUT_BORDER, highlightbackground=INPUT_BORDER, highlightthickness=1)
        self.drive_health_cards_shell = cards_shell
        cards_shell.grid(row=0, column=0, sticky="nsew", padx=(0, 6))
        cards_shell.grid_columnconfigure(0, weight=1)
        cards_shell.grid_rowconfigure(0, weight=1)
        self.drive_health_canvas = tk.Canvas(cards_shell, bg=CYBER_BG, highlightthickness=0, bd=0, height=390)
        self.drive_health_scrollbar = ttk.Scrollbar(cards_shell, orient="vertical", command=self.drive_health_canvas.yview, style="Cyber.Vertical.TScrollbar")
        self.drive_health_canvas.configure(yscrollcommand=self.drive_health_scrollbar.set)
        self.drive_health_canvas.grid(row=0, column=0, sticky="nsew")
        self.drive_health_scrollbar.grid(row=0, column=1, sticky="ns")
        self.drive_health_grid = tk.Frame(self.drive_health_canvas, bg=CYBER_BG)
        self.drive_health_canvas_window = self.drive_health_canvas.create_window((0, 0), window=self.drive_health_grid, anchor="nw")
        self.drive_health_grid.bind("<Configure>", lambda _event: self.drive_health_canvas.configure(scrollregion=self.drive_health_canvas.bbox("all")))
        self.drive_health_canvas.bind("<Configure>", self._resize_drive_health_canvas_window)
        self.bind_mousewheel(self.drive_health_canvas, self.drive_health_canvas)
        self.bind_mousewheel(self.drive_health_grid, self.drive_health_canvas)

        details = self.make_panel(dash)
        self.drive_health_details_panel = details
        details.grid(row=0, column=1, sticky="nsew", padx=(6, 0))
        details.grid_columnconfigure(0, weight=1)
        details.grid_rowconfigure(1, weight=1)
        tk.Label(details, text="SELECTED DRIVE DETAILS", bg=CYBER_PANEL, fg=CYBER_CYAN, font=("Consolas", 12, "bold")).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 8))
        self.drive_health_details_text = self.make_text(details, height=18)
        self.drive_health_details_text.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
        self.set_text(self.drive_health_details_text, "Select a storage device card to view full health details.\n")

        cards = tk.Frame(body, bg=CYBER_BG)
        cards.grid(row=4, column=0, sticky="ew", padx=8, pady=6)
        self.manual_health_cards_frame = cards
        self.health_cards = {}
        self.manual_health_card_items = []
        health_specs = [
            ("Health Status", "Not Checked", CYBER_CYAN),
            ("SMART Status", "Not Checked", CYBER_PURPLE),
            ("Windows Health", "Not Checked", CYBER_BLUE),
            ("Temperature", "Unknown", CYBER_YELLOW),
            ("Wear / Age", "Unknown", CYBER_GREEN),
            ("Read Stability", "Not Checked", CYBER_CYAN),
            ("Health Risk Score", "0 / 100", CYBER_GREEN),
        ]
        for idx, (title, value, color) in enumerate(health_specs):
            card = self.make_card(cards, title, value, color)
            card.grid(row=0, column=idx, sticky="ew", padx=4, pady=4)
            card.grid_propagate(False)
            card.configure(width=190, height=86)
            self.health_cards[title] = card
            self.manual_health_card_items.append(card)

        actions = self.make_panel(body)
        actions.grid(row=5, column=0, sticky="ew", padx=8, pady=6)
        self.manual_health_actions_frame = actions
        self.manual_health_action_buttons = []
        buttons = [
            ("Refresh Health", self.refresh_health),
            ("Run SMART Check", self.run_health_smart),
            ("Run Windows Health Check", self.run_health_windows),
            ("Run Read-Only CHKDSK", self.run_health_chkdsk),
            ("Run Surface Read Stability Scan", self.run_health_surface),
            ("Cancel Health Diagnostic", self.cancel_health_diagnostic),
            ("Export Health Report", self.export_health_report),
        ]
        for idx, (label, command) in enumerate(buttons):
            btn = ttk.Button(actions, text=label, style="Cyber.TButton", command=command)
            btn.grid(row=0, column=idx, sticky="ew", padx=6, pady=12)
            Tooltip(btn, "Safe read-only diagnostic action. No repair, format, firmware, or low-level disk operation is performed.")
            self.manual_health_action_buttons.append(btn)

        output_panel = self.make_panel(body)
        output_panel.grid(row=6, column=0, sticky="nsew", padx=8, pady=(6, 8))
        output_panel.grid_columnconfigure(0, weight=1)
        output_panel.grid_rowconfigure(1, weight=1)
        top = tk.Frame(output_panel, bg=CYBER_PANEL)
        top.grid(row=0, column=0, sticky="ew", padx=14, pady=(12, 8))
        top.grid_columnconfigure(0, weight=1)
        self.health_status_var = tk.StringVar(value="Storage health diagnostics are idle.")
        tk.Label(top, textvariable=self.health_status_var, bg=CYBER_PANEL, fg=CYBER_CYAN, font=("Consolas", 12, "bold")).grid(row=0, column=0, sticky="w")
        self.health_progress_var = tk.DoubleVar(value=0)
        ttk.Progressbar(top, variable=self.health_progress_var, maximum=100, style="Neon.Horizontal.TProgressbar").grid(row=1, column=0, sticky="ew", pady=(8, 0))
        self.health_output_text = self.make_text(output_panel, height=18)
        self.health_output_text.grid(row=1, column=0, sticky="nsew", padx=14, pady=(0, 14))
        self.set_text(self.health_output_text, "Select a target drive, then run a safe diagnostic action.\n")
        self.bind_mousewheel_recursive(body, self.health_tab_canvas)
        self.rebuild_health_dashboard_layout()

    def create_help_tab(self):
        tab = self.tabs["Help Center"]
        tab.grid_columnconfigure(1, weight=1)
        tab.grid_rowconfigure(1, weight=1)

        header = tk.Frame(tab, bg=CYBER_BG)
        header.grid(row=0, column=0, columnspan=2, sticky="ew", padx=8, pady=(8, 6))
        header.grid_columnconfigure(1, weight=1)
        tk.Label(header, text="HELP CENTER", bg=CYBER_BG, fg=CYBER_CYAN, font=("Consolas", 20, "bold")).grid(row=0, column=0, sticky="w")
        tk.Label(
            header,
            text="Integrated documentation, scan guidance, recovery notes, and developer credits",
            bg=CYBER_BG,
            fg=CYBER_MUTED,
            font=("Segoe UI", 10),
        ).grid(row=1, column=0, columnspan=3, sticky="w", pady=(2, 0))

        self.help_search_var = tk.StringVar()
        search = self.neon_entry(header, self.help_search_var)
        search.grid(row=0, column=1, sticky="ew", padx=16)
        search.insert(0, "")
        Tooltip(search, "Search help topics by scan mode, report type, risk score, resume, warning, or troubleshooting term.")
        ttk.Button(header, text="SEARCH", style="Cyber.TButton", command=self.refresh_help_content).grid(row=0, column=2, sticky="ew", padx=(0, 8))
        ttk.Button(header, text="EXPORT TXT", style="Cyber.TButton", command=lambda: self.export_help_guide("txt")).grid(row=0, column=3, sticky="ew", padx=4)
        ttk.Button(header, text="EXPORT HTML", style="Cyber.TButton", command=lambda: self.export_help_guide("html")).grid(row=0, column=4, sticky="ew", padx=4)
        ttk.Button(header, text="ONBOARDING", style="Cyber.TButton", command=self.show_onboarding_wizard).grid(row=0, column=5, sticky="ew", padx=(4, 0))

        sidebar = self.make_panel(tab)
        sidebar.grid(row=1, column=0, sticky="nsew", padx=(8, 6), pady=(0, 8))
        sidebar.grid_columnconfigure(0, weight=1)
        sidebar.grid_rowconfigure(1, weight=1)
        tk.Label(sidebar, text="TOPICS", bg=CYBER_PANEL, fg=CYBER_CYAN, font=("Consolas", 12, "bold")).grid(row=0, column=0, sticky="w", padx=12, pady=(12, 8))
        nav_shell = tk.Frame(sidebar, bg=CYBER_PANEL)
        nav_shell.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))
        nav_shell.grid_columnconfigure(0, weight=1)
        nav_shell.grid_rowconfigure(0, weight=1)
        self.help_nav_canvas = tk.Canvas(nav_shell, bg=CYBER_PANEL, highlightthickness=0, bd=0, width=230)
        self.help_nav_scrollbar = ttk.Scrollbar(nav_shell, orient="vertical", command=self.help_nav_canvas.yview, style="Cyber.Vertical.TScrollbar")
        self.help_nav_canvas.configure(yscrollcommand=self.help_nav_scrollbar.set)
        self.help_nav_canvas.grid(row=0, column=0, sticky="nsew")
        self.help_nav_scrollbar.grid(row=0, column=1, sticky="ns")
        self.help_nav_frame = tk.Frame(self.help_nav_canvas, bg=CYBER_PANEL)
        self.help_nav_window = self.help_nav_canvas.create_window((0, 0), window=self.help_nav_frame, anchor="nw")
        self.help_nav_frame.bind("<Configure>", self._update_help_nav_scroll_region)
        self.help_nav_canvas.bind("<Configure>", self._resize_help_nav_canvas_window)
        self.bind_mousewheel(self.help_nav_canvas, self.help_nav_canvas)
        self.bind_mousewheel(self.help_nav_frame, self.help_nav_canvas)

        content_shell = tk.Frame(tab, bg=INPUT_BORDER, highlightbackground=INPUT_BORDER, highlightthickness=1)
        content_shell.grid(row=1, column=1, sticky="nsew", padx=(6, 8), pady=(0, 8))
        content_shell.grid_columnconfigure(0, weight=1)
        content_shell.grid_rowconfigure(0, weight=1)
        self.help_canvas = tk.Canvas(content_shell, bg=CYBER_BG, highlightthickness=0, bd=0)
        self.help_scrollbar = ttk.Scrollbar(content_shell, orient="vertical", command=self.help_canvas.yview, style="Cyber.Vertical.TScrollbar")
        self.help_canvas.configure(yscrollcommand=self.help_scrollbar.set)
        self.help_canvas.grid(row=0, column=0, sticky="nsew")
        self.help_scrollbar.grid(row=0, column=1, sticky="ns")
        self.help_content_frame = tk.Frame(self.help_canvas, bg=CYBER_BG)
        self.help_canvas_window = self.help_canvas.create_window((0, 0), window=self.help_content_frame, anchor="nw")
        self.help_content_frame.bind("<Configure>", self._update_help_scroll_region)
        self.help_canvas.bind("<Configure>", self._resize_help_canvas_window)
        self.bind_mousewheel(self.help_canvas, self.help_canvas)
        self.bind_mousewheel(self.help_content_frame, self.help_canvas)
        self.help_search_var.trace_add("write", lambda *_: self.refresh_help_content())
        self.help_sections_open = {}
        self.help_section_widgets = {}
        self.show_older_changelog_versions = False
        self.refresh_help_content()

    def get_help_sections(self):
        py_version = sys.version.split()[0]
        os_label = f"{platform.system()} {platform.release()} ({platform.version()})"
        smart_state = "Available" if smartctl_available() else "Not detected"
        pdf_engines = pdf_engine_available()
        pdf_state = ", ".join(pdf_engines) if pdf_engines else "Unavailable"
        return [
            (
                "Introduction",
                "What Cyber Storage Verifier does",
                [
                    "Cyber Storage Verifier is a Windows-focused storage authenticity and integrity scanner for HDDs, SSDs, USB pendrives, SD cards, and external storage.",
                    "It helps identify fake-capacity devices, unstable flash media, suspicious metadata, filesystem anomalies, slow or collapsing speeds, and health warnings exposed by Windows or smartctl.",
                    "Counterfeit storage is dangerous because it may report a large capacity while silently overwriting old data, returning corrupted bytes, failing near fixed boundaries, or losing files after a delay.",
                    "The scanner uses safe temporary-file testing. It writes normal test files inside the selected folder, verifies deterministic SHA256-backed patterns, and never overwrites raw disks or partitions.",
                    "A partial scan can find strong evidence of failure, but only broad or full-capacity validation can provide high confidence across the entire device.",
                ],
                "info",
            ),
            (
                "Quick Start Guide",
                "Beginner workflow",
                [
                    "1. Select a target drive or folder from Scan Controls, or use Browse to choose a mounted storage location.",
                    "2. Choose a scan mode. Balanced Scan is the safest default; Quick Health does not write test data; Full Capacity Validation gives the strongest capacity evidence.",
                    "3. Configure Test Size MB and Block Size MB. Leave both as AUTO unless you have a specific testing requirement.",
                    "4. Start the scan. The Dashboard and Active Scan tabs show current phase, progress, speeds, and findings.",
                    "5. Use Pause and Continue for temporary interruptions. Use Cancel to stop while preserving the session for resume.",
                    "6. Read the final verdict, risk score, and findings. Do not rely only on color; read the conclusion and coverage percentage.",
                    "7. Open TXT, JSON, CSV, or HTML reports from the Reports tab.",
                    "8. If the app closes, crashes, or the scan is cancelled, use Resume Previous Scan after reconnecting the same target device.",
                ],
                "info",
            ),
            (
                "Scan Modes",
                "Purpose, speed, accuracy, and impact",
                [
                    "Quick Scan: lightweight write/read validation. Fast, low impact, useful for a first look, but not enough to prove large-capacity authenticity.",
                    "Balanced Scan: recommended default. Uses adaptive size and block parameters to test meaningful coverage while preserving a safe free-space buffer.",
                    "Deep Scan: larger write/read coverage with stronger detection value. Slower and more stressful; use when the device is suspicious or important.",
                    "Full Capacity Validation: writes across available safe free space. Highest confidence and highest time impact. Always keep backups and avoid system drives.",
                    "Random Spot Check: verifies a sampled block set. Fast for quick instability checks but less complete than sequential verification.",
                    "Fake-Capacity Boundary: targets common counterfeit boundaries such as 8GB, 16GB, 32GB, 64GB, 128GB, and 256GB where fake media often fails.",
                    "Quick Health: metadata, volume, Windows disk, and optional SMART checks without test writes. Good before a write-heavy scan.",
                ],
                "info",
            ),
            (
                "Resume Scan System",
                "Checkpointed recovery",
                [
                    "Every writable scan creates a session folder inside the verifier test directory on the target.",
                    "The checkpoint JSON stores target identity, volume serial, filesystem, reported capacity, session path, test file path, and every block record.",
                    "Each block records offset, size, deterministic seed, expected SHA256, write status, read status, verification result, speeds, retry count, timestamp, and errors.",
                    "Checkpoints are saved after block writes and verifications, so a crash or cancellation can resume from the last known state.",
                    "Resume validates target drive identity, volume serial, filesystem, capacity, and test file presence before continuing.",
                    "Already verified-good blocks are skipped unless Recheck all blocks when resuming is enabled.",
                    "Temporary test files are intentionally preserved after interruption so resume can verify the original bytes.",
                    "Resume can fail if the device was reformatted, the volume serial changed, the test file was deleted, or the drive letter points to a different device.",
                ],
                "warning",
            ),
            (
                "Storage Safety Information",
                "How the app avoids destructive operations",
                [
                    "The application never writes to raw disks, device handles, partition tables, boot sectors, or unallocated space.",
                    "Test data is stored as ordinary files inside the selected target folder.",
                    "The scanner keeps a free-space buffer and warns when deep or full tests may write large amounts of data.",
                    "System drive testing is discouraged because filling or stressing C: can affect Windows stability.",
                    "Do not scan the only copy of important data. Any storage validation can reveal a failing device by forcing it to read and write.",
                    "Use Discard Selected Session only after confirming that resume is no longer needed.",
                ],
                "warning",
            ),
            (
                "Advanced Detection Features",
                "Signals used by the detection engine",
                [
                    "Boundary detection looks for failures near common fake-capacity thresholds.",
                    "SHA256 verification detects changed, repeated, remapped, or corrupted bytes after writing.",
                    "Random post-write rechecks help catch unstable flash translation behavior after the main pass.",
                    "Metadata mismatch detection compares volume, filesystem, Windows disk, and physical disk information when available.",
                    "Speed collapse detection records blocks that suddenly fall far below the session average.",
                    "Filesystem anomaly detection flags cases such as FAT/FAT32 on very large removable media.",
                    "SMART warning detection uses smartctl when installed and Windows metadata when available.",
                    "Read/write instability analysis tracks short reads, write failures, read failures, retries, speed variation, and corrupt blocks.",
                ],
                "info",
            ),
            (
                "Reports & Export Formats",
                "TXT, JSON, CSV, HTML, and history",
                [
                    "TXT report: human-readable scan summary, final verdict, capacity, speeds, metadata, findings, conclusion, and limitations.",
                    "JSON report: structured data for automation, audit pipelines, ticket evidence, or later analysis.",
                    "CSV block report: per-block evidence including offset, size, seed, hash, status, speed, retries, and errors.",
                    "HTML report: readable browser-based summary with styled metadata, findings, and a block preview.",
                    "Scan History stores completed scan summaries and report paths for quick review.",
                    "Block reports are especially useful when corruption begins near a capacity boundary or after a speed collapse.",
                ],
                "info",
            ),
            (
                "SMART & Metadata Checks",
                "Health and identity signals",
                [
                    "Windows volume checks collect filesystem, serial, flags, and capacity information.",
                    "PowerShell metadata checks map drive letters to Windows disk and physical disk information when permissions allow it.",
                    "Optional smartctl checks collect SMART identity and health summaries if smartmontools is installed.",
                    f"Current smartctl status: {smart_state}.",
                    "Missing SMART does not mean the drive is healthy or unhealthy; many USB bridges hide SMART data.",
                    "Suspicious metadata includes unknown serials, generic model names, unrealistic removable capacity, and mismatch between volume and physical disk information.",
                ],
                "info",
            ),
            (
                "Storage Health & Diagnostics",
                "Read-only health analysis module",
                [
                    "The Storage Health & Diagnostics tab adds safe, read-only health checks beside the authenticity scanner.",
                    "SMART Health Analyzer uses smartctl -H and smartctl -a when smartmontools is installed, then parses reallocated sectors, pending sectors, uncorrectable sectors, CRC errors, power-on hours, temperature, wear, and NVMe media errors.",
                    "Windows Health Analyzer uses read-only PowerShell commands: Get-PhysicalDisk, Get-Disk, Get-Volume, and Get-StorageReliabilityCounter where available.",
                    "Run Read-Only File System Check executes chkdsk X: only. It never uses /f, /r, format, diskpart clean, repair-volume -repair, or low-level disk operations.",
                    "Surface Read Stability Scan reads existing files only. It reports slow regions, read errors, latency spikes, and speed collapse signals without writing or repairing anything.",
                    "Health Risk Score is separate from the authenticity risk score and should be used for backup, monitoring, and replacement decisions.",
                    "Professional recommendations include No major health issues detected, Monitor this device, Backup recommended, Replacement recommended, and Do not rely on this device for important data.",
                ],
                "warning",
            ),
            (
                "Risk Score Explanation",
                "How to interpret the verdict",
                [
                    "0-20 Low Risk: no major issue found in the tested range. This does not prove the entire device is genuine unless coverage was broad.",
                    "21-45 Needs Deeper Testing: limited coverage or moderate warning signs. Run a larger scan before trusting the device.",
                    "46-70 Suspicious: high warnings, inconsistent behavior, metadata concerns, speed collapse, or failed operations may be present.",
                    "71-100 Likely Fake or Failing: strong evidence such as corruption, read mismatch, capacity mismatch, write failure, or severe metadata inconsistency.",
                    "Scores increase when corruption, read/write failures, health warnings, metadata anomalies, and severe speed instability are detected.",
                    "False positives are possible with bad cables, unstable hubs, overheating, permissions, antivirus interference, or a device disconnecting mid-scan.",
                ],
                "warning",
            ),
            (
                "Troubleshooting",
                "Common problems and fixes",
                [
                    "Access denied: choose a folder you can write to, run from a normal user profile, or avoid protected system locations.",
                    "SMART not available: install smartmontools or connect the device through a bridge that passes SMART data.",
                    "Drive disconnected: stop the scan, reconnect the device, confirm the same drive letter, then resume if the session validates.",
                    "Scan interrupted: use Resume Previous Scan. Do not delete the session folder or test file.",
                    "Slow scan speed: use Balanced or Fast flush policy, try another USB port, avoid hubs, and check for thermal throttling.",
                    "High RAM usage: keep AUTO block size or reduce Block Size MB. The scanner streams data but very large block sizes still add overhead.",
                    "Scan not resuming: verify the session drop-down, drive identity, test file presence, and volume serial.",
                    "Missing reports: open the Reports folder. If Documents is restricted, reports may fall back to the system temp report folder.",
                    "UI freezing: long work should run in the background; if Windows storage calls hang, the device or bridge may be unresponsive.",
                    "USB instability: use a short direct cable, a powered port, and avoid testing through low-quality hubs.",
                ],
                "warning",
            ),
            (
                "FAQ",
                "Frequently asked questions",
                [
                    "Is this safe? It writes normal temporary files only and never writes raw disks, but heavy testing can expose weak or failing media.",
                    "Can this damage my drive? It should not damage healthy storage, but deep testing increases wear on flash media and workload on drives.",
                    "Why does Deep Scan take long? It writes and verifies much more data, often with stronger flush behavior.",
                    "Why can fake storage pass Quick Scan? Many fake devices work at the beginning of their address range and fail only after their real capacity is exceeded.",
                    "Why use SHA256? It gives a strong fingerprint for each deterministic test block so mismatches are reliable corruption evidence.",
                    "Why leave temporary files? Interrupted scans need original test files to resume and verify without rewriting already completed blocks.",
                    "Why are speeds inconsistent? Flash controllers, thermal throttling, USB bridges, caching, antivirus, cable quality, and bad sectors can all affect speed.",
                    "Why is FAT32 suspicious on huge drives? It is not proof of fraud, but it is common on low-cost removable devices and deserves deeper testing.",
                    "Why do counterfeit drives fail near boundaries? Many are built from smaller flash modules while firmware falsely reports a larger address space.",
                ],
                "info",
            ),
            (
                "Keyboard Shortcuts",
                "Fast navigation and actions",
                [
                    "Ctrl+O: Browse for target drive or folder.",
                    "Ctrl+S: Start scan.",
                    "Ctrl+P: Pause scan.",
                    "Ctrl+R: Resume or continue scan.",
                    "Ctrl+X: Cancel scan.",
                    "Ctrl+H: Open Help Center.",
                    "Ctrl+L: Clear logs.",
                    "Ctrl+E: Open latest report.",
                ],
                "info",
            ),
            (
                "Performance Optimization Tips",
                "Speed, stability, and coverage",
                [
                    "Use AUTO block size unless you are diagnosing a specific storage behavior.",
                    "Balanced flush policy is a good default. Deep flushing is stronger evidence but slower.",
                    "For USB storage, connect directly to the machine rather than through a shared hub.",
                    "Run Quick Health first if you want metadata and health context before writing test files.",
                    "Use Fake-Capacity Boundary when you suspect an advertised capacity is much larger than real flash.",
                    "Avoid running heavy file copies, backups, or antivirus scans on the target during validation.",
                    "Let drives cool between repeated deep scans to reduce thermal throttling.",
                ],
                "info",
            ),
            (
                "Warnings & Limitations",
                "Read before trusting results",
                [
                    "No software can guarantee future data safety. A device can pass today and fail later.",
                    "A partial scan cannot prove every address on a large device is valid.",
                    "A quick scan may miss fake capacity that begins beyond the tested range.",
                    "USB bridges may hide model, serial, SMART, and health data.",
                    "Power loss, bad cables, unstable ports, and antivirus interception can affect scan results.",
                    "The tool does not recover data, repair filesystems, or certify storage for forensic use.",
                ],
                "danger",
            ),
            (
                "Developer Credits",
                "About the author",
                [
                    "Application Name: Cyber Storage Verifier",
                    "Developer: Rushab",
                    f"Version: {APP_VERSION}",
                    f"Python Runtime: {py_version}",
                    f"Operating System: {os_label}",
                    f"Optional Dependencies: smartctl/smartmontools ({smart_state})",
                    "Thanks: Python, Tkinter, Windows storage tooling, smartmontools, and the storage-security research community.",
                    "Security Disclaimer: The application helps identify risk signals but does not provide a legal authenticity certification.",
                    "Storage Safety Disclaimer: Always keep backups. Do not test the only copy of important data.",
                ],
                "credit",
            ),
            (
    "Changelog / Update Notes",
    "Major feature history",
    [
        "v2.1 - Latest Release: Storage Health & Diagnostics, SMART Dashboard, Full Details Viewer, and Responsive Health UI",

        "v2.1: Added advanced Storage Health & Diagnostics dashboard with automatic multi-drive health discovery, live device telemetry monitoring, and enterprise-style cyber-themed diagnostics UI.",
        "v2.1: Added fully responsive health diagnostics layout engine with adaptive drive-card rendering, automatic grid resizing, dynamic stacking behavior, scrollable containers, and compact-window optimization.",
        "v2.1: Added intelligent drive identity discovery with automatic detection of drive model, manufacturer, firmware version, serial number, filesystem, bus/interface type, media classification, and physical storage metadata.",
        "v2.1: Added professional drive health cards with dynamic health score visualization, cyber-themed status badges, responsive telemetry widgets, live SMART summaries, and risk indicator rendering.",
        "v2.1: Added advanced SMART diagnostics engine with automatic smartctl discovery, SMART parsing, Windows-to-SMART device mapping intelligence, confidence scoring, and read-only hardware health analysis.",
        "v2.1: Added enhanced Windows storage telemetry integration using Get-Disk, Get-PhysicalDisk, Get-Volume, and Get-StorageReliabilityCounter for deeper reliability diagnostics and health-state monitoring.",
        "v2.1: Added automatic SSD/HDD/NVMe/USB/removable-media classification with intelligent badge rendering and storage-type-specific telemetry presentation.",
        "v2.1: Added intelligent device-aware telemetry handling with automatic fallback wording such as 'Mechanical HDD', 'Not Exposed', 'USB Bridge Hidden', and 'SMART Unavailable' instead of generic unknown states.",
        "v2.1: Added NVMe and SSD wear-level analysis using Percentage Used, Wear_Leveling_Count, Media_Wearout_Indicator, Percent_Lifetime_Remain, and Windows reliability wear telemetry.",
        "v2.1: Added HDD-specific reliability analysis including reallocated sectors, pending sectors, offline uncorrectable sectors, CRC errors, power-on hours, start/stop counts, and mechanical-drive health interpretation.",
        "v2.1: Added advanced predictive health risk scoring engine with failure-intelligence logic based on SMART degradation indicators, SSD wear levels, temperature anomalies, CRC instability, and media/data integrity errors.",
        "v2.1: Added live temperature telemetry, wear-level tracking, SMART attribute monitoring, Windows health synchronization, power-cycle analysis, and power-on-hours telemetry integration.",
        "v2.1: Added read-only surface read stability diagnostics with latency anomaly analysis, slow-region detection, timeout intelligence, sampled stability scoring, and non-destructive read verification.",
        "v2.1: Added read-only CHKDSK preview integration with filesystem warning analysis, safer diagnostics-only execution, and non-destructive filesystem integrity inspection.",
        "v2.1: Added complete 'View Full Details' diagnostics window with responsive Toplevel UI, tabbed forensic telemetry views, SMART tables, health-analysis panels, raw SMART viewers, and diagnostic history rendering.",
        "v2.1: Added dedicated Overview, SMART Details, Health Analysis, Surface Stability, Raw SMART Output, and History/Timeline tabs for expanded forensic storage analysis.",
        "v2.1: Added raw SMART output viewer with scrollable forensic telemetry rendering, copy-to-clipboard support, and raw smartctl evidence inspection.",
        "v2.1: Added advanced SMART attribute parsing for Spin_Retry_Count, Seek_Error_Rate, Start_Stop_Count, Load_Cycle_Count, Unsafe Shutdowns, Available Spare, Controller Busy Time, Host Read Commands, and Host Write Commands.",
        "v2.1: Added intelligent SMART-device confidence matching using serial numbers, drive models, bus types, physical drive numbers, and metadata correlation logic.",
        "v2.1: Added single-drive forensic report export support for TXT, JSON, HTML, and PDF formats directly from the full diagnostics viewer.",
        "v2.1: Added drive-specific recommendation engine with contextual health guidance such as backup recommendations, thermal warnings, SMART degradation alerts, and mechanical-drive advisories.",
        "v2.1: Added enterprise-style health summary telemetry widgets for total drives, healthy devices, warning devices, critical-risk devices, and unknown-state tracking.",
        "v2.1: Added safer diagnostics-only architecture with explicit prevention of destructive operations, firmware modification, raw-disk writes, formatting, repair-volume actions, and bad-sector repair execution.",
        "v2.1: Added improved report/export reliability with enhanced storage-health rendering, SMART evidence preservation, interruption-aware exports, and advanced telemetry presentation.",
        "v2.1: Added extensive health diagnostics unit testing including SMART parser validation, device-aware fallback handling, uncertain SMART mapping detection, full-details-window testing, export validation, and HDD/NVMe telemetry rendering verification.",
        "v2.1: Improved drive discovery reliability, metadata caching, PowerShell integration stability, smartctl matching accuracy, responsive UI scaling, diagnostics performance, and overall application stability.",

        "v2.0: Added resumable block scan sessions, JSON checkpoints, per-block metadata, random rechecks, delayed verification, scan history, and multi-format forensic reports.",
        "v2.0: Added Quick, Balanced, Deep, Full Capacity Validation, Random Spot Check, Fake-Capacity Boundary, and Quick Health scan modes.",
        "v2.0: Added enterprise-style cyber-themed tabbed UI, dashboard cards, active telemetry views, settings panels, improved input styling, and safer cleanup handling.",
        "v2.0: Improved metadata analysis, SMART integration, speed anomaly detection, corruption intelligence, risk categories, and forensic report conclusions.",
        "v2.0: Added real-time processed, verified, corrupted, failed, and read-failure telemetry synchronization.",
        "v2.0: Added advanced corruption analytics including corruption percentage tracking, consecutive corruption detection, corruption start offset analysis, and estimated authentic usable capacity detection.",
        "v2.0: Added SHA-256 mismatch evidence tracking, verified/corrupted/failed range mapping, fake-capacity boundary intelligence, and forensic evidence preservation.",
        "v2.0: Added partial scan finalization with support for interrupted scans, Stop Scan, Cancel, Emergency Stop, and severe corruption auto-stop recovery.",
        "v2.0: Added advanced cyber-forensic HTML dashboard reports with storage authenticity visualization maps, risk indicator widgets, corruption analytics, and forensic warning panels.",
        "v2.0: Added professional PDF forensic report export support with enhanced dashboard rendering and evidence presentation.",
        "v2.0: Improved Active Scan UI with live corruption visualization, processed vs verified telemetry tracking, warning banners, stabilized ETA calculations, and live findings updates.",
        "v2.0: Enhanced TXT, JSON, CSV, HTML, and PDF reporting engines with interruption-aware evidence preservation and forensic telemetry rendering.",
        "v2.0: Improved finalize() reliability, finish_session() synchronization, resumable checkpoint recovery, corruption persistence tracking, and overall scan stability.",
        "v2.0 Help Center: Added integrated documentation, searchable help system, collapsible sections, exports, shortcuts, onboarding, context help, and developer credits.",
    ],
    "credit",
),
        ]

    def refresh_help_content(self):
        if not hasattr(self, "help_content_frame"):
            return
        query = self.help_search_var.get().strip().lower() if hasattr(self, "help_search_var") else ""
        for child in self.help_content_frame.winfo_children():
            child.destroy()
        for child in self.help_nav_frame.winfo_children():
            child.destroy()
        self.help_section_widgets = {}
        sections = []
        for title, subtitle, lines, kind in self.get_help_sections():
            haystack = " ".join([title, subtitle] + lines).lower()
            if not query or query in haystack:
                sections.append((title, subtitle, lines, kind))
        if not sections:
            sections = [("No Results", "Search did not match any help topic", ["Try terms such as resume, risk, SMART, report, boundary, SHA256, or shortcut."], "warning")]
        for idx, (title, subtitle, lines, kind) in enumerate(sections):
            nav = ttk.Button(self.help_nav_frame, text=title, style="Cyber.TButton", command=lambda t=title: self.jump_to_help_section(t))
            nav.grid(row=idx, column=0, sticky="ew", pady=3)
            self.bind_mousewheel(nav, self.help_nav_canvas)
            self.help_nav_frame.grid_columnconfigure(0, weight=1)
            self.add_help_section(self.help_content_frame, title, subtitle, lines, kind, idx)
        self.help_content_frame.update_idletasks()
        self._update_help_nav_scroll_region()
        self.help_canvas.yview_moveto(0)

    def add_help_section(self, parent, title, subtitle, lines, kind, row):
        accent = {
            "info": CYBER_CYAN,
            "warning": CYBER_YELLOW,
            "danger": CYBER_RED,
            "credit": CYBER_GREEN,
        }.get(kind, CYBER_CYAN)
        panel = tk.Frame(parent, bg=CYBER_PANEL, highlightbackground=accent, highlightthickness=1, padx=14, pady=10)
        panel.grid(row=row, column=0, sticky="ew", padx=12, pady=8)
        parent.grid_columnconfigure(0, weight=1)
        panel.grid_columnconfigure(0, weight=1)
        is_open = self.help_sections_open.get(title, True)
        toggle_text = f"[-] {title}" if is_open else f"[+] {title}"
        header = tk.Button(
            panel,
            text=toggle_text,
            command=lambda t=title: self.toggle_help_section(t),
            bg=CYBER_PANEL,
            fg=accent,
            activebackground=INPUT_BG_HOVER,
            activeforeground="#FFFFFF",
            relief="flat",
            anchor="w",
            font=("Consolas", 13, "bold"),
            bd=0,
        )
        header.grid(row=0, column=0, sticky="ew")
        self.bind_mousewheel(header, self.help_canvas)
        subtitle_lbl = tk.Label(panel, text=subtitle, bg=CYBER_PANEL, fg=INPUT_MUTED, font=("Segoe UI", 9, "bold"), anchor="w")
        subtitle_lbl.grid(row=1, column=0, sticky="ew", pady=(2, 8))
        self.bind_mousewheel(subtitle_lbl, self.help_canvas)
        body = tk.Frame(panel, bg=CYBER_PANEL)
        if is_open:
            body.grid(row=2, column=0, sticky="ew")
        if title == "Changelog / Update Notes":
            box = self.render_changelog_section(body, lines)
        else:
            box = self.help_info_box(body, lines, kind)
        box.pack(fill="x", expand=True)
        self.bind_mousewheel_recursive(panel, self.help_canvas)
        self.help_section_widgets[title] = {"panel": panel, "body": body, "header": header}

    def render_changelog_section(self, parent, lines):
        frame = tk.Frame(parent, bg="#081526", highlightbackground=CYBER_GREEN, highlightthickness=1, padx=12, pady=10)
        query = self.help_search_var.get().strip().lower() if hasattr(self, "help_search_var") else ""
        latest_items = [line for line in lines if str(line).startswith("v2.1")]
        older_items = [line for line in lines if str(line).startswith("v2.0")]
        show_older = bool(query) or self.show_older_changelog_versions

        row = 0
        tk.Label(
            frame,
            text="v2.1 - Latest Release",
            bg="#081526",
            fg=CYBER_GREEN,
            font=("Consolas", 12, "bold"),
            anchor="w",
        ).grid(row=row, column=0, sticky="ew", pady=(0, 8))
        row += 1
        for line in latest_items:
            lbl = tk.Label(
                frame,
                text=f">> {line}",
                bg="#081526",
                fg=INPUT_FG,
                font=("Segoe UI", 10),
                justify="left",
                anchor="w",
                wraplength=920,
            )
            lbl.grid(row=row, column=0, sticky="ew", pady=2)
            self.bind_mousewheel(lbl, self.help_canvas if hasattr(self, "help_canvas") else frame)
            row += 1

        btn_text = "Hide Older Versions" if self.show_older_changelog_versions else "Show Older Versions"
        if not query:
            toggle = ttk.Button(frame, text=btn_text, style="Cyber.TButton", command=self.toggle_older_changelog_versions)
            toggle.grid(row=row, column=0, sticky="w", pady=(12, 8))
            self.bind_mousewheel(toggle, self.help_canvas if hasattr(self, "help_canvas") else frame)
            row += 1

        if show_older:
            tk.Label(
                frame,
                text="v2.0 - Older Version",
                bg="#081526",
                fg=CYBER_CYAN,
                font=("Consolas", 12, "bold"),
                anchor="w",
            ).grid(row=row, column=0, sticky="ew", pady=(8, 8))
            row += 1
            for line in older_items:
                if query and query not in line.lower() and query not in "changelog update notes older version v2.0".lower():
                    continue
                lbl = tk.Label(
                    frame,
                    text=f">> {line}",
                    bg="#081526",
                    fg=INPUT_FG,
                    font=("Segoe UI", 10),
                    justify="left",
                    anchor="w",
                    wraplength=920,
                )
                lbl.grid(row=row, column=0, sticky="ew", pady=2)
                self.bind_mousewheel(lbl, self.help_canvas if hasattr(self, "help_canvas") else frame)
                row += 1

        frame.grid_columnconfigure(0, weight=1)
        return frame

    def toggle_older_changelog_versions(self):
        self.show_older_changelog_versions = not getattr(self, "show_older_changelog_versions", False)
        self.refresh_help_content()
        self.jump_to_help_section("Changelog / Update Notes")

    def help_info_box(self, parent, lines, kind):
        accent = {"info": CYBER_CYAN, "warning": CYBER_YELLOW, "danger": CYBER_RED, "credit": CYBER_GREEN}.get(kind, CYBER_CYAN)
        bg = "#081526" if kind != "danger" else "#21101A"
        frame = tk.Frame(parent, bg=bg, highlightbackground=accent, highlightthickness=1, padx=12, pady=10)
        for i, line in enumerate(lines):
            bullet = ">>" if kind != "danger" else "!!"
            lbl = tk.Label(
                frame,
                text=f"{bullet} {line}",
                bg=bg,
                fg=INPUT_FG,
                font=("Segoe UI", 10),
                justify="left",
                anchor="w",
                wraplength=920,
            )
            lbl.grid(row=i, column=0, sticky="ew", pady=2)
            self.bind_mousewheel(lbl, self.help_canvas if hasattr(self, "help_canvas") else frame)
        frame.grid_columnconfigure(0, weight=1)
        return frame

    def toggle_help_section(self, title):
        self.help_sections_open[title] = not self.help_sections_open.get(title, True)
        self.refresh_help_content()
        self.jump_to_help_section(title)

    def jump_to_help_section(self, title):
        self.update_idletasks()
        widget = self.help_section_widgets.get(title, {}).get("panel")
        if not widget:
            return
        y = widget.winfo_y()
        total = max(1, self.help_content_frame.winfo_height())
        self.smooth_help_scroll(y / total)

    def smooth_help_scroll(self, target):
        target = min(1.0, max(0.0, target))
        start = self.help_canvas.yview()[0]
        steps = 8
        for step in range(1, steps + 1):
            pos = start + (target - start) * (step / steps)
            self.after(step * 12, lambda p=pos: self.help_canvas.yview_moveto(p))

    def _update_help_scroll_region(self, _event=None):
        self.help_canvas.configure(scrollregion=self.help_canvas.bbox("all"))

    def _resize_help_canvas_window(self, event):
        self.help_canvas.itemconfigure(self.help_canvas_window, width=event.width)

    def _update_help_nav_scroll_region(self, _event=None):
        if hasattr(self, "help_nav_canvas"):
            self.help_nav_canvas.configure(scrollregion=self.help_nav_canvas.bbox("all"))

    def _resize_help_nav_canvas_window(self, event):
        if hasattr(self, "help_nav_canvas"):
            self.help_nav_canvas.itemconfigure(self.help_nav_window, width=event.width)

    def help_plain_text(self):
        chunks = [f"{APP_NAME} v{APP_VERSION} Help Center", f"Generated: {now_stamp()}", ""]
        for title, subtitle, lines, _kind in self.get_help_sections():
            chunks.append(title.upper())
            chunks.append(subtitle)
            chunks.append("-" * 72)
            chunks.extend(lines)
            chunks.append("")
        return "\n".join(chunks)

    def help_html_text(self):
        body = []
        for title, subtitle, lines, kind in self.get_help_sections():
            items = "".join(f"<li>{html.escape(line)}</li>" for line in lines)
            body.append(f"<section class='{kind}'><h2>{html.escape(title)}</h2><h3>{html.escape(subtitle)}</h3><ul>{items}</ul></section>")
        return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{APP_NAME} Help Center</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#070B14;color:#F4FCFF;margin:28px;line-height:1.5}}
h1,h2{{color:#00E5FF}} h3{{color:#9FBFD0}} section{{background:#0B1220;border:1px solid #2C5E8F;padding:16px;margin:16px 0}}
.warning{{border-color:#FFD166}} .danger{{border-color:#FF3B6B}} .credit{{border-color:#39FF88}}
li{{margin:7px 0}} code{{color:#39FF88}}
</style></head><body><h1>{APP_NAME} v{APP_VERSION} Help Center</h1><p>Generated: {now_stamp()}</p>{''.join(body)}</body></html>"""

    def export_help_guide(self, fmt):
        reports_dir = ensure_reports_dir()
        suffix = ".html" if fmt == "html" else ".txt"
        path = reports_dir / f"Cyber_Storage_Verifier_Help_{file_stamp()}{suffix}"
        try:
            if fmt == "html":
                path.write_text(self.help_html_text(), encoding="utf-8")
            else:
                path.write_text(self.help_plain_text(), encoding="utf-8")
            self.open_file(str(path))
            self.log_callback(f"Help guide exported: {path}")
        except Exception as exc:
            messagebox.showerror("Help Export Failed", str(exc))

    def show_scan_mode_help(self):
        mode = self.scan_mode_var.get() if hasattr(self, "scan_mode_var") else "Balanced Scan"
        section = next((lines for title, _subtitle, lines, _kind in self.get_help_sections() if title == "Scan Modes"), [])
        matching = [line for line in section if line.lower().startswith(mode.lower())]
        detail = matching[0] if matching else "Choose a scan mode based on how much time, coverage, and write workload you can allow."
        self.show_context_help(f"{mode} Help", detail)

    def show_context_help(self, title="What does this mean?", message=None):
        if message is None:
            message = (
                "Warnings are risk signals, not automatic proof of fraud. Review the risk score, findings, scan coverage, "
                "device metadata, and block report together before deciding whether a device is trustworthy."
            )
        popup = tk.Toplevel(self)
        popup.title(title)
        popup.configure(bg=CYBER_BG)
        popup.geometry("520x260")
        popup.transient(self)
        popup.grab_set()
        panel = self.make_panel(popup)
        panel.pack(fill="both", expand=True, padx=16, pady=16)
        tk.Label(panel, text=title.upper(), bg=CYBER_PANEL, fg=CYBER_CYAN, font=("Consolas", 14, "bold")).pack(anchor="w", padx=16, pady=(16, 8))
        tk.Label(panel, text=message, bg=CYBER_PANEL, fg=INPUT_FG, font=("Segoe UI", 10), wraplength=460, justify="left").pack(anchor="w", padx=16, pady=8)
        ttk.Button(panel, text="OPEN HELP CENTER", style="Cyber.TButton", command=lambda: [popup.destroy(), self.open_help_center()]).pack(fill="x", padx=16, pady=(12, 6))
        ttk.Button(panel, text="CLOSE", style="Cyber.TButton", command=popup.destroy).pack(fill="x", padx=16, pady=(0, 16))

    def show_onboarding_wizard(self):
        steps = [
            ("Welcome", "Cyber Storage Verifier tests storage authenticity using safe temporary files and metadata checks."),
            ("Choose Target", "Select the drive or folder you want to test. Avoid C: unless you understand the risk."),
            ("Pick Mode", "Balanced Scan is recommended. Use Quick Health for metadata-only checks and Full Capacity Validation for strongest coverage."),
            ("Run Safely", "Keep AUTO sizing unless needed. Pause or cancel if the drive becomes unstable."),
            ("Review Evidence", "Read the risk score, findings, coverage, and reports. Resume interrupted scans from Scan History."),
        ]
        popup = tk.Toplevel(self)
        popup.title("Onboarding Wizard")
        popup.configure(bg=CYBER_BG)
        popup.geometry("600x330")
        popup.transient(self)
        idx = tk.IntVar(value=0)
        panel = self.make_panel(popup)
        panel.pack(fill="both", expand=True, padx=16, pady=16)
        title_var = tk.StringVar()
        body_var = tk.StringVar()
        tk.Label(panel, textvariable=title_var, bg=CYBER_PANEL, fg=CYBER_CYAN, font=("Consolas", 16, "bold")).pack(anchor="w", padx=18, pady=(18, 8))
        tk.Label(panel, textvariable=body_var, bg=CYBER_PANEL, fg=INPUT_FG, font=("Segoe UI", 11), wraplength=530, justify="left").pack(anchor="w", padx=18, pady=8)
        progress_var = tk.StringVar()
        tk.Label(panel, textvariable=progress_var, bg=CYBER_PANEL, fg=CYBER_MUTED, font=("Consolas", 10)).pack(anchor="w", padx=18, pady=8)

        def render():
            i = idx.get()
            title_var.set(steps[i][0])
            body_var.set(steps[i][1])
            progress_var.set(f"Step {i + 1} of {len(steps)}")

        def next_step():
            if idx.get() >= len(steps) - 1:
                popup.destroy()
            else:
                idx.set(idx.get() + 1)
                render()

        def prev_step():
            idx.set(max(0, idx.get() - 1))
            render()

        btns = tk.Frame(panel, bg=CYBER_PANEL)
        btns.pack(fill="x", padx=18, pady=(20, 18))
        ttk.Button(btns, text="BACK", style="Cyber.TButton", command=prev_step).pack(side="left", fill="x", expand=True, padx=(0, 6))
        ttk.Button(btns, text="NEXT / FINISH", style="Cyber.TButton", command=next_step).pack(side="left", fill="x", expand=True, padx=(6, 0))
        render()

    def create_settings_tab(self):
        tab = self.tabs["Settings"]
        tab.grid_columnconfigure(0, weight=1)
        panel = self.make_panel(tab)
        panel.grid(row=0, column=0, sticky="new", padx=8, pady=8)
        panel.grid_columnconfigure(1, weight=1)
        self.section_title(panel, "SETTINGS").grid(row=0, column=0, columnspan=2, sticky="w", padx=18, pady=(18, 12))
        settings = [
            ("Retry Count", "retry_count", tk.StringVar(value=str(self.settings.retry_count))),
            ("Retry Delay Sec", "retry_delay_sec", tk.StringVar(value=str(self.settings.retry_delay_sec))),
            ("Delayed Verify Sec", "delayed_verify_seconds", tk.StringVar(value=str(self.settings.delayed_verify_seconds))),
            ("Random Recheck %", "random_recheck_percent", tk.StringVar(value=str(self.settings.random_recheck_percent))),
            ("Severe Corruption Stop Blocks", "severe_corruption_blocks", tk.StringVar(value=str(self.settings.severe_corruption_blocks))),
            ("Surface Scan Max MB", "surface_scan_max_mb", tk.StringVar(value=str(self.settings.surface_scan_max_mb))),
            ("Surface Chunk MB", "surface_scan_chunk_mb", tk.StringVar(value=str(self.settings.surface_scan_chunk_mb))),
            ("Surface Max Seconds", "surface_scan_max_seconds", tk.StringVar(value=str(self.settings.surface_scan_max_seconds))),
        ]
        self.setting_vars = {}
        r = 1
        for label, key, var in settings:
            tk.Label(panel, text=label, bg=CYBER_PANEL, fg=CYBER_MUTED).grid(row=r, column=0, sticky="w", padx=18, pady=6)
            self.neon_entry(panel, var).grid(row=r, column=1, sticky="ew", padx=18, pady=6)
            self.setting_vars[key] = var
            r += 1
        self.smart_var = tk.BooleanVar(value=self.settings.enable_smart_checks)
        self.ps_var = tk.BooleanVar(value=self.settings.enable_powershell_metadata)
        self.exclude_c_var = tk.BooleanVar(value=self.settings.exclude_system_drive)
        self.warn_var = tk.BooleanVar(value=self.settings.show_advanced_warnings)
        self.auto_stop_corruption_var = tk.BooleanVar(value=self.settings.auto_stop_severe_corruption)
        for text, var in (
            ("Enable SMART checks", self.smart_var),
            ("Enable PowerShell metadata checks", self.ps_var),
            ("Exclude system drive by default", self.exclude_c_var),
            ("Show advanced warnings", self.warn_var),
            ("Auto-stop scan after severe continuous corruption", self.auto_stop_corruption_var),
        ):
            self.cyber_checkbutton(panel, text, var).grid(row=r, column=1, sticky="w", padx=18, pady=5)
            r += 1
        ttk.Button(panel, text="Apply Settings", style="Cyber.TButton", command=self.apply_settings).grid(row=r, column=0, columnspan=2, sticky="ew", padx=18, pady=16)

    def make_text(self, parent, height=12):
        frame = tk.Frame(parent, bg=INPUT_BORDER, highlightbackground=INPUT_BORDER, highlightcolor=INPUT_BORDER_FOCUS, highlightthickness=1, bd=0)
        text = tk.Text(
            frame,
            bg="#07101D",
            fg=INPUT_FG,
            insertbackground=CYBER_CYAN,
            selectbackground=INPUT_SELECT_BG,
            selectforeground=INPUT_SELECT_FG,
            relief="flat",
            font=("Consolas", 10),
            wrap="word",
            padx=12,
            pady=10,
            height=height,
            bd=0,
        )
        scroll = ttk.Scrollbar(frame, orient="vertical", command=text.yview, style="Cyber.Vertical.TScrollbar")
        text.configure(yscrollcommand=scroll.set)
        text.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        text.configure(state="disabled")
        def focus_in(_event):
            frame.configure(highlightbackground=INPUT_BORDER_FOCUS)

        def focus_out(_event):
            frame.configure(highlightbackground=INPUT_BORDER)

        text.bind("<FocusIn>", focus_in, add="+")
        text.bind("<FocusOut>", focus_out, add="+")
        self.bind_mousewheel(text, text)
        self.bind_mousewheel(frame, text)
        return frame

    def bind_mousewheel(self, widget, target, horizontal=False):
        def on_mousewheel(event):
            delta = event.delta
            if delta == 0 and hasattr(event, "num"):
                delta = 120 if event.num == 4 else -120
            units = int(-1 * (delta / 120)) if delta else 0
            if units == 0:
                units = -1 if delta > 0 else 1
            try:
                if horizontal:
                    target.xview_scroll(units, "units")
                else:
                    target.yview_scroll(units, "units")
            except Exception:
                return None
            return "break"

        widget.bind("<MouseWheel>", on_mousewheel, add="+")
        widget.bind("<Button-4>", on_mousewheel, add="+")
        widget.bind("<Button-5>", on_mousewheel, add="+")

    def bind_mousewheel_recursive(self, widget, target):
        self.bind_mousewheel(widget, target)
        for child in widget.winfo_children():
            self.bind_mousewheel_recursive(child, target)

    def text_widget(self, frame):
        return frame.winfo_children()[0]

    def set_text(self, frame, content):
        text = self.text_widget(frame)
        content = str(content)
        if len(content) > MAX_TEXT_WIDGET_CHARS:
            content = content[:6000] + "\n\n[Output truncated in UI. Full output is preserved in reports where applicable.]\n\n" + content[-(MAX_TEXT_WIDGET_CHARS - 6200):]
        text.configure(state="normal")
        text.delete("1.0", tk.END)
        text.insert(tk.END, content)
        text.configure(state="disabled")

    def append_text(self, frame, content):
        text = self.text_widget(frame)
        text.configure(state="normal")
        text.insert(tk.END, content)
        current_chars = int(float(text.index("end-1c").split(".")[0])) * 120
        if current_chars > MAX_TEXT_WIDGET_CHARS:
            text.delete("1.0", "200.0")
        text.see(tk.END)
        text.configure(state="disabled")

    def format_eta(self, seconds):
        try:
            seconds = max(0, int(seconds))
        except Exception:
            return "Unknown"
        h, rem = divmod(seconds, 3600)
        m, s = divmod(rem, 60)
        if h:
            return f"{h}h {m:02d}m"
        if m:
            return f"{m}m {s:02d}s"
        return f"{s}s"

    def update_scan_visualization(self, metrics):
        if not hasattr(self, "scan_viz"):
            return
        canvas = self.scan_viz
        canvas.delete("all")
        width = max(1, canvas.winfo_width() or 900)
        height = max(1, canvas.winfo_height() or 96)
        pad = 14
        bar_x = pad
        bar_y = 24
        bar_w = max(1, width - pad * 2)
        bar_h = 22
        test_size = max(1, int(metrics.get("test_size_bytes") or 1))
        processed = min(test_size, int(metrics.get("processed_bytes") or 0))
        verified = min(test_size, int(metrics.get("verified_bytes") or 0))
        corrupted = min(test_size, int(metrics.get("corrupted_bytes") or 0))
        failed = min(test_size, int(metrics.get("failed_bytes") or 0))

        canvas.create_rectangle(bar_x, bar_y, bar_x + bar_w, bar_y + bar_h, outline=CYBER_BORDER, fill="#0B1220")
        verified_w = bar_w * verified / test_size
        corrupt_w = bar_w * corrupted / test_size
        failed_w = bar_w * failed / test_size
        processed_w = bar_w * processed / test_size
        canvas.create_rectangle(bar_x, bar_y, bar_x + processed_w, bar_y + bar_h, outline="", fill="#12304A")
        canvas.create_rectangle(bar_x, bar_y, bar_x + verified_w, bar_y + bar_h, outline="", fill=CYBER_GREEN)
        canvas.create_rectangle(bar_x + verified_w, bar_y, bar_x + verified_w + corrupt_w, bar_y + bar_h, outline="", fill=CYBER_RED)
        canvas.create_rectangle(bar_x + verified_w + corrupt_w, bar_y, bar_x + verified_w + corrupt_w + failed_w, bar_y + bar_h, outline="", fill=CYBER_ORANGE)
        current_offset = int(metrics.get("current_offset") or 0)
        current_x = bar_x + min(bar_w, bar_w * current_offset / test_size)
        canvas.create_line(current_x, bar_y - 8, current_x, bar_y + bar_h + 8, fill=CYBER_CYAN, width=2)
        canvas.create_text(bar_x, 10, anchor="w", fill=CYBER_MUTED, font=("Consolas", 9), text="processed / verified / corrupted")
        canvas.create_text(bar_x, height - 24, anchor="w", fill=CYBER_GREEN, font=("Consolas", 9), text=f"Verified {human_bytes(verified)}")
        canvas.create_text(bar_x + bar_w * 0.38, height - 24, anchor="w", fill=CYBER_RED, font=("Consolas", 9), text=f"Corrupted {human_bytes(corrupted)}")
        canvas.create_text(bar_x + bar_w * 0.70, height - 24, anchor="w", fill=CYBER_CYAN, font=("Consolas", 9), text=f"Processed {human_bytes(processed)}")

    def update_live_findings_from_metrics(self, metrics):
        if not metrics.get("first_corruption_block") and not metrics.get("failed_blocks"):
            return
        lines = [
            "LIVE CORRUPTION TRACKING",
            "",
            f"Current phase: {metrics.get('phase', 'Unknown')}",
            f"Current block: {metrics.get('block', 0)} / {metrics.get('total_blocks', 0)}",
            f"Corrupted blocks: {metrics.get('corrupted_blocks', 0)}",
            f"Failed blocks: {metrics.get('failed_blocks', 0)}",
            f"Read failures: {metrics.get('read_failures', 0)}",
            f"Corruption percentage: {metrics.get('corruption_percent', 0):.2f}% of processed bytes",
            f"First corruption block: {metrics.get('first_corruption_block') or 'None'}",
            f"Consecutive corruption count: {metrics.get('consecutive_corruption_count', 0)}",
            f"Estimated valid capacity before corruption: {human_bytes(metrics.get('estimated_valid_capacity_bytes', 0))}",
            "",
            f"Processed: {human_bytes(metrics.get('processed_bytes', 0))}",
            f"Verified: {human_bytes(metrics.get('verified_bytes', 0))}",
            f"Corrupted: {human_bytes(metrics.get('corrupted_bytes', 0))}",
        ]
        self.set_text(self.findings_text, "\n".join(lines))

    def log_callback(self, message):
        logging.info(message)
        self.log_queue.put(message)

    def progress_callback(self, value):
        self.progress_queue.put(value)

    def metric_callback(self, metrics):
        self.metric_queue.put(metrics)

    def health_log_callback(self, message):
        logging.info(message)
        self.health_queue.put({"type": "log", "message": message})

    def health_status_callback(self, message):
        self.health_queue.put({"type": "status", "message": message})

    def health_progress_callback(self, value):
        self.health_queue.put({"type": "progress", "value": value})

    def selected_health_target(self):
        return self.get_selected_target_path() if hasattr(self, "drive_var") and self.drive_var.get() else (get_windows_drives()[0] if get_windows_drives() else "/")

    def _update_health_tab_scroll_region(self, _event=None):
        if hasattr(self, "health_tab_canvas"):
            self.health_tab_canvas.configure(scrollregion=self.health_tab_canvas.bbox("all"))

    def on_health_tab_resize(self, event=None):
        if hasattr(self, "health_tab_canvas") and hasattr(self, "health_tab_window"):
            width = event.width if event else self.health_tab_canvas.winfo_width()
            self.health_tab_canvas.itemconfigure(self.health_tab_window, width=max(1, width))
        self.rebuild_health_dashboard_layout()

    def calculate_health_card_columns(self, width, min_width=210, max_columns=5):
        usable = max(1, int(width or 1) - 32)
        return max(1, min(max_columns, usable // max(1, min_width)))

    def wrap_grid_widgets(self, frame, widgets, columns, padx=4, pady=4, min_width=190, min_height=86):
        if not frame:
            return
        for child in widgets:
            child.grid_forget()
        for col in range(12):
            frame.grid_columnconfigure(col, weight=0, minsize=0)
        columns = max(1, int(columns or 1))
        for col in range(columns):
            frame.grid_columnconfigure(col, weight=1, minsize=min_width)
        for idx, widget in enumerate(widgets):
            widget.grid(row=idx // columns, column=idx % columns, sticky="ew", padx=padx, pady=pady)
            try:
                widget.grid_propagate(False)
                widget.configure(width=min_width, height=min_height)
            except Exception:
                pass

    def wrap_health_action_buttons(self, frame, buttons, columns):
        if not frame:
            return
        for button in buttons:
            button.grid_forget()
        for col in range(12):
            frame.grid_columnconfigure(col, weight=0, minsize=0)
        columns = max(1, int(columns or 1))
        for col in range(columns):
            frame.grid_columnconfigure(col, weight=1, minsize=180)
        for idx, button in enumerate(buttons):
            button.grid(row=idx // columns, column=idx % columns, sticky="ew", padx=6, pady=6)

    def rebuild_health_dashboard_layout(self):
        if not hasattr(self, "health_tab_canvas"):
            return
        width = self.health_tab_canvas.winfo_width() or self.winfo_width() or 1200
        summary_cols = self.calculate_health_card_columns(width, min_width=205, max_columns=5)
        self.wrap_grid_widgets(
            getattr(self, "drive_health_summary_frame", None),
            getattr(self, "drive_health_summary_items", []),
            summary_cols,
            min_width=195,
            min_height=86,
        )
        manual_card_cols = self.calculate_health_card_columns(width, min_width=205, max_columns=4)
        self.wrap_grid_widgets(
            getattr(self, "manual_health_cards_frame", None),
            getattr(self, "manual_health_card_items", []),
            manual_card_cols,
            min_width=195,
            min_height=86,
        )
        dashboard_button_cols = 3 if width >= 920 else 2 if width >= 620 else 1
        if hasattr(self, "drive_health_dashboard_buttons_frame"):
            if width < 760:
                self.drive_health_dashboard_buttons_frame.grid(row=1, column=0, sticky="ew", padx=12, pady=(0, 10))
            else:
                self.drive_health_dashboard_buttons_frame.grid(row=0, column=1, sticky="e", padx=12, pady=8)
            self.wrap_health_action_buttons(self.drive_health_dashboard_buttons_frame, self.drive_health_dashboard_buttons, dashboard_button_cols)
        manual_button_cols = 4 if width >= 1120 else 3 if width >= 860 else 2 if width >= 620 else 1
        self.wrap_health_action_buttons(getattr(self, "manual_health_actions_frame", None), getattr(self, "manual_health_action_buttons", []), manual_button_cols)

        if hasattr(self, "health_dashboard_region") and hasattr(self, "drive_health_details_panel"):
            region = self.health_dashboard_region
            cards_shell = self.drive_health_cards_shell
            details = self.drive_health_details_panel
            cards_shell.grid_forget()
            details.grid_forget()
            for col in range(2):
                region.grid_columnconfigure(col, weight=0, minsize=0)
            if width >= 1080:
                region.grid_columnconfigure(0, weight=3, minsize=560)
                region.grid_columnconfigure(1, weight=2, minsize=390)
                region.grid_rowconfigure(0, weight=1, minsize=390)
                cards_shell.grid(row=0, column=0, sticky="nsew", padx=(0, 6), pady=0)
                details.grid(row=0, column=1, sticky="nsew", padx=(6, 0), pady=0)
                self.drive_health_canvas.configure(height=390)
            else:
                region.grid_columnconfigure(0, weight=1, minsize=0)
                region.grid_rowconfigure(0, weight=1, minsize=390)
                region.grid_rowconfigure(1, weight=1, minsize=300)
                cards_shell.grid(row=0, column=0, sticky="nsew", padx=0, pady=(0, 8))
                details.grid(row=1, column=0, sticky="nsew", padx=0, pady=(8, 0))
                self.drive_health_canvas.configure(height=430 if width >= 760 else 390)
        if hasattr(self, "drive_health_canvas"):
            self.render_drive_health_cards()
        self._update_health_tab_scroll_region()

    def _resize_drive_health_canvas_window(self, event=None):
        if hasattr(self, "drive_health_canvas") and hasattr(self, "drive_health_canvas_window"):
            width = event.width if event else self.drive_health_canvas.winfo_width()
            self.drive_health_canvas.itemconfigure(self.drive_health_canvas_window, width=max(1, width))
            self.render_drive_health_cards()

    def refresh_all_drive_health(self):
        if self.drive_health_thread and self.drive_health_thread.is_alive():
            if hasattr(self, "drive_health_status_var"):
                self.drive_health_status_var.set("Drive health dashboard is already scanning...")
            return
        if not hasattr(self, "drive_health_status_var"):
            return
        self.drive_health_loading = True
        self.drive_health_status_var.set("Scanning drives with safe read-only diagnostics...")
        self.render_drive_health_cards(loading=True)

        def worker():
            try:
                snapshots = collect_all_drive_health_snapshots(log_callback=lambda msg: self.health_queue.put({"type": "log", "message": msg}))
                self.health_queue.put({"type": "drive_health_complete", "snapshots": snapshots})
            except Exception as exc:
                logging.exception("Drive health dashboard refresh failed")
                self.health_queue.put({"type": "drive_health_error", "message": f"{type(exc).__name__}: {exc}"})

        self.drive_health_thread = threading.Thread(target=worker, daemon=True)
        self.drive_health_thread.start()

    def rescan_selected_drive_health(self):
        root = self.selected_drive_health_root or self.selected_health_target()
        if not root:
            messagebox.showinfo("Drive Health", "Select a drive card or target drive first.")
            return
        if self.drive_health_thread and self.drive_health_thread.is_alive():
            messagebox.showinfo("Drive Health", "A drive health refresh is already running.")
            return
        self.drive_health_status_var.set(f"Rescanning {root} with read-only diagnostics...")

        def worker():
            try:
                snapshots = collect_all_drive_health_snapshots(
                    log_callback=lambda msg: self.health_queue.put({"type": "log", "message": msg}),
                    roots=[root],
                )
                self.health_queue.put({"type": "drive_health_partial", "snapshots": snapshots})
            except Exception as exc:
                logging.exception("Selected drive health refresh failed")
                self.health_queue.put({"type": "drive_health_error", "message": f"{type(exc).__name__}: {exc}"})

        self.drive_health_thread = threading.Thread(target=worker, daemon=True)
        self.drive_health_thread.start()

    def update_drive_health_dashboard(self, snapshots):
        global LAST_HEALTH_SUMMARY
        self.drive_health_loading = False
        self.drive_health_snapshots = list(snapshots or [])
        if self.drive_health_snapshots and not self.selected_drive_health_root:
            self.selected_drive_health_root = self.drive_health_snapshots[0].root
        if self.selected_drive_health_root and not any(s.root == self.selected_drive_health_root for s in self.drive_health_snapshots):
            self.selected_drive_health_root = self.drive_health_snapshots[0].root if self.drive_health_snapshots else ""
        self.update_drive_health_summary_cards()
        self.render_drive_health_cards()
        self.update_drive_health_details()
        self.refresh_open_drive_detail_windows()
        LAST_HEALTH_SUMMARY["drive_snapshots"] = [asdict(item) for item in self.drive_health_snapshots]
        self.drive_health_status_var.set(
            f"Last refreshed {now_stamp()} - {len(self.drive_health_snapshots)} drive(s) detected."
            if self.drive_health_snapshots else
            "No storage drives detected by the health dashboard."
        )

    def merge_drive_health_snapshots(self, snapshots):
        if not snapshots:
            return
        existing = {item.root: item for item in self.drive_health_snapshots}
        for snapshot in snapshots:
            existing[snapshot.root] = snapshot
            self.selected_drive_health_root = snapshot.root
        ordered_roots = [item.root for item in self.drive_health_snapshots if item.root in existing]
        for snapshot in snapshots:
            if snapshot.root not in ordered_roots:
                ordered_roots.append(snapshot.root)
        self.update_drive_health_dashboard([existing[root] for root in ordered_roots])

    def update_drive_health_summary_cards(self):
        if not hasattr(self, "drive_health_summary_cards"):
            return
        counts = {"Total Drives": len(self.drive_health_snapshots), "Healthy": 0, "Warning": 0, "Critical": 0, "Unknown": 0}
        for snapshot in self.drive_health_snapshots:
            status = str(snapshot.health_status).upper()
            if "CRITICAL" in status:
                counts["Critical"] += 1
            elif "WARNING" in status:
                counts["Warning"] += 1
            elif "GOOD" in status or "HEALTHY" in status:
                counts["Healthy"] += 1
            else:
                counts["Unknown"] += 1
        for title, value in counts.items():
            card = self.drive_health_summary_cards.get(title)
            if card:
                card.value_label.config(text=str(value))

    def render_drive_health_cards(self, loading=False):
        if not hasattr(self, "drive_health_grid"):
            return
        for child in self.drive_health_grid.winfo_children():
            child.destroy()
        self.drive_health_card_widgets = {}
        if loading:
            tk.Label(
                self.drive_health_grid,
                text="Scanning drives...",
                bg=CYBER_BG,
                fg=CYBER_CYAN,
                font=("Consolas", 14, "bold"),
            ).grid(row=0, column=0, sticky="w", padx=18, pady=18)
            return
        if not self.drive_health_snapshots:
            tk.Label(
                self.drive_health_grid,
                text="No drive health snapshots available. Click Refresh All Drives.",
                bg=CYBER_BG,
                fg=CYBER_MUTED,
                font=("Segoe UI", 11),
            ).grid(row=0, column=0, sticky="w", padx=18, pady=18)
            return
        width = self.drive_health_canvas.winfo_width() if hasattr(self, "drive_health_canvas") else 1000
        columns = 2 if width >= 760 else 1
        for col in range(4):
            self.drive_health_grid.grid_columnconfigure(col, weight=0, minsize=0)
        for col in range(columns):
            self.drive_health_grid.grid_columnconfigure(col, weight=1, minsize=340)
        for idx, snapshot in enumerate(self.drive_health_snapshots):
            card = self.create_drive_health_card(self.drive_health_grid, snapshot)
            card.grid(row=idx // columns, column=idx % columns, sticky="nsew", padx=8, pady=8)
            self.drive_health_card_widgets[snapshot.root] = card
        self.drive_health_grid.update_idletasks()
        self.drive_health_canvas.configure(scrollregion=self.drive_health_canvas.bbox("all"))

    def drive_health_card_stats(self, snapshot: DriveHealthSnapshot):
        base = [
            ("Capacity", human_bytes(snapshot.capacity)),
            ("Free", human_bytes(snapshot.free)),
            ("Interface", snapshot.bus_type),
            ("Media", snapshot.media_type),
        ]
        parsed = snapshot.smart_parsed or {}
        is_nvme = is_nvme_drive(snapshot.bus_type, snapshot.media_type, snapshot.model, snapshot.raw_smart_preview)
        is_ssd = is_ssd_drive(snapshot.bus_type, snapshot.media_type, snapshot.model, snapshot.raw_smart_preview)
        is_hdd = is_hdd_drive(snapshot.bus_type, snapshot.media_type, snapshot.model, snapshot.raw_smart_preview, snapshot.drive_type)
        is_usb = is_usb_bridge_device(snapshot.bus_type, snapshot.media_type, snapshot.model, snapshot.raw_smart_preview, snapshot.drive_type, snapshot.smart_status)
        if is_nvme or is_ssd:
            return base + [
                ("Temp", snapshot.temperature),
                ("Wear", snapshot.wear),
                ("Media Errors", str(snapshot.nvme_media_errors)),
                ("Power Hours", snapshot.power_on_hours),
                ("Spare", f"{safe_int(parsed.get('nvme_available_spare'), 0)}%" if safe_int(parsed.get("nvme_available_spare"), 0) else "Not Reported"),
                ("Data Written", str(parsed.get("nvme_data_units_written", "Not Reported"))),
            ]
        if is_hdd:
            return base + [
                ("Reallocated", str(snapshot.reallocated)),
                ("Pending", str(snapshot.pending)),
                ("Uncorrectable", str(snapshot.uncorrectable)),
                ("CRC", str(snapshot.crc_errors)),
                ("Spin Retry", str(parsed.get("spin_retry_count", "Not Reported"))),
                ("Power Hours", snapshot.power_on_hours),
            ]
        if is_usb:
            return base + [
                ("SMART", snapshot.smart_status or "SMART Unavailable"),
                ("Temp", snapshot.temperature),
                ("Wear", snapshot.wear),
                ("Controller", "Visible" if snapshot.smart_parsed else "Not Exposed"),
                ("Capacity", f"{human_bytes(snapshot.free)} free"),
                ("CRC", str(snapshot.crc_errors)),
            ]
        return base + [
            ("SMART", snapshot.smart_status or "SMART Unavailable"),
            ("Temp", snapshot.temperature),
            ("Wear", snapshot.wear),
            ("Power Hours", snapshot.power_on_hours),
            ("Pending", str(snapshot.pending)),
            ("CRC", str(snapshot.crc_errors)),
        ]

    def create_drive_health_card(self, parent, snapshot: DriveHealthSnapshot):
        selected = snapshot.root == self.selected_drive_health_root
        accent = health_status_color(snapshot.health_status)
        border = CYBER_CYAN if selected else accent
        frame = tk.Frame(parent, bg=CYBER_PANEL, highlightbackground=border, highlightcolor=CYBER_CYAN, highlightthickness=2 if selected else 1, padx=12, pady=10)
        frame.configure(height=300)
        frame.grid_columnconfigure(0, weight=1)
        header = tk.Frame(frame, bg=CYBER_PANEL)
        header.grid(row=0, column=0, sticky="ew")
        header.grid_columnconfigure(0, weight=1)
        title = f"{snapshot.drive_letter} {snapshot.model}"
        tk.Label(header, text=title, bg=CYBER_PANEL, fg=CYBER_TEXT, font=("Consolas", 12, "bold"), wraplength=360, justify="left").grid(row=0, column=0, sticky="w")
        tk.Label(header, text=snapshot.health_status, bg=accent, fg="#FFFFFF", font=("Consolas", 9, "bold"), padx=8, pady=3).grid(row=0, column=1, sticky="e", padx=(8, 0))
        tk.Label(frame, text=f"{snapshot.display_name}", bg=CYBER_PANEL, fg=CYBER_MUTED, font=("Segoe UI", 9), wraplength=460, justify="left").grid(row=1, column=0, sticky="w", pady=(4, 8))

        score_shell = tk.Frame(frame, bg=CYBER_PANEL)
        score_shell.grid(row=2, column=0, sticky="ew", pady=(0, 8))
        score_shell.grid_columnconfigure(1, weight=1)
        tk.Label(score_shell, text=f"{snapshot.health_score}/100", bg=CYBER_PANEL, fg=accent, font=("Consolas", 18, "bold")).grid(row=0, column=0, sticky="w")
        bar = tk.Canvas(score_shell, height=12, bg=CYBER_PANEL, highlightthickness=0)
        bar.grid(row=0, column=1, sticky="ew", padx=(12, 0))
        bar.bind("<Configure>", lambda e, s=snapshot, c=bar, a=accent: self.draw_health_score_bar(c, s.health_score, a))

        grid = tk.Frame(frame, bg=CYBER_PANEL)
        grid.grid(row=3, column=0, sticky="ew")
        for i in range(2):
            grid.grid_columnconfigure(i, weight=1)
        stats = self.drive_health_card_stats(snapshot)
        for idx, (label, value) in enumerate(stats):
            cell = tk.Frame(grid, bg=CYBER_PANEL_2, highlightbackground=CYBER_BORDER, highlightthickness=1, padx=7, pady=5)
            cell.grid(row=idx // 2, column=idx % 2, sticky="ew", padx=3, pady=3)
            tk.Label(cell, text=label.upper(), bg=CYBER_PANEL_2, fg=CYBER_MUTED, font=("Segoe UI", 7, "bold")).pack(anchor="w")
            tk.Label(cell, text=value or "Unknown", bg=CYBER_PANEL_2, fg=CYBER_TEXT, font=("Consolas", 9, "bold"), wraplength=180, justify="left").pack(anchor="w")

        footer = tk.Frame(frame, bg=CYBER_PANEL)
        footer.grid(row=4, column=0, sticky="ew", pady=(8, 0))
        footer.grid_columnconfigure(0, weight=1)
        tk.Label(footer, text=snapshot.recommendation, bg=CYBER_PANEL, fg=accent, font=("Segoe UI", 9, "bold"), wraplength=320, justify="left").grid(row=0, column=0, sticky="w")
        ttk.Button(footer, text="View Full Details", style="Cyber.TButton", command=lambda r=snapshot.root: self.open_drive_full_details(r)).grid(row=0, column=1, sticky="e", padx=(8, 0))

        def select(_event=None, root=snapshot.root):
            self.select_drive_health_card(root)
            return "break"

        for widget in (frame, header, score_shell, grid, footer):
            widget.bind("<Button-1>", select, add="+")
            self.bind_mousewheel(widget, self.drive_health_canvas)
        self.bind_mousewheel_recursive(frame, self.drive_health_canvas)
        return frame

    def draw_health_score_bar(self, canvas, score, color):
        canvas.delete("all")
        width = max(1, canvas.winfo_width())
        height = max(1, canvas.winfo_height())
        canvas.create_rectangle(0, 0, width, height, outline=CYBER_BORDER, fill="#07101D")
        fill = width * max(0, min(100, int(score))) / 100
        canvas.create_rectangle(0, 0, fill, height, outline=color, fill=color)

    def select_drive_health_card(self, root):
        self.selected_drive_health_root = root
        self.render_drive_health_cards()
        self.update_drive_health_details()

    def open_drive_full_details(self, root):
        self.select_drive_health_card(root)
        snapshot = self.selected_drive_health_snapshot()
        if not snapshot:
            messagebox.showinfo("Drive Details", "No drive health snapshot is available for this device.")
            return
        existing = self.drive_detail_windows.get(root)
        if existing and existing.get("window") and existing["window"].winfo_exists():
            existing["window"].lift()
            existing["window"].focus_force()
            self.populate_drive_detail_window(root)
            return
        win = tk.Toplevel(self)
        win.title(f"{APP_NAME} - Full Drive Diagnostics")
        win.configure(bg=CYBER_BG)
        win.geometry("1200x800")
        win.minsize(980, 680)
        try:
            icon_path = Path(APP_ICON_PATH)
            if icon_path.is_file():
                win.iconbitmap(str(icon_path))
        except Exception:
            pass
        self.center_toplevel(win, 1200, 800)
        win.grid_columnconfigure(0, weight=1)
        win.grid_rowconfigure(1, weight=1)
        header = self.make_panel(win)
        header.grid(row=0, column=0, sticky="ew", padx=10, pady=(10, 6))
        header.grid_columnconfigure(0, weight=1)
        title_var = tk.StringVar(value="")
        subtitle_var = tk.StringVar(value="")
        tk.Label(header, textvariable=title_var, bg=CYBER_PANEL, fg=CYBER_CYAN, font=("Consolas", 16, "bold")).grid(row=0, column=0, sticky="w", padx=14, pady=(12, 2))
        tk.Label(header, textvariable=subtitle_var, bg=CYBER_PANEL, fg=CYBER_TEXT, font=("Segoe UI", 10), wraplength=860, justify="left").grid(row=1, column=0, sticky="w", padx=14, pady=(0, 12))
        action_frame = tk.Frame(header, bg=CYBER_PANEL)
        action_frame.grid(row=0, column=1, rowspan=2, sticky="e", padx=12, pady=10)
        notebook = ttk.Notebook(win, style="Cyber.TNotebook")
        notebook.grid(row=1, column=0, sticky="nsew", padx=10, pady=(0, 10))
        state = {
            "window": win,
            "title_var": title_var,
            "subtitle_var": subtitle_var,
            "notebook": notebook,
            "tabs": {},
            "widgets": {},
            "action_frame": action_frame,
        }
        self.drive_detail_windows[root] = state
        win.protocol("WM_DELETE_WINDOW", lambda r=root: self.close_drive_detail_window(r))
        self.build_drive_detail_tabs(root)
        self.populate_drive_detail_window(root)

    def center_toplevel(self, win, width, height):
        try:
            self.update_idletasks()
            x = self.winfo_rootx() + max(0, (self.winfo_width() - width) // 2)
            y = self.winfo_rooty() + max(0, (self.winfo_height() - height) // 2)
            win.geometry(f"{width}x{height}+{x}+{y}")
        except Exception:
            pass

    def close_drive_detail_window(self, root):
        state = self.drive_detail_windows.pop(root, None)
        if state and state.get("window") and state["window"].winfo_exists():
            state["window"].destroy()

    def refresh_open_drive_detail_windows(self):
        stale = []
        for root, state in list(getattr(self, "drive_detail_windows", {}).items()):
            if not state.get("window") or not state["window"].winfo_exists():
                stale.append(root)
                continue
            self.populate_drive_detail_window(root)
        for root in stale:
            self.drive_detail_windows.pop(root, None)

    def build_drive_detail_tabs(self, root):
        state = self.drive_detail_windows[root]
        nb = state["notebook"]
        for name in ("Overview", "SMART Details", "Health Analysis", "Surface Stability", "Raw SMART Output", "History / Timeline"):
            frame = tk.Frame(nb, bg=CYBER_BG)
            frame.grid_columnconfigure(0, weight=1)
            frame.grid_rowconfigure(0, weight=1)
            nb.add(frame, text=name)
            state["tabs"][name] = frame
        state["widgets"]["overview"] = self.create_scrollable_detail_tab(state["tabs"]["Overview"])
        state["widgets"]["smart"] = self.create_scrollable_detail_tab(state["tabs"]["SMART Details"])
        state["widgets"]["analysis"] = self.create_scrollable_detail_tab(state["tabs"]["Health Analysis"])
        state["widgets"]["surface"] = self.create_scrollable_detail_tab(state["tabs"]["Surface Stability"])
        raw_panel = self.make_panel(state["tabs"]["Raw SMART Output"])
        raw_panel.grid(row=0, column=0, sticky="nsew", padx=8, pady=8)
        raw_panel.grid_columnconfigure(0, weight=1)
        raw_panel.grid_rowconfigure(2, weight=1)
        raw_tools = tk.Frame(raw_panel, bg=CYBER_PANEL)
        raw_tools.grid(row=0, column=0, sticky="ew", padx=12, pady=(12, 8))
        raw_tools.grid_columnconfigure(2, weight=1)
        search_var = tk.StringVar()
        tk.Label(raw_tools, text="SEARCH", bg=CYBER_PANEL, fg=CYBER_MUTED, font=("Segoe UI", 8, "bold")).grid(row=0, column=0, sticky="w", padx=(0, 6))
        search_entry = self.neon_entry(raw_tools, search_var)
        search_entry.grid(row=0, column=1, sticky="ew", padx=(0, 8))
        ttk.Button(raw_tools, text="Find", style="Cyber.TButton", command=lambda r=root: self.search_raw_smart_output(r)).grid(row=0, column=2, sticky="w", padx=4)
        ttk.Button(raw_tools, text="Copy to Clipboard", style="Cyber.TButton", command=lambda r=root: self.copy_raw_smart_output(r)).grid(row=0, column=3, sticky="e", padx=4)
        ttk.Button(raw_tools, text="Save Raw Output", style="Cyber.TButton", command=lambda r=root: self.save_raw_smart_output(r)).grid(row=0, column=4, sticky="e", padx=4)
        raw_text = self.make_text(raw_panel, height=28)
        raw_text.grid(row=2, column=0, sticky="nsew", padx=12, pady=(0, 12))
        state["widgets"]["raw_search_var"] = search_var
        state["widgets"]["raw_text"] = raw_text
        state["widgets"]["history"] = self.create_scrollable_detail_tab(state["tabs"]["History / Timeline"])

    def create_scrollable_detail_tab(self, parent):
        canvas = tk.Canvas(parent, bg=CYBER_BG, highlightthickness=0, bd=0)
        scroll = ttk.Scrollbar(parent, orient="vertical", command=canvas.yview, style="Cyber.Vertical.TScrollbar")
        canvas.configure(yscrollcommand=scroll.set)
        canvas.grid(row=0, column=0, sticky="nsew")
        scroll.grid(row=0, column=1, sticky="ns")
        frame = tk.Frame(canvas, bg=CYBER_BG)
        window = canvas.create_window((0, 0), window=frame, anchor="nw")
        frame.bind("<Configure>", lambda _event, c=canvas: c.configure(scrollregion=c.bbox("all")))
        canvas.bind("<Configure>", lambda event, c=canvas, w=window: c.itemconfigure(w, width=max(1, event.width)))
        self.bind_mousewheel(canvas, canvas)
        self.bind_mousewheel(frame, canvas)
        return {"canvas": canvas, "frame": frame}

    def clear_frame(self, frame):
        for child in frame.winfo_children():
            child.destroy()

    def detail_panel(self, parent, title, accent=CYBER_CYAN):
        panel = tk.Frame(parent, bg=CYBER_PANEL, highlightbackground=accent, highlightthickness=1, padx=14, pady=12)
        panel.grid_columnconfigure(0, weight=1)
        tk.Label(panel, text=title, bg=CYBER_PANEL, fg=accent, font=("Consolas", 12, "bold")).grid(row=0, column=0, sticky="w", pady=(0, 10))
        return panel

    def populate_drive_detail_window(self, root):
        state = self.drive_detail_windows.get(root)
        if not state or not state.get("window") or not state["window"].winfo_exists():
            return
        snapshot = next((item for item in self.drive_health_snapshots if item.root == root), None)
        if not snapshot:
            snapshot = self.selected_drive_health_snapshot()
        if not snapshot:
            return
        state["title_var"].set(f"{snapshot.drive_letter} {snapshot.model} - Full Drive Diagnostics")
        state["subtitle_var"].set(f"{snapshot.display_name} | {snapshot.recommendation} | Last checked {snapshot.last_checked}")
        self.populate_drive_detail_actions(root, snapshot)
        self.populate_detail_overview(root, snapshot)
        self.populate_detail_smart(root, snapshot)
        self.populate_detail_analysis(root, snapshot)
        self.populate_detail_surface(root, snapshot)
        self.populate_detail_raw(root, snapshot)
        self.populate_detail_history(root, snapshot)

    def populate_drive_detail_actions(self, root, snapshot):
        state = self.drive_detail_windows[root]
        frame = state["action_frame"]
        for child in frame.winfo_children():
            child.destroy()
        buttons = [
            ("Refresh Diagnostics", lambda: self.rescan_drive_from_detail(root)),
            ("Re-run SMART Analysis", lambda: self.run_detail_health_task(root, "SMART Health Analyzer", lambda runner: runner.run_smart_check())),
            ("Re-run Windows Health", lambda: self.run_detail_health_task(root, "Windows Health Analyzer", lambda runner: runner.run_windows_health_check())),
            ("Read-Only CHKDSK", lambda: self.run_detail_health_task(root, "Read-Only CHKDSK Preview", lambda runner: runner.run_read_only_chkdsk())),
            ("Surface Stability Scan", lambda: self.run_detail_surface_scan(root)),
            ("Copy Device Summary", lambda: self.copy_device_summary(snapshot)),
            ("Export TXT", lambda: self.export_single_drive_health_report(snapshot, "txt")),
            ("Export JSON", lambda: self.export_single_drive_health_report(snapshot, "json")),
            ("Export HTML", lambda: self.export_single_drive_health_report(snapshot, "html")),
            ("Export PDF", lambda: self.export_single_drive_health_report(snapshot, "pdf")),
        ]
        for col in range(5):
            frame.grid_columnconfigure(col, weight=1, minsize=145)
        for idx, (label, command) in enumerate(buttons):
            ttk.Button(frame, text=label, style="Cyber.TButton", command=command).grid(row=idx // 5, column=idx % 5, sticky="ew", padx=4, pady=4)

    def populate_detail_overview(self, root, snapshot):
        frame = self.drive_detail_windows[root]["widgets"]["overview"]["frame"]
        self.clear_frame(frame)
        frame.grid_columnconfigure(0, weight=1)
        accent = health_status_color(snapshot.health_status)
        badge = self.detail_panel(frame, "HEALTH OVERVIEW", accent)
        badge.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        badge.grid_columnconfigure(1, weight=1)
        tk.Label(badge, text=snapshot.health_status, bg=accent, fg="#FFFFFF", font=("Consolas", 22, "bold"), padx=18, pady=10).grid(row=1, column=0, sticky="w", padx=(0, 14))
        tk.Label(badge, text=f"Health Score: {snapshot.health_score}/100\n{snapshot.recommendation}", bg=CYBER_PANEL, fg=CYBER_TEXT, font=("Consolas", 13, "bold"), justify="left").grid(row=1, column=1, sticky="w")
        score_bar = tk.Canvas(badge, height=18, bg=CYBER_PANEL, highlightthickness=0)
        score_bar.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(12, 4))
        score_bar.bind("<Configure>", lambda _e, c=score_bar, s=snapshot, a=accent: self.draw_health_score_bar(c, s.health_score, a))
        cap_bar = tk.Canvas(badge, height=18, bg=CYBER_PANEL, highlightthickness=0)
        cap_bar.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(8, 4))
        cap_bar.bind("<Configure>", lambda _e, c=cap_bar, s=snapshot: self.draw_capacity_bar(c, s))
        tk.Label(badge, text=f"Temperature: {snapshot.temperature}", bg=CYBER_PANEL, fg=CYBER_YELLOW, font=("Consolas", 12, "bold")).grid(row=4, column=0, columnspan=2, sticky="w", pady=(8, 0))

        identity = self.detail_panel(frame, "DRIVE IDENTITY", CYBER_CYAN)
        identity.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        items = [
            ("Drive Letter", snapshot.drive_letter),
            ("Root Path", snapshot.root),
            ("Volume Label", snapshot.volume_label),
            ("Model", snapshot.model),
            ("Manufacturer", snapshot.manufacturer),
            ("Serial Number", snapshot.serial),
            ("Firmware Version", snapshot.firmware),
            ("Capacity", human_bytes(snapshot.capacity)),
            ("Free Space", human_bytes(snapshot.free)),
            ("Used Space", human_bytes(snapshot.used)),
            ("File System", snapshot.filesystem),
            ("Bus Type", snapshot.bus_type),
            ("Media Type", snapshot.media_type),
            ("SMART Status", snapshot.smart_status),
            ("Windows Health", snapshot.windows_status),
            ("Last Checked", snapshot.last_checked),
        ]
        self.add_key_value_grid(identity, items, start_row=1)

    def draw_capacity_bar(self, canvas, snapshot):
        canvas.delete("all")
        width = max(1, canvas.winfo_width())
        height = max(1, canvas.winfo_height())
        used_ratio = snapshot.used / max(1, snapshot.capacity)
        canvas.create_rectangle(0, 0, width, height, outline=CYBER_BORDER, fill="#07101D")
        canvas.create_rectangle(0, 0, width * used_ratio, height, outline=CYBER_BLUE, fill=CYBER_BLUE)
        canvas.create_text(8, height / 2, anchor="w", fill="#FFFFFF", font=("Consolas", 9, "bold"), text=f"Capacity used {used_ratio * 100:.1f}%")

    def add_key_value_grid(self, parent, items, start_row=0):
        for col in range(2):
            parent.grid_columnconfigure(col, weight=1)
        for idx, (label, value) in enumerate(items):
            cell = tk.Frame(parent, bg=CYBER_PANEL_2, highlightbackground=CYBER_BORDER, highlightthickness=1, padx=9, pady=7)
            cell.grid(row=start_row + idx // 2, column=idx % 2, sticky="ew", padx=4, pady=4)
            tk.Label(cell, text=label.upper(), bg=CYBER_PANEL_2, fg=CYBER_MUTED, font=("Segoe UI", 8, "bold")).pack(anchor="w")
            tk.Label(cell, text=str(value or "Not Reported"), bg=CYBER_PANEL_2, fg=CYBER_TEXT, font=("Consolas", 10, "bold"), wraplength=430, justify="left").pack(anchor="w", pady=(2, 0))

    def smart_attribute_rows(self, snapshot):
        parsed = snapshot.smart_parsed or {}
        raw_map = {
            "Reallocated_Sector_Ct": ("reallocated_sector_count", snapshot.reallocated, 0, 10),
            "Current_Pending_Sector": ("current_pending_sector_count", snapshot.pending, 0, 1),
            "Offline_Uncorrectable": ("offline_uncorrectable", snapshot.uncorrectable, 0, 1),
            "UDMA_CRC_Error_Count": ("udma_crc_error_count", snapshot.crc_errors, 0, 10),
            "Power_On_Hours": ("power_on_hours", snapshot.power_on_hours, None, None),
            "Power_Cycle_Count": ("power_cycle_count", snapshot.power_cycle_count, None, None),
            "Temperature_Celsius": ("temperature_celsius", snapshot.temperature, 50, 60),
            "Percentage Used": ("percentage_used", parsed.get("percentage_used", "Not Reported"), 70, 90),
            "Available Spare": ("nvme_available_spare", parsed.get("nvme_available_spare", "Not Reported"), 30, 10),
            "Unsafe Shutdowns": ("unsafe_shutdowns", parsed.get("unsafe_shutdowns", "Not Reported"), 1, 20),
            "Media and Data Integrity Errors": ("nvme_media_data_integrity_errors", snapshot.nvme_media_errors, 0, 1),
            "Spin_Retry_Count": ("spin_retry_count", parsed.get("spin_retry_count", "Not Reported"), 0, 1),
            "Seek_Error_Rate": ("seek_error_rate", parsed.get("seek_error_rate", "Not Reported"), None, None),
            "Start_Stop_Count": ("start_stop_count", parsed.get("start_stop_count", "Not Reported"), None, None),
            "Load_Cycle_Count": ("load_cycle_count", parsed.get("load_cycle_count", "Not Reported"), None, None),
        }
        rows = []
        for attr, (key, value, warn, critical) in raw_map.items():
            raw_value = parsed.get(key, value)
            numeric = safe_int(raw_value, -1)
            status = "Healthy"
            color = CYBER_GREEN
            if attr == "Available Spare" and numeric >= 0:
                if numeric <= critical:
                    status, color = "Critical", CYBER_RED
                elif numeric <= warn:
                    status, color = "Warning", CYBER_ORANGE
            elif numeric >= 0 and warn is not None and critical is not None:
                if numeric >= critical:
                    status, color = "Critical", CYBER_RED
                elif numeric > warn:
                    status, color = "Warning", CYBER_ORANGE
            elif raw_value == "Not Reported":
                status, color = "Not Reported", CYBER_MUTED
            rows.append(
                {
                    "attribute": attr,
                    "current": parsed.get(f"{key}_current", "N/A"),
                    "worst": parsed.get(f"{key}_worst", "N/A"),
                    "threshold": parsed.get(f"{key}_threshold", "N/A"),
                    "raw": raw_value,
                    "status": status,
                    "color": color,
                }
            )
        return rows

    def populate_detail_smart(self, root, snapshot):
        frame = self.drive_detail_windows[root]["widgets"]["smart"]["frame"]
        self.clear_frame(frame)
        panel = self.detail_panel(frame, "SMART ATTRIBUTE TABLE", CYBER_CYAN)
        panel.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        headers = ("Attribute", "Current", "Worst", "Threshold", "Raw Value", "Status")
        for col, header in enumerate(headers):
            panel.grid_columnconfigure(col, weight=1 if col in (0, 4) else 0)
            tk.Label(panel, text=header.upper(), bg=CYBER_PANEL, fg=CYBER_MUTED, font=("Segoe UI", 8, "bold")).grid(row=1, column=col, sticky="ew", padx=4, pady=4)
        rows = self.smart_attribute_rows(snapshot)
        if not rows:
            tk.Label(panel, text="SMART attributes are not available for this device.", bg=CYBER_PANEL, fg=CYBER_MUTED).grid(row=2, column=0, columnspan=6, sticky="w", padx=4, pady=8)
            return
        for ridx, row in enumerate(rows, start=2):
            values = (row["attribute"], row["current"], row["worst"], row["threshold"], row["raw"], row["status"])
            for col, value in enumerate(values):
                fg = row["color"] if col == 5 else CYBER_TEXT
                tk.Label(panel, text=str(value), bg=CYBER_PANEL_2, fg=fg, font=("Consolas", 9, "bold" if col in (0, 5) else "normal"), anchor="w", padx=7, pady=5, wraplength=260).grid(row=ridx, column=col, sticky="ew", padx=2, pady=2)

    def populate_detail_analysis(self, root, snapshot):
        frame = self.drive_detail_windows[root]["widgets"]["analysis"]["frame"]
        self.clear_frame(frame)
        summary = self.detail_panel(frame, "HEALTH SCORE BREAKDOWN", health_status_color(snapshot.health_status))
        summary.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        tk.Label(summary, text=f"Health Score: {snapshot.health_score}/100", bg=CYBER_PANEL, fg=health_status_color(snapshot.health_status), font=("Consolas", 20, "bold")).grid(row=1, column=0, sticky="w")
        tk.Label(summary, text=f"Recommendation: {snapshot.recommendation}", bg=CYBER_PANEL, fg=CYBER_TEXT, font=("Segoe UI", 11, "bold"), wraplength=980, justify="left").grid(row=2, column=0, sticky="w", pady=(8, 0))
        issues_panel = self.detail_panel(frame, "TRIGGERED ISSUES / RISK FACTORS", CYBER_YELLOW)
        issues_panel.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        issues = snapshot.issues or []
        if not issues:
            tk.Label(issues_panel, text="No health-specific findings recorded.", bg=CYBER_PANEL, fg=CYBER_GREEN, font=("Consolas", 11, "bold")).grid(row=1, column=0, sticky="w")
        for idx, issue in enumerate(issues, start=1):
            severity = issue.get("severity", "Info")
            color = CYBER_RED if severity in ("Critical", "High") else CYBER_ORANGE if severity in ("Warning", "Medium") else CYBER_CYAN
            card = tk.Frame(issues_panel, bg=CYBER_PANEL_2, highlightbackground=color, highlightthickness=1, padx=10, pady=8)
            card.grid(row=idx, column=0, sticky="ew", pady=5)
            card.grid_columnconfigure(0, weight=1)
            tk.Label(card, text=f"{severity}: {issue.get('title', 'Finding')}", bg=CYBER_PANEL_2, fg=color, font=("Consolas", 11, "bold")).grid(row=0, column=0, sticky="w")
            tk.Label(card, text=issue.get("detail", ""), bg=CYBER_PANEL_2, fg=CYBER_TEXT, font=("Segoe UI", 10), wraplength=980, justify="left").grid(row=1, column=0, sticky="w", pady=(4, 0))
        diag = self.detail_panel(frame, "DIAGNOSTIC SUMMARY", CYBER_CYAN)
        diag.grid(row=2, column=0, sticky="ew", padx=10, pady=10)
        self.add_key_value_grid(
            diag,
            [
                ("SMART Status", snapshot.smart_status),
                ("Windows Health", snapshot.windows_status),
                ("Temperature", snapshot.temperature),
                ("Wear", snapshot.wear),
                ("Reallocated", snapshot.reallocated),
                ("Pending", snapshot.pending),
                ("Uncorrectable", snapshot.uncorrectable),
                ("CRC Errors", snapshot.crc_errors),
            ],
            start_row=1,
        )

    def latest_surface_result_for_root(self, root):
        result = getattr(self, "last_health_result", None)
        if result and normalize_drive_root(result.target).lower() == normalize_drive_root(root).lower() and result.surface_results:
            return result.surface_results
        return {}

    def populate_detail_surface(self, root, snapshot):
        frame = self.drive_detail_windows[root]["widgets"]["surface"]["frame"]
        self.clear_frame(frame)
        surface = self.latest_surface_result_for_root(root)
        panel = self.detail_panel(frame, "SURFACE READ STABILITY", CYBER_CYAN)
        panel.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        if not surface:
            tk.Label(panel, text="No surface read stability analysis has been performed.", bg=CYBER_PANEL, fg=CYBER_MUTED, font=("Segoe UI", 11)).grid(row=1, column=0, sticky="w")
            return
        self.add_key_value_grid(
            panel,
            [
                ("Status", surface.get("status", "Unknown")),
                ("Average Read Speed", f"{surface.get('average_mb_s', 'Unknown')} MB/s"),
                ("Sampled Bytes", surface.get("sampled_human", human_bytes(surface.get("sampled_bytes", 0)))),
                ("Files Seen", surface.get("files_seen", "Unknown")),
                ("Inaccessible Files", surface.get("inaccessible_files", "Unknown")),
                ("Recommendation", surface.get("recommendation", "N/A")),
            ],
            start_row=1,
        )
        log_panel = self.detail_panel(frame, "SLOW REGIONS / READ FAILURES", CYBER_YELLOW)
        log_panel.grid(row=1, column=0, sticky="ew", padx=10, pady=10)
        text = self.make_text(log_panel, height=16)
        text.grid(row=1, column=0, sticky="nsew")
        self.set_text(text, json.dumps({"slow_samples": surface.get("slow_samples", []), "read_failures": surface.get("read_failures", [])}, indent=2))

    def populate_detail_raw(self, root, snapshot):
        raw_text = self.drive_detail_windows[root]["widgets"]["raw_text"]
        self.set_text(raw_text, snapshot.raw_smart_preview or "No raw SMART output available for this device.")

    def populate_detail_history(self, root, snapshot):
        frame = self.drive_detail_windows[root]["widgets"]["history"]["frame"]
        self.clear_frame(frame)
        panel = self.detail_panel(frame, "HEALTH HISTORY / TIMELINE", CYBER_CYAN)
        panel.grid(row=0, column=0, sticky="ew", padx=10, pady=10)
        entries = []
        try:
            target_root = normalize_drive_root(root).lower()
            for item in load_health_history():
                target = str(item.get("target", ""))
                if target and (target.lower() == root.lower() or normalize_drive_root(target).lower() == target_root or target == "All detected drives"):
                    entries.append(item)
        except Exception:
            entries = []
        if not entries:
            tk.Label(panel, text="No historical diagnostics available.", bg=CYBER_PANEL, fg=CYBER_MUTED, font=("Segoe UI", 11)).grid(row=1, column=0, sticky="w")
            return
        headers = ("Time", "Status", "Risk", "Recommendation", "Report")
        for col, header in enumerate(headers):
            panel.grid_columnconfigure(col, weight=1)
            tk.Label(panel, text=header.upper(), bg=CYBER_PANEL, fg=CYBER_MUTED, font=("Segoe UI", 8, "bold")).grid(row=1, column=col, sticky="ew", padx=3, pady=3)
        for ridx, item in enumerate(entries[:80], start=2):
            values = (item.get("completed_at"), item.get("health_status"), item.get("health_risk_score"), item.get("recommendation"), item.get("report_html") or item.get("report_txt") or "")
            for col, value in enumerate(values):
                tk.Label(panel, text=str(value or "N/A"), bg=CYBER_PANEL_2, fg=CYBER_TEXT, font=("Consolas", 9), anchor="w", wraplength=280, padx=6, pady=5).grid(row=ridx, column=col, sticky="ew", padx=2, pady=2)

    def device_summary_text(self, snapshot: DriveHealthSnapshot):
        return "\n".join(
            [
                f"{snapshot.model} ({snapshot.drive_letter})",
                f"{snapshot.bus_type} {snapshot.media_type}".strip(),
                f"Root: {snapshot.root}",
                f"Capacity: {human_bytes(snapshot.capacity)}",
                f"Health Score: {snapshot.health_score}/100",
                f"SMART Status: {snapshot.smart_status}",
                f"Windows Health: {snapshot.windows_status}",
                f"Temperature: {snapshot.temperature}",
                f"Wear: {snapshot.wear}",
                f"Recommendation: {snapshot.recommendation}",
            ]
        )

    def copy_device_summary(self, snapshot):
        try:
            self.clipboard_clear()
            self.clipboard_append(self.device_summary_text(snapshot))
            self.health_status_var.set("Device summary copied to clipboard.")
        except Exception as exc:
            messagebox.showerror("Copy Failed", str(exc))

    def copy_raw_smart_output(self, root):
        snapshot = next((item for item in self.drive_health_snapshots if item.root == root), None)
        text = snapshot.raw_smart_preview if snapshot else ""
        if not text:
            text = "No raw SMART output available."
        try:
            self.clipboard_clear()
            self.clipboard_append(text)
        except Exception as exc:
            messagebox.showerror("Copy Failed", str(exc))

    def save_raw_smart_output(self, root):
        snapshot = next((item for item in self.drive_health_snapshots if item.root == root), None)
        text = snapshot.raw_smart_preview if snapshot else ""
        if not text:
            messagebox.showinfo("Raw SMART Output", "No raw SMART output is available for this device.")
            return
        reports_dir = ensure_reports_dir()
        clean = (snapshot.drive_letter or snapshot.root or "drive").replace("\\", "_").replace("/", "_").replace(":", "")
        path = reports_dir / f"raw_smart_{clean}_{file_stamp()}.txt"
        path.write_text(text, encoding="utf-8")
        self.open_file(str(path))

    def search_raw_smart_output(self, root):
        state = self.drive_detail_windows.get(root)
        if not state:
            return
        text_frame = state["widgets"].get("raw_text")
        query = state["widgets"].get("raw_search_var").get().strip()
        if not text_frame or not query:
            return
        text = self.text_widget(text_frame)
        text.configure(state="normal")
        text.tag_remove("raw_search", "1.0", tk.END)
        pos = text.search(query, "1.0", nocase=True, stopindex=tk.END)
        if pos:
            end = f"{pos}+{len(query)}c"
            text.tag_add("raw_search", pos, end)
            text.tag_config("raw_search", background=CYBER_YELLOW, foreground="#031019")
            text.see(pos)
        text.configure(state="disabled")

    def export_single_drive_health_report(self, snapshot, fmt):
        reports_dir = ensure_reports_dir()
        clean = (snapshot.drive_letter or snapshot.root or "drive").replace("\\", "_").replace("/", "_").replace(":", "")
        base = reports_dir / f"storage_health_{clean}_{file_stamp()}"
        fmt = fmt.lower()
        try:
            if fmt == "txt":
                path = base.with_suffix(".txt")
                path.write_text(self.drive_health_report_text([snapshot]), encoding="utf-8")
            elif fmt == "json":
                path = base.with_suffix(".json")
                path.write_text(json.dumps({"generated_at": now_stamp(), "drive_snapshot": asdict(snapshot)}, indent=2), encoding="utf-8")
            elif fmt == "html":
                path = base.with_suffix(".html")
                path.write_text(self.drive_health_html_report([snapshot]), encoding="utf-8")
            elif fmt == "pdf":
                html_content = self.drive_health_html_report([snapshot])
                path = base.with_suffix(".pdf")
                try:
                    from weasyprint import HTML
                    HTML(string=html_content, base_url=str(reports_dir)).write_pdf(str(path))
                except Exception as exc:
                    logging.info("Single-drive PDF export unavailable: %s", exc)
                    html_path = base.with_suffix(".html")
                    html_path.write_text(html_content, encoding="utf-8")
                    messagebox.showinfo("PDF Export", "PDF engine is unavailable. HTML report was generated instead.")
                    path = html_path
            else:
                return
            append_health_history(
                {
                    "completed_at": now_stamp(),
                    "target": snapshot.root,
                    "health_status": snapshot.health_status,
                    "health_risk_score": 100 - snapshot.health_score,
                    "recommendation": snapshot.recommendation,
                    "smart_status": snapshot.smart_status,
                    "windows_health_status": snapshot.windows_status,
                    "read_stability_status": "Not run",
                    "report_html": str(path) if path.suffix.lower() == ".html" else "",
                    "report_txt": str(path) if path.suffix.lower() == ".txt" else "",
                }
            )
            self.open_file(str(path))
        except Exception as exc:
            messagebox.showerror("Export Failed", str(exc))

    def run_health_task_for_target(self, task_name, target, action):
        if self.health_thread and self.health_thread.is_alive():
            messagebox.showinfo("Diagnostics Running", "A health diagnostic task is already running.")
            return
        self.health_status_var.set(f"{task_name} running for {target}...")
        self.health_progress_var.set(0)
        self.append_text(self.health_output_text, f"\n[{now_stamp()}] {task_name} started for {target}\n")
        self.health_runner = StorageHealthDiagnostics(target, self.health_log_callback, self.health_status_callback, self.health_progress_callback)

        def worker():
            try:
                action(self.health_runner)
                result = self.health_runner.finalize()
                self.health_queue.put({"type": "complete", "result": result})
            except Exception as exc:
                self.health_queue.put({"type": "log", "message": f"[Health/Critical] {type(exc).__name__}: {exc}"})
                logging.exception("Health diagnostic task failed")

        self.health_thread = threading.Thread(target=worker, daemon=True)
        self.health_thread.start()

    def run_detail_health_task(self, root, task_name, action):
        self.selected_drive_health_root = root
        self.run_health_task_for_target(task_name, root, action)

    def run_detail_surface_scan(self, root):
        if not messagebox.askyesno("Read-Only Surface Scan", "This scan reads existing files only and does not repair or write data. Continue?"):
            return
        self.apply_settings()
        self.run_detail_health_task(
            root,
            "Surface Read Stability Scan",
            lambda runner: runner.run_surface_read_stability_scan(
                max_bytes=self.settings.surface_scan_max_mb * 1024 * 1024,
                chunk_size=self.settings.surface_scan_chunk_mb * 1024 * 1024,
                max_seconds=self.settings.surface_scan_max_seconds,
            ),
        )

    def rescan_drive_from_detail(self, root):
        self.selected_drive_health_root = root
        self.rescan_selected_drive_health()

    def selected_drive_health_snapshot(self):
        for snapshot in self.drive_health_snapshots:
            if snapshot.root == self.selected_drive_health_root:
                return snapshot
        return self.drive_health_snapshots[0] if self.drive_health_snapshots else None

    def update_drive_health_details(self):
        if not hasattr(self, "drive_health_details_text"):
            return
        snapshot = self.selected_drive_health_snapshot()
        if not snapshot:
            self.set_text(self.drive_health_details_text, "No drive selected.\n")
            return
        self.set_text(self.drive_health_details_text, self.drive_health_details_text_for(snapshot))

    def drive_health_details_text_for(self, snapshot: DriveHealthSnapshot):
        issues = "\n".join(f"- [{i.get('severity')}] {i.get('title')}: {i.get('detail')}" for i in snapshot.issues) or "- No health-specific findings recorded."
        lines = [
            "IDENTITY",
            "-" * 78,
            f"Root: {snapshot.root}",
            f"Drive Letter: {snapshot.drive_letter}",
            f"Volume Label: {snapshot.volume_label}",
            f"Model / Friendly Name: {snapshot.model}",
            f"Manufacturer: {snapshot.manufacturer}",
            f"Serial Number: {snapshot.serial}",
            f"Firmware: {snapshot.firmware}",
            f"Last Checked: {snapshot.last_checked}",
            "",
            "VOLUME DETAILS",
            "-" * 78,
            f"Capacity: {human_bytes(snapshot.capacity)}",
            f"Used: {human_bytes(snapshot.used)}",
            f"Free: {human_bytes(snapshot.free)}",
            f"File System: {snapshot.filesystem}",
            f"Drive Type: {snapshot.drive_type}",
            f"Bus / Interface: {snapshot.bus_type}",
            f"Media Type: {snapshot.media_type}",
            "",
            "HEALTH SUMMARY",
            "-" * 78,
            f"Health Status: {snapshot.health_status}",
            f"Health Score: {snapshot.health_score}/100",
            f"Recommendation: {snapshot.recommendation}",
            f"Windows Health: {snapshot.windows_status}",
            f"SMART Health: {snapshot.smart_status}",
            f"SMART Device: {snapshot.smart_device or 'Not matched'}",
            f"SMART Match: {snapshot.smart_match_confidence}",
            f"SMART Match Reason: {snapshot.smart_match_reason or 'N/A'}",
            "",
            "SMART PARSED VALUES",
            "-" * 78,
            f"Temperature: {snapshot.temperature}",
            f"SSD Wear / Percentage Used: {snapshot.wear}",
            f"Power-On Hours: {snapshot.power_on_hours}",
            f"Power Cycle Count: {snapshot.power_cycle_count}",
            f"Reallocated Sectors: {snapshot.reallocated}",
            f"Current Pending Sectors: {snapshot.pending}",
            f"Offline Uncorrectable: {snapshot.uncorrectable}",
            f"UDMA CRC Errors: {snapshot.crc_errors}",
            f"NVMe Media/Data Integrity Errors: {snapshot.nvme_media_errors}",
            f"Available Spare: {snapshot.smart_parsed.get('nvme_available_spare', 'Not Reported')}",
            f"Available Spare Threshold: {snapshot.smart_parsed.get('nvme_available_spare_threshold', 'Not Reported')}",
            f"Spin Retry Count: {snapshot.smart_parsed.get('spin_retry_count', 'Not Reported')}",
            f"Seek Error Rate: {snapshot.smart_parsed.get('seek_error_rate', 'Not Reported')}",
            f"Start/Stop Count: {snapshot.smart_parsed.get('start_stop_count', 'Not Reported')}",
            f"Load Cycle Count: {snapshot.smart_parsed.get('load_cycle_count', 'Not Reported')}",
            f"Unsafe Shutdowns: {snapshot.smart_parsed.get('unsafe_shutdowns', 'Not Reported')}",
            "",
            "RISK FACTORS",
            "-" * 78,
            issues,
            "",
            "WINDOWS HEALTH VALUES",
            "-" * 78,
            json.dumps(snapshot.windows_parsed, indent=2),
            "",
            "RAW SMART OUTPUT PREVIEW",
            "-" * 78,
            snapshot.raw_smart_preview or "No raw SMART output available.",
        ]
        return "\n".join(lines)

    def run_health_task(self, task_name, action):
        target = self.selected_health_target()
        self.run_health_task_for_target(task_name, target, action)

    def refresh_health(self):
        self.run_health_task("Refresh Health", lambda runner: runner.run_all(include_chkdsk=False, include_surface=False))

    def run_health_smart(self):
        self.run_health_task("SMART Health Analyzer", lambda runner: runner.run_smart_check())

    def run_health_windows(self):
        self.run_health_task("Windows Health Analyzer", lambda runner: runner.run_windows_health_check())

    def run_health_chkdsk(self):
        self.run_health_task("Read-Only CHKDSK Preview", lambda runner: runner.run_read_only_chkdsk())

    def run_health_surface(self):
        if not messagebox.askyesno("Read-Only Surface Scan", "This scan reads existing files only and does not repair or write data. Continue?"):
            return
        self.apply_settings()
        self.run_health_task(
            "Surface Read Stability Scan",
            lambda runner: runner.run_surface_read_stability_scan(
                max_bytes=self.settings.surface_scan_max_mb * 1024 * 1024,
                chunk_size=self.settings.surface_scan_chunk_mb * 1024 * 1024,
                max_seconds=self.settings.surface_scan_max_seconds,
            ),
        )

    def cancel_health_diagnostic(self):
        if self.health_runner and self.health_thread and self.health_thread.is_alive():
            self.health_runner.cancel()
            self.health_status_var.set("Cancelling health diagnostic...")
            self.health_log_callback("Health diagnostic cancellation requested.")
        else:
            self.health_status_var.set("No health diagnostic is currently running.")

    def update_health_ui(self, result: HealthDiagnosticResult):
        global LAST_HEALTH_SUMMARY
        self.last_health_result = result
        drive_snapshots = LAST_HEALTH_SUMMARY.get("drive_snapshots", []) if isinstance(LAST_HEALTH_SUMMARY, dict) else []
        LAST_HEALTH_SUMMARY = asdict(result)
        if drive_snapshots:
            LAST_HEALTH_SUMMARY["drive_snapshots"] = drive_snapshots
        self.health_cards["Health Status"].value_label.config(text=result.health_status)
        self.health_cards["SMART Status"].value_label.config(text=result.smart_status)
        self.health_cards["Windows Health"].value_label.config(text=result.windows_health_status)
        self.health_cards["Temperature"].value_label.config(text=result.temperature)
        self.health_cards["Wear / Age"].value_label.config(text=result.wear_age)
        self.health_cards["Read Stability"].value_label.config(text=result.read_stability_status)
        self.health_cards["Health Risk Score"].value_label.config(text=f"{result.health_risk_score} / 100")
        risk_color = CYBER_RED if result.health_risk_score >= 75 else CYBER_ORANGE if result.health_risk_score >= 25 else CYBER_GREEN
        self.health_cards["Health Risk Score"].value_label.config(fg=risk_color)
        output = self.health_result_text(result)
        self.set_text(self.health_output_text, output)
        self.health_status_var.set(f"{result.health_status} - {result.recommendation}")
        self.health_progress_var.set(100)
        append_health_history(
            {
                "completed_at": result.completed_at or now_stamp(),
                "target": result.target,
                "health_status": result.health_status,
                "health_risk_score": result.health_risk_score,
                "recommendation": result.recommendation,
                "smart_status": result.smart_status,
                "windows_health_status": result.windows_health_status,
                "read_stability_status": result.read_stability_status,
                "report_html": result.report_html,
                "report_txt": result.report_txt,
            }
        )
        if hasattr(self, "history_text"):
            self.refresh_history()
        if hasattr(self, "health_history_text"):
            self.refresh_health_history()

    def health_result_text(self, result: HealthDiagnosticResult):
        lines = [
            f"Target: {result.target}",
            f"Started: {result.started_at}",
            f"Completed: {result.completed_at}",
            f"Health Status: {result.health_status}",
            f"Health Risk Score: {result.health_risk_score}/100",
            f"Recommendation: {result.recommendation}",
            f"SMART Selected Device: {result.smart_selected_device or 'Not matched'}",
            f"SMART Match Confidence: {result.smart_match_confidence}",
            f"SMART Match Reason: {result.smart_match_reason or 'N/A'}",
            "",
            "SMART Parsed Results",
            "-" * 78,
            json.dumps(result.smart_parsed, indent=2),
            "",
            "Windows Health Results",
            "-" * 78,
            json.dumps(result.windows_parsed, indent=2),
            "",
            "Surface Read Stability Results",
            "-" * 78,
            json.dumps(result.surface_results, indent=2),
            "",
            "Read-only CHKDSK Output",
            "-" * 78,
            result.chkdsk_output or "Not run.",
            "",
            "Health Findings",
            "-" * 78,
        ]
        if result.issues:
            for issue in result.issues:
                lines.append(f"[{issue.get('severity')}] {issue.get('title')}: {issue.get('detail')}")
        else:
            lines.append("No health-specific findings recorded.")
        return "\n".join(lines)

    def health_html_report(self, result: HealthDiagnosticResult):
        data = asdict(result)
        issues = "".join(
            f"<li><b>{html.escape(str(i.get('severity')))} - {html.escape(str(i.get('title')))}</b>: {html.escape(str(i.get('detail')))}</li>"
            for i in result.issues
        ) or "<li>No health-specific findings recorded.</li>"
        return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{APP_NAME} Health Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#070B14;color:#F4FCFF;margin:24px;line-height:1.45}}
h1,h2{{color:#00E5FF}} .panel{{background:#0B1220;border:1px solid #2C5E8F;padding:14px;margin:12px 0}}
.metric{{display:inline-block;min-width:190px;background:#081526;border:1px solid #1B3355;padding:10px;margin:4px}}
.risk{{color:#FFD166;font-weight:800}} pre{{white-space:pre-wrap;overflow-wrap:anywhere;color:#D7F7FF}}
</style></head><body>
<h1>{APP_NAME} Storage Health & Diagnostics</h1>
<div class="panel"><div class="metric">Health<br><b>{html.escape(result.health_status)}</b></div>
<div class="metric">SMART<br><b>{html.escape(result.smart_status)}</b></div>
<div class="metric">Windows Health<br><b>{html.escape(result.windows_health_status)}</b></div>
<div class="metric">Temperature<br><b>{html.escape(result.temperature)}</b></div>
<div class="metric">Health Risk<br><b class="risk">{result.health_risk_score}/100</b></div>
<p><b>Recommendation:</b> {html.escape(result.recommendation)}</p></div>
<div class="panel"><h2>SMART Device Mapping</h2>
<p><b>Selected smartctl device:</b> {html.escape(result.smart_selected_device or 'Not matched')}</p>
<p><b>Match confidence:</b> {html.escape(result.smart_match_confidence)}</p>
<p><b>Reason:</b> {html.escape(result.smart_match_reason or 'N/A')}</p></div>
<div class="panel"><h2>Findings</h2><ul>{issues}</ul></div>
<div class="panel"><h2>SMART Parsed Results</h2><pre>{html.escape(json.dumps(result.smart_parsed, indent=2))}</pre></div>
<div class="panel"><h2>Windows Health Results</h2><pre>{html.escape(json.dumps(result.windows_parsed, indent=2))}</pre></div>
<div class="panel"><h2>CHKDSK Output</h2><pre>{html.escape(result.chkdsk_output or 'Not run.')}</pre></div>
<div class="panel"><h2>Surface Read Stability</h2><pre>{html.escape(json.dumps(result.surface_results, indent=2))}</pre></div>
<div class="panel"><h2>Raw JSON</h2><pre>{html.escape(json.dumps(data, indent=2))}</pre></div>
</body></html>"""

    def drive_health_report_text(self, snapshots):
        lines = [
            f"{APP_NAME} - All Drive Health Dashboard Report",
            f"Generated: {now_stamp()}",
            f"Detected drives: {len(snapshots)}",
            "",
            "SAFETY NOTE",
            "-" * 78,
            "Diagnostics only. No repair, no formatting, no firmware operations, and no destructive disk actions were performed.",
            "",
        ]
        for snapshot in snapshots:
            lines.extend(
                [
                    "=" * 78,
                    f"{snapshot.drive_letter} {snapshot.model}",
                    "=" * 78,
                    f"Root: {snapshot.root}",
                    f"Volume Label: {snapshot.volume_label}",
                    f"Manufacturer: {snapshot.manufacturer}",
                    f"Serial: {snapshot.serial}",
                    f"Firmware: {snapshot.firmware}",
                    f"Capacity: {human_bytes(snapshot.capacity)}",
                    f"Used: {human_bytes(snapshot.used)}",
                    f"Free: {human_bytes(snapshot.free)}",
                    f"Filesystem: {snapshot.filesystem}",
                    f"Drive Type: {snapshot.drive_type}",
                    f"Bus / Interface: {snapshot.bus_type}",
                    f"Media Type: {snapshot.media_type}",
                    f"Windows Health: {snapshot.windows_status}",
                    f"SMART Health: {snapshot.smart_status}",
                    f"SMART Device: {snapshot.smart_device or 'Not matched'}",
                    f"SMART Match Confidence: {snapshot.smart_match_confidence}",
                    f"Temperature: {snapshot.temperature}",
                    f"Wear: {snapshot.wear}",
                    f"Power-On Hours: {snapshot.power_on_hours}",
                    f"Power Cycles: {snapshot.power_cycle_count}",
                    f"Reallocated: {snapshot.reallocated}",
                    f"Pending: {snapshot.pending}",
                    f"Uncorrectable: {snapshot.uncorrectable}",
                    f"CRC Errors: {snapshot.crc_errors}",
                    f"NVMe Media/Data Integrity Errors: {snapshot.nvme_media_errors}",
                    f"Health Score: {snapshot.health_score}/100",
                    f"Status: {snapshot.health_status}",
                    f"Recommendation: {snapshot.recommendation}",
                    f"Last Checked: {snapshot.last_checked}",
                    "",
                    "Issues:",
                ]
            )
            if snapshot.issues:
                for issue in snapshot.issues:
                    lines.append(f"- [{issue.get('severity')}] {issue.get('title')}: {issue.get('detail')}")
            else:
                lines.append("- No health-specific findings recorded.")
            lines.extend(["", "SMART Parsed:", json.dumps(snapshot.smart_parsed, indent=2), "", "Windows Parsed:", json.dumps(snapshot.windows_parsed, indent=2), ""])
        return "\n".join(lines)

    def drive_health_html_report(self, snapshots):
        cards = []
        for snapshot in snapshots:
            color = health_status_color(snapshot.health_status)
            issues = "".join(
                f"<li><b>{html.escape(str(i.get('severity')))} - {html.escape(str(i.get('title')))}</b>: {html.escape(str(i.get('detail')))}</li>"
                for i in snapshot.issues
            ) or "<li>No health-specific findings recorded.</li>"
            cards.append(
                f"""<div class="card" style="border-color:{color}">
<div class="top"><h2>{html.escape(snapshot.drive_letter)} {html.escape(snapshot.model)}</h2><span style="background:{color}">{html.escape(snapshot.health_status)}</span></div>
<p>{html.escape(snapshot.display_name)}</p>
<div class="metrics">
<div>Health Score<br><b style="color:{color}">{snapshot.health_score}/100</b></div>
<div>Capacity<br><b>{html.escape(human_bytes(snapshot.capacity))}</b></div>
<div>Free<br><b>{html.escape(human_bytes(snapshot.free))}</b></div>
<div>Interface<br><b>{html.escape(snapshot.bus_type)}</b></div>
<div>Media<br><b>{html.escape(snapshot.media_type)}</b></div>
<div>SMART<br><b>{html.escape(snapshot.smart_status)}</b></div>
<div>Temperature<br><b>{html.escape(snapshot.temperature)}</b></div>
<div>Wear<br><b>{html.escape(snapshot.wear)}</b></div>
</div>
<p><b>Recommendation:</b> {html.escape(snapshot.recommendation)}</p>
<h3>Identity</h3><pre>{html.escape(json.dumps({
    "root": snapshot.root,
    "volume_label": snapshot.volume_label,
    "manufacturer": snapshot.manufacturer,
    "serial": snapshot.serial,
    "firmware": snapshot.firmware,
    "filesystem": snapshot.filesystem,
    "drive_type": snapshot.drive_type,
    "smart_device": snapshot.smart_device,
    "smart_match_confidence": snapshot.smart_match_confidence,
    "smart_match_reason": snapshot.smart_match_reason,
}, indent=2))}</pre>
<h3>Findings</h3><ul>{issues}</ul>
<h3>SMART Parsed Values</h3><pre>{html.escape(json.dumps(snapshot.smart_parsed, indent=2))}</pre>
<h3>Windows Health Values</h3><pre>{html.escape(json.dumps(snapshot.windows_parsed, indent=2))}</pre>
<h3>Raw SMART Preview</h3><pre>{html.escape(snapshot.raw_smart_preview or 'No raw SMART output available.')}</pre>
</div>"""
            )
        return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{APP_NAME} All Drive Health Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#070B14;color:#F4FCFF;margin:24px;line-height:1.45}}
h1{{color:#00E5FF}} h2,h3{{color:#D7F7FF}} .note{{background:#101826;border:1px solid #FFD166;padding:12px;margin:12px 0}}
.card{{background:#0B1220;border:1px solid #2C5E8F;padding:14px;margin:14px 0}}
.top{{display:flex;align-items:center;justify-content:space-between;gap:12px}} .top span{{color:#fff;font-weight:800;padding:5px 10px}}
.metrics{{display:grid;grid-template-columns:repeat(auto-fit,minmax(150px,1fr));gap:8px;margin:10px 0}}
.metrics div{{background:#081526;border:1px solid #1B3355;padding:10px}} pre{{white-space:pre-wrap;overflow-wrap:anywhere;color:#D7F7FF}}
</style></head><body>
<h1>{APP_NAME} - Storage Health & Diagnostics Dashboard</h1>
<div class="note">Generated {html.escape(now_stamp())}. Diagnostics only: no repair, no formatting, no firmware operations, and no destructive disk actions were performed.</div>
{''.join(cards) if cards else '<p>No drive health snapshots were available.</p>'}
</body></html>"""

    def export_health_report(self):
        snapshots = list(getattr(self, "drive_health_snapshots", []) or [])
        if not self.last_health_result and not snapshots:
            messagebox.showinfo("Health Report", "Run or refresh health diagnostics first.")
            return
        reports_dir = ensure_reports_dir()
        if snapshots:
            base = reports_dir / f"storage_health_all_drives_{file_stamp()}"
            txt = base.with_suffix(".txt")
            js = base.with_suffix(".json")
            html_path = base.with_suffix(".html")
            pdf_path = base.with_suffix(".pdf")
            txt.write_text(self.drive_health_report_text(snapshots), encoding="utf-8")
            js.write_text(json.dumps({"generated_at": now_stamp(), "drive_snapshots": [asdict(item) for item in snapshots]}, indent=2), encoding="utf-8")
            html_content = self.drive_health_html_report(snapshots)
            html_path.write_text(html_content, encoding="utf-8")
            try:
                from weasyprint import HTML
                HTML(string=html_content, base_url=str(reports_dir)).write_pdf(str(pdf_path))
            except Exception as exc:
                logging.info("Health dashboard PDF export unavailable: %s", exc)
            append_health_history(
                {
                    "completed_at": now_stamp(),
                    "target": "All detected drives",
                    "health_status": "Dashboard Export",
                    "health_risk_score": min((100 - item.health_score for item in snapshots), default=0),
                    "recommendation": f"{len(snapshots)} drive health snapshot(s) exported",
                    "smart_status": "Per-drive",
                    "windows_health_status": "Per-drive",
                    "read_stability_status": "Not run",
                    "report_html": str(html_path),
                    "report_txt": str(txt),
                }
            )
            if hasattr(self, "health_history_text"):
                self.refresh_health_history()
            self.open_file(str(html_path))
            return

        result = self.last_health_result
        clean_root = result.target.replace("\\", "_").replace("/", "_").replace(":", "")
        base = reports_dir / f"storage_health_{clean_root}_{file_stamp()}"
        txt = base.with_suffix(".txt")
        js = base.with_suffix(".json")
        html_path = base.with_suffix(".html")
        pdf_path = base.with_suffix(".pdf")
        txt.write_text(self.health_result_text(result), encoding="utf-8")
        js.write_text(json.dumps(asdict(result), indent=2), encoding="utf-8")
        html_content = self.health_html_report(result)
        html_path.write_text(html_content, encoding="utf-8")
        result.report_txt = str(txt)
        result.report_json = str(js)
        result.report_html = str(html_path)
        try:
            from weasyprint import HTML
            HTML(string=html_content, base_url=str(reports_dir)).write_pdf(str(pdf_path))
            result.report_pdf = str(pdf_path)
        except Exception as exc:
            logging.info("Health PDF export unavailable: %s", exc)
        self.update_health_ui(result)
        self.open_file(str(html_path))

    def bind_keyboard_shortcuts(self):
        shortcuts = {
            "<Control-o>": lambda _event: self.browse_path(),
            "<Control-O>": lambda _event: self.browse_path(),
            "<Control-s>": lambda _event: self.start_scan(),
            "<Control-S>": lambda _event: self.start_scan(),
            "<Control-p>": lambda _event: self.pause_scan(),
            "<Control-P>": lambda _event: self.pause_scan(),
            "<Control-r>": lambda _event: self.continue_or_resume_scan(),
            "<Control-R>": lambda _event: self.continue_or_resume_scan(),
            "<Control-x>": lambda _event: self.cancel_scan(),
            "<Control-X>": lambda _event: self.cancel_scan(),
            "<Control-h>": lambda _event: self.open_help_center(),
            "<Control-H>": lambda _event: self.open_help_center(),
            "<Control-l>": lambda _event: self.clear_logs(),
            "<Control-L>": lambda _event: self.clear_logs(),
            "<Control-e>": lambda _event: self.open_latest_report(),
            "<Control-E>": lambda _event: self.open_latest_report(),
            "<F1>": lambda _event: self.open_help_center(),
        }
        for sequence, callback in shortcuts.items():
            self.bind_all(sequence, self._shortcut(callback))

    def _shortcut(self, callback):
        def handler(event):
            widget = event.widget
            if isinstance(widget, (tk.Entry, tk.Text)) and event.keysym.lower() in ("s", "x", "l"):
                return None
            callback(event)
            return "break"
        return handler

    def refresh_drives(self):
        previous_root = self.get_selected_target_path() if hasattr(self, "drive_var") else ""
        identities = discover_drive_identities_quick()
        if self.settings.exclude_system_drive and os.name == "nt":
            filtered = [item for item in identities if not item["root"].upper().startswith("C:")]
            identities = filtered or identities
        self.apply_drive_identities(identities, previous_root)
        self.update_drive_details_panel()
        self.start_drive_enrichment(previous_root)

    def start_drive_enrichment(self, previous_root):
        if self.drive_refresh_thread and self.drive_refresh_thread.is_alive():
            return
        self.drive_refresh_generation += 1
        generation = self.drive_refresh_generation
        if hasattr(self, "drive_details_var"):
            self.drive_details_var.set(self.drive_details_var.get() + "\n\nLoading physical disk identity in background...")

        def worker():
            try:
                identities = discover_drive_identities()
                self.drive_refresh_queue.put({"generation": generation, "identities": identities, "previous_root": previous_root})
            except Exception as exc:
                self.drive_refresh_queue.put({"generation": generation, "error": str(exc), "previous_root": previous_root})

        self.drive_refresh_thread = threading.Thread(target=worker, daemon=True)
        self.drive_refresh_thread.start()

    def apply_drive_identities(self, identities, previous_root=""):
        if self.settings.exclude_system_drive and os.name == "nt":
            filtered = [item for item in identities if not item["root"].upper().startswith("C:")]
            identities = filtered or identities
        self.drive_display_map = {item["display"]: item["root"] for item in identities}
        self.drive_identity_map = {item["display"]: item for item in identities}
        displays = [item["display"] for item in identities]
        self.drive_combo["values"] = displays
        selected_display = ""
        previous_root = previous_root or self.get_selected_target_path()
        if previous_root:
            for item in identities:
                if normalize_drive_root(item["root"]).lower() == normalize_drive_root(previous_root).lower():
                    selected_display = item["display"]
                    break
        if not selected_display and displays:
            selected_display = displays[0]
        if selected_display:
            self.drive_var.set(selected_display)
            self.cards["Selected Drive"].value_label.config(text=self.drive_display_map.get(selected_display, selected_display))

    def browse_path(self):
        path = filedialog.askdirectory(title="Select Target Drive or Folder")
        if path:
            self.drive_var.set(path)
            self.cards["Selected Drive"].value_label.config(text=path)
            self.update_drive_details_panel()

    def get_selected_target_path(self):
        selected = self.drive_var.get() if hasattr(self, "drive_var") else ""
        return self.drive_display_map.get(selected, selected)

    def update_drive_details_panel(self):
        if not hasattr(self, "drive_details_var"):
            return
        selected = self.drive_var.get()
        root = self.drive_display_map.get(selected, selected)
        item = self.drive_identity_map.get(selected)
        if not root:
            self.drive_details_var.set("No target selected.")
            return
        if item:
            meta = item.get("metadata") or {}
            vol = item.get("volume_info") or {}
            usage = item.get("usage") or {}
            lines = [
                f"Root: {item.get('root', root)}",
                f"Volume: {vol.get('volume_name', 'Unknown')} | File System: {vol.get('filesystem', 'Unknown')}",
                f"Capacity: {human_bytes(usage.get('total', 0))} | Free: {human_bytes(usage.get('free', 0))} | Used: {human_bytes(usage.get('used', 0))}",
                f"Drive Type: {item.get('drive_type', 'Unknown')} | Badge: {item.get('badge', 'Unknown')}",
                f"Model/FriendlyName: {meta.get('PhysicalFriendlyName') or meta.get('FriendlyName') or meta.get('Model') or 'Unknown'}",
                f"Serial: {meta.get('SerialNumber') or meta.get('PhysicalSerialNumber') or 'Unknown'} | Bus: {meta.get('BusType') or meta.get('PhysicalBusType') or 'Unknown'} | Media: {meta.get('PhysicalMediaType') or meta.get('MediaType') or 'Unknown'}",
                f"Health: {meta.get('HealthStatus') or meta.get('PhysicalHealthStatus') or 'Unknown'} | Operational: {meta.get('OperationalStatus') or meta.get('PhysicalOperationalStatus') or 'Unknown'}",
            ]
            if item.get("warning"):
                lines.append(f"Metadata Note: {item.get('warning')}")
            self.drive_details_var.set("\n".join(lines))
        else:
            try:
                usage = shutil.disk_usage(root)
                details = f"Custom Path: {root}\nCapacity: {human_bytes(usage.total)} | Free: {human_bytes(usage.free)} | Used: {human_bytes(usage.used)}\nDrive metadata is shown for discovered drive roots only."
            except Exception as exc:
                details = f"Custom Path: {root}\nDrive details unavailable: {exc}"
            self.drive_details_var.set(details)

    def validate_inputs(self, target):
        if not target:
            messagebox.showwarning("Missing Target", "Please select a target drive or folder.")
            return False
        if os.name == "nt" and get_disk_root(target).upper().startswith("C:"):
            if not messagebox.askyesno("System Drive Warning", "The target is on C:. This can fill or stress the system drive. Continue only if you are sure."):
                return False
        mode = self.scan_mode_var.get()
        if mode in ("Deep Scan", "Full Capacity Validation"):
            if not messagebox.askyesno("Deep Scan Confirmation", f"{mode} may write a large amount of temporary data. Continue?"):
                return False
        test_mb = safe_float(self.test_size_var.get(), 0.0)
        if test_mb and test_mb < 256 and self.settings.show_advanced_warnings:
            messagebox.showwarning("Small Test Size", "This test size is too small to reliably detect many fake-capacity devices.")
        return True

    def start_scan(self, resume_session=None):
        target = self.get_selected_target_path()
        if not self.validate_inputs(target):
            return
        if self.scan_thread and self.scan_thread.is_alive():
            return
        self.apply_settings()
        self.resume_session_path = resume_session
        adv_gb = safe_float(self.advertised_var.get(), 0.0)
        test_mb = safe_float(self.test_size_var.get(), 0.0)
        block_mb = safe_float(self.block_size_var.get(), 0.0)
        self.clear_run_ui()
        self.header_status.config(text="SCANNING", fg=CYBER_YELLOW)
        self.scanner = StorageScanner(
            target,
            adv_gb,
            test_mb,
            block_mb,
            self.scan_mode_var.get(),
            self.flush_policy_var.get(),
            self.settings,
            self.log_callback,
            self.progress_callback,
            self.metric_callback,
            resume_session=resume_session,
            recheck_all=self.recheck_all_var.get(),
        )
        self.scan_thread = threading.Thread(target=self.run_scan, daemon=True)
        self.scan_thread.start()

    def run_scan(self):
        self.last_result = self.scanner.run()
        self.log_queue.put("SCAN_COMPLETE")

    def clear_run_ui(self):
        self.set_text(self.log_text, "")
        self.set_text(self.findings_text, "")
        for var in self.progress_vars.values():
            var.set(0)
        self.progress_label.config(text="0%")
        if hasattr(self, "warning_banner_var"):
            self.warning_banner_var.set("")
        if hasattr(self, "processed_summary_var"):
            self.processed_summary_var.set("Processed: 0 B | Verified: 0 B | Corrupted: 0 B")
        if hasattr(self, "scan_viz"):
            self.scan_viz.delete("all")
        for name, value in (
            ("Current Phase", "Starting"),
            ("ETA", "Calculating"),
            ("Write Speed", "0 MB/s"),
            ("Read Speed", "0 MB/s"),
            ("Processed", "0 B"),
            ("Verified", "0 B"),
            ("Corrupted", "0 B"),
            ("Corrupted Blocks", "0"),
            ("Failed Blocks", "0"),
            ("Read Failures", "0"),
            ("Current Block", "0 / 0"),
            ("Risk Score", "0 / 100"),
        ):
            self.cards[name].value_label.config(text=value)

    def resume_previous_scan(self):
        self.refresh_sessions()
        selected = self.session_var.get()
        if not selected:
            messagebox.showinfo("Resume", "No resumable sessions were found for the selected drive.")
            return
        session_dir = selected.split(" | ")[-1]
        self.start_scan(resume_session=session_dir)

    def continue_or_resume_scan(self):
        if self.scanner and self.scan_thread and self.scan_thread.is_alive():
            self.continue_scan()
        else:
            self.resume_previous_scan()

    def pause_scan(self):
        if self.scanner:
            self.scanner.pause()
            self.log_callback("Scan paused.")
            self.header_status.config(text="PAUSED", fg=CYBER_YELLOW)

    def continue_scan(self):
        if self.scanner:
            self.scanner.resume()
            self.log_callback("Scan resumed.")
            self.header_status.config(text="SCANNING", fg=CYBER_YELLOW)

    def cancel_scan(self):
        if self.scanner:
            self.scanner.cancel()
            self.log_callback("Cancelling scan. Checkpoint and unfinished test files will be preserved.")

    def emergency_stop(self):
        if self.scanner:
            if messagebox.askyesno("Emergency Stop", "Stop immediately? The current session will be left for recovery/resume."):
                self.scanner.emergency()
                self.log_callback("Emergency stop requested.")

    def open_path(self, attr):
        if self.last_result and getattr(self.last_result, attr, ""):
            self.open_file(getattr(self.last_result, attr))
        else:
            messagebox.showinfo("Report", "No report generated yet.")

    def open_pdf_report(self):
        if self.last_result and self.last_result.pdf_report_path and Path(self.last_result.pdf_report_path).exists():
            self.open_file(self.last_result.pdf_report_path)
            return
        if self.last_result:
            messagebox.showinfo(
                "PDF Report",
                "No PDF report was generated for this scan. Install WeasyPrint, or install pdfkit with wkhtmltopdf, then run or export the report again. The HTML report remains available for browser print-to-PDF.",
            )
            return
        entries = load_history()
        for item in entries:
            path = item.get("pdf_report_path")
            if path and Path(path).exists():
                self.open_file(path)
                return
        messagebox.showinfo("PDF Report", "No PDF report has been generated yet.")

    def open_latest_report(self):
        if self.last_result and self.last_result.report_path:
            self.open_file(self.last_result.report_path)
            return
        entries = load_history()
        for item in entries:
            path = item.get("report_path")
            if path and Path(path).exists():
                self.open_file(path)
                return
        messagebox.showinfo("Report", "No report has been generated yet.")

    def open_help_center(self):
        if "Help Center" in self.tabs:
            self.notebook.select(self.tabs["Help Center"])

    def clear_logs(self):
        if hasattr(self, "log_text"):
            self.set_text(self.log_text, "")
            self.log_callback("Log view cleared.")

    def open_file(self, path):
        try:
            if os.name == "nt":
                os.startfile(path)
            else:
                webbrowser.open(Path(path).as_uri())
        except Exception as exc:
            messagebox.showerror("Open Failed", str(exc))

    def update_results_cards(self):
        res = self.last_result
        if not res:
            return
        self.cards["Selected Drive"].value_label.config(text=res.root)
        self.cards["Reported Capacity"].value_label.config(text=human_bytes(res.capacity_reported_bytes))
        self.cards["Free Space"].value_label.config(text=human_bytes(res.free_bytes))
        coverage = res.coverage_percent or ((res.processed_bytes / max(1, res.capacity_reported_bytes)) * 100 if res.capacity_reported_bytes else 0)
        self.cards["Test Coverage"].value_label.config(text=f"{coverage:.2f}%")
        self.cards["Current Phase"].value_label.config(text=res.status)
        self.cards["Write Speed"].value_label.config(text=f"{res.write_mb_s:.2f} MB/s")
        self.cards["Read Speed"].value_label.config(text=f"{res.read_mb_s:.2f} MB/s")
        self.cards["Processed"].value_label.config(text=human_bytes(res.processed_bytes))
        self.cards["Verified"].value_label.config(text=human_bytes(res.verified_bytes))
        self.cards["Corrupted"].value_label.config(text=human_bytes(res.corrupted_bytes))
        self.cards["Corrupted Blocks"].value_label.config(text=str(res.corrupted_blocks))
        self.cards["Failed Blocks"].value_label.config(text=str(res.failed_blocks))
        self.cards["Read Failures"].value_label.config(text=str(res.read_failures))
        self.cards["Current Block"].value_label.config(text=f"{res.current_block_index} / {res.total_blocks}")
        self.cards["Risk Score"].value_label.config(text=f"{res.risk_score} / 100")
        risk_color = CYBER_RED if res.risk_score >= 70 else CYBER_ORANGE if res.risk_score >= 30 else CYBER_GREEN
        self.cards["Risk Score"].value_label.config(fg=risk_color)
        self.update_device_text(res)
        self.update_findings_text(res)
        self.update_scan_visualization(asdict(res))
        self.refresh_report_dashboard()
        self.refresh_history()
        self.refresh_sessions()

    def update_device_text(self, res):
        info = [
            f"Target: {res.root}",
            f"Type: {res.drive_type}",
            f"Total: {human_bytes(res.capacity_reported_bytes)}",
            f"Free: {human_bytes(res.free_bytes)}",
            f"Filesystem: {res.volume_info.get('filesystem', 'Unknown')}",
            f"Volume Serial: {res.volume_info.get('serial', 'Unknown')}",
            "",
            "Disk Metadata:",
            json.dumps(res.disk_metadata or {}, indent=2),
            "",
            "SMART Summary:",
            json.dumps(res.smart_summary or res.smart_warning or "Unavailable", indent=2),
        ]
        self.set_text(self.device_text, "\n".join(info))

    def update_findings_text(self, res):
        lines = [f"Verdict: {res.status}", f"Risk Score: {res.risk_score}/100", f"Conclusion: {res.conclusion}", ""]
        if res.issues:
            for issue in res.issues:
                lines.append(f"[{issue.severity}] {issue.title}")
                lines.append(f"  {issue.detail}")
        else:
            lines.append("No major suspicious findings were detected during this scan.")
        lines += ["", "Fake-capacity indicators:"]
        lines += [f"- {x}" for x in res.fake_capacity_indicators] or ["- None recorded."]
        self.set_text(self.findings_text, "\n".join(lines))

    def process_queues(self):
        try:
            while True:
                msg = self.log_queue.get_nowait()
                if msg == "SCAN_COMPLETE":
                    self.update_results_cards()
                    if self.last_result and self.last_result.scan_interrupted:
                        self.header_status.config(text="PARTIAL REPORT READY", fg=CYBER_ORANGE)
                    else:
                        self.header_status.config(text="COMPLETED", fg=CYBER_GREEN)
                else:
                    self.append_text(self.log_text, str(msg) + "\n")
                    if hasattr(self, "report_log_preview"):
                        self.set_text(self.report_log_preview, self.text_widget(self.log_text).get("1.0", tk.END).strip()[-4000:] or "N/A")
        except queue.Empty:
            pass
        try:
            while True:
                val = self.progress_queue.get_nowait()
                self.progress_vars["overall"].set(val)
                self.progress_label.config(text=f"{int(val)}%")
                if val < 57:
                    self.progress_vars["write"].set(max(0, (val - 23) / 34 * 100))
                elif val < 90:
                    self.progress_vars["read"].set(max(0, (val - 57) / 31 * 100))
        except queue.Empty:
            pass
        try:
            while True:
                metrics = self.metric_queue.get_nowait()
                phase = metrics.get("phase")
                if phase:
                    self.cards["Current Phase"].value_label.config(text=phase)
                if "write_speed" in metrics:
                    speed = metrics["write_speed"]
                    self.cards["Write Speed"].value_label.config(text=f"{speed:.2f} MB/s")
                    self.speed_trend_var.set(f"Speed trend: write {speed:.2f} MB/s at block {metrics.get('block', '-')}")
                if "read_speed" in metrics:
                    speed = metrics["read_speed"]
                    self.cards["Read Speed"].value_label.config(text=f"{speed:.2f} MB/s")
                    self.speed_trend_var.set(f"Speed trend: read {speed:.2f} MB/s at block {metrics.get('block', '-')}")
                if "eta_seconds" in metrics:
                    self.cards["ETA"].value_label.config(text=self.format_eta(metrics.get("eta_seconds")))
                if "verified_bytes" in metrics:
                    self.cards["Verified"].value_label.config(text=human_bytes(metrics.get("verified_bytes", 0)))
                if "corrupted_bytes" in metrics:
                    self.cards["Corrupted"].value_label.config(text=human_bytes(metrics.get("corrupted_bytes", 0)))
                if "processed_bytes" in metrics:
                    self.cards["Processed"].value_label.config(text=human_bytes(metrics.get("processed_bytes", 0)))
                if "corrupted_blocks" in metrics:
                    self.cards["Corrupted Blocks"].value_label.config(text=str(metrics.get("corrupted_blocks", 0)))
                if "failed_blocks" in metrics:
                    self.cards["Failed Blocks"].value_label.config(text=str(metrics.get("failed_blocks", 0)))
                if "read_failures" in metrics:
                    self.cards["Read Failures"].value_label.config(text=str(metrics.get("read_failures", 0)))
                if "risk_score" in metrics:
                    risk = int(metrics.get("risk_score", 0))
                    self.cards["Risk Score"].value_label.config(text=f"{risk} / 100")
                    self.cards["Risk Score"].value_label.config(fg=CYBER_RED if risk >= 70 else CYBER_ORANGE if risk >= 30 else CYBER_GREEN)
                if "coverage_percent" in metrics:
                    self.cards["Test Coverage"].value_label.config(text=f"{metrics.get('coverage_percent', 0):.2f}%")
                if "block" in metrics:
                    self.cards["Current Block"].value_label.config(text=f"{metrics.get('block', 0)} / {metrics.get('total_blocks', 0)}")
                    self.progress_vars["block"].set((float(metrics.get("block", 0)) / max(1, float(metrics.get("total_blocks", 1)))) * 100)
                if "processed_bytes" in metrics:
                    processed = metrics.get("processed_bytes", 0)
                    test_size = max(1, metrics.get("test_size_bytes", 1))
                    self.progress_vars["read"].set((processed / test_size) * 100)
                    self.processed_summary_var.set(
                        f"Processed: {human_bytes(processed)} | "
                        f"Verified: {human_bytes(metrics.get('verified_bytes', 0))} | "
                        f"Corrupted: {human_bytes(metrics.get('corrupted_bytes', 0))}"
                    )
                    self.update_scan_visualization(metrics)
                if metrics.get("first_corruption_block"):
                    valid = human_bytes(metrics.get("estimated_valid_capacity_bytes", 0))
                    self.warning_banner_var.set(
                        f"WARNING: corruption began at block {metrics.get('first_corruption_block')} "
                        f"({metrics.get('corruption_percent', 0):.2f}% of processed bytes). "
                        f"Estimated authentic usable capacity before corruption: {valid}."
                    )
                self.update_live_findings_from_metrics(metrics)
        except queue.Empty:
            pass
        try:
            while True:
                item = self.health_queue.get_nowait()
                kind = item.get("type")
                if kind == "status":
                    self.health_status_var.set(item.get("message", "Diagnostics running..."))
                elif kind == "progress":
                    try:
                        self.health_progress_var.set(float(item.get("value", 0)))
                    except Exception:
                        pass
                elif kind == "log":
                    message = str(item.get("message", ""))
                    self.append_text(self.health_output_text, message + "\n")
                    logging.info(message)
                elif kind == "complete":
                    self.update_health_ui(item.get("result"))
                    self.refresh_open_drive_detail_windows()
                    self.log_callback("Storage health diagnostics completed.")
                elif kind == "drive_health_complete":
                    self.update_drive_health_dashboard(item.get("snapshots", []))
                    self.log_callback("Storage health dashboard refreshed.")
                elif kind == "drive_health_partial":
                    self.merge_drive_health_snapshots(item.get("snapshots", []))
                    self.log_callback("Selected drive health snapshot refreshed.")
                elif kind == "drive_health_error":
                    message = item.get("message", "Unknown dashboard error")
                    if hasattr(self, "drive_health_status_var"):
                        self.drive_health_status_var.set(f"Drive health refresh failed: {message}")
                    self.append_text(self.health_output_text, f"[Health/Dashboard] {message}\n")
                    self.drive_health_loading = False
        except queue.Empty:
            pass
        try:
            while True:
                item = self.drive_refresh_queue.get_nowait()
                if item.get("generation") != self.drive_refresh_generation:
                    continue
                if item.get("error"):
                    if hasattr(self, "drive_details_var"):
                        self.drive_details_var.set(self.drive_details_var.get() + f"\n\nMetadata refresh note: {item.get('error')}")
                    continue
                current_root = self.get_selected_target_path()
                self.apply_drive_identities(item.get("identities", []), current_root or item.get("previous_root", ""))
                self.update_drive_details_panel()
                self.log_callback("Drive identity metadata refreshed.")
        except queue.Empty:
            pass
        self.after(100, self.process_queues)

    def apply_settings(self):
        self.settings.retry_count = max(0, safe_int(self.setting_vars.get("retry_count", tk.StringVar(value="2")).get(), 2))
        self.settings.retry_delay_sec = max(0.0, safe_float(self.setting_vars.get("retry_delay_sec", tk.StringVar(value="0.4")).get(), 0.4))
        self.settings.delayed_verify_seconds = max(0, safe_int(self.setting_vars.get("delayed_verify_seconds", tk.StringVar(value="0")).get(), 0))
        self.settings.random_recheck_percent = max(0, min(100, safe_int(self.setting_vars.get("random_recheck_percent", tk.StringVar(value="8")).get(), 8)))
        self.settings.severe_corruption_blocks = max(1, safe_int(self.setting_vars.get("severe_corruption_blocks", tk.StringVar(value="100")).get(), 100))
        self.settings.surface_scan_max_mb = max(16, safe_int(self.setting_vars.get("surface_scan_max_mb", tk.StringVar(value="512")).get(), 512))
        self.settings.surface_scan_chunk_mb = max(1, min(128, safe_int(self.setting_vars.get("surface_scan_chunk_mb", tk.StringVar(value="4")).get(), 4)))
        self.settings.surface_scan_max_seconds = max(10, safe_int(self.setting_vars.get("surface_scan_max_seconds", tk.StringVar(value="180")).get(), 180))
        self.settings.enable_smart_checks = self.smart_var.get()
        self.settings.enable_powershell_metadata = self.ps_var.get()
        self.settings.exclude_system_drive = self.exclude_c_var.get()
        self.settings.show_advanced_warnings = self.warn_var.get()
        self.settings.auto_stop_severe_corruption = self.auto_stop_corruption_var.get()
        self.save_app_settings()
        self.log_callback("Settings applied and saved.")

    def discover_sessions(self):
        sessions = []
        roots = get_windows_drives() if os.name == "nt" else ["/"]
        target = self.get_selected_target_path()
        if target:
            roots.insert(0, target)
        seen = set()
        for root in roots:
            try:
                base = Path(root) / TEST_DIR_NAME
                if not base.exists():
                    continue
                for session_dir in base.glob(f"{SESSION_PREFIX}*"):
                    checkpoint = session_dir / CHECKPOINT_NAME
                    if checkpoint.exists() and str(session_dir) not in seen:
                        data = json.loads(checkpoint.read_text(encoding="utf-8"))
                        sessions.append((data.get("updated_at", ""), data.get("status", "active"), str(session_dir)))
                        seen.add(str(session_dir))
            except Exception:
                continue
        sessions.sort(reverse=True)
        return sessions

    def refresh_sessions(self):
        sessions = self.discover_sessions()
        values = [f"{updated} | {status} | {path}" for updated, status, path in sessions]
        self.session_combo["values"] = values
        if values:
            self.session_combo.current(0)
        else:
            self.session_var.set("")

    def refresh_history(self):
        entries = load_history()
        health_entries = load_health_history()
        lines = []
        if health_entries:
            lines.append("STORAGE HEALTH & DIAGNOSTICS HISTORY")
            lines.append("=" * 78)
            for item in health_entries[:40]:
                lines.append(
                    f"{item.get('completed_at')} | {item.get('health_status')} | "
                    f"Health Risk {item.get('health_risk_score')} | {item.get('target')}"
                )
                lines.append(f"  Recommendation: {item.get('recommendation')}")
                if item.get("report_html"):
                    lines.append(f"  Health Report: {item.get('report_html')}")
                lines.append("")
            lines.append("SCAN HISTORY")
            lines.append("=" * 78)
        for item in entries[:80]:
            lines.append(f"{item.get('completed_at')} | {item.get('status')} | Risk {item.get('risk_score')} | {item.get('target')}")
            lines.append(f"  Mode: {item.get('scan_mode')} | Test: {item.get('test_size')}")
            lines.append(f"  Report: {item.get('report_path')}")
            if item.get("pdf_report_path"):
                lines.append(f"  PDF: {item.get('pdf_report_path')}")
            lines.append("")
        self.set_text(self.history_text, "\n".join(lines) if lines else "No completed scan or health history yet.\n")

    def refresh_health_history(self):
        entries = load_health_history()
        lines = ["STORAGE HEALTH & DIAGNOSTICS HISTORY", "=" * 78, ""]
        for item in entries[:120]:
            lines.append(
                f"{item.get('completed_at')} | {item.get('health_status')} | "
                f"Health Risk {item.get('health_risk_score')} | {item.get('target')}"
            )
            lines.append(f"  Recommendation: {item.get('recommendation')}")
            lines.append(f"  SMART: {item.get('smart_status')}")
            lines.append(f"  Windows: {item.get('windows_health_status')}")
            lines.append(f"  Read Stability: {item.get('read_stability_status')}")
            if item.get("report_html"):
                lines.append(f"  HTML Report: {item.get('report_html')}")
            if item.get("report_txt"):
                lines.append(f"  TXT Report: {item.get('report_txt')}")
            lines.append("")
        self.set_text(self.health_history_text, "\n".join(lines) if entries else "No storage health diagnostics history yet.\n")

    def discard_selected_session(self):
        selected = self.session_var.get()
        if not selected:
            messagebox.showinfo("Discard Session", "No session selected.")
            return
        session_dir = Path(selected.split(" | ")[-1])
        if not messagebox.askyesno("Delete Session Data", f"Delete checkpoint and temporary test data?\n\n{session_dir}"):
            return
        try:
            resolved = session_dir.resolve()
            if TEST_DIR_NAME not in str(resolved):
                raise ValueError("Refusing to delete a path outside the test directory.")
            shutil.rmtree(resolved)
            self.refresh_sessions()
            messagebox.showinfo("Discard Session", "Session deleted.")
        except Exception as exc:
            messagebox.showerror("Delete Failed", str(exc))

    def cleanup_old_temp_files(self):
        if not messagebox.askyesno("Cleanup Confirmation", "Search selected drive for old verifier temp sessions and ask before deleting each group?"):
            return
        self.refresh_sessions()
        messagebox.showinfo("Cleanup", "Use the session drop-down and Discard Selected Session to remove old data safely.")

    def on_close(self):
        if self.scan_thread and self.scan_thread.is_alive():
            if not messagebox.askyesno("Scan Running", "A scan is active. Close anyway and preserve the resume checkpoint?"):
                return
            if self.scanner:
                self.scanner.cancel()
        if self.health_thread and self.health_thread.is_alive() and self.health_runner:
            self.health_runner.cancel()
        self.destroy()


if __name__ == "__main__":
    app = CyberStorageVerifierApp()
    app.mainloop()
