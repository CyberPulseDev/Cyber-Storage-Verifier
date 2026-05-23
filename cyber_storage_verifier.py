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
APP_VERSION = "2.0"
TEST_DIR_NAME = "_csv_temp_integrity_test"
SESSION_PREFIX = "session_"
CHECKPOINT_NAME = "checkpoint.json"
BLOCK_REPORT_NAME = "block_report.csv"
LOG_FILE_NAME = "scanner.log"
REPORT_DIR_NAME = "CyberStorageVerifier_Reports"
HISTORY_FILE = Path.home() / "Documents" / REPORT_DIR_NAME / "scan_history.json"

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
REPORT_FORMATS = ("Text", "JSON", "CSV", "HTML")
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


def smartctl_available():
    candidates = [
        "smartctl.exe",
        "smartctl",
        r"C:\Program Files\smartmontools\bin\smartctl.exe",
        r"C:\Program Files (x86)\smartmontools\bin\smartctl.exe",
    ]
    for exe in candidates:
        path = shutil.which(exe)
        if path:
            return path
        if os.path.isfile(exe):
            return exe
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
    reports_dir = Path.home() / "Documents" / REPORT_DIR_NAME
    try:
        reports_dir.mkdir(parents=True, exist_ok=True)
    except Exception:
        reports_dir = Path(tempfile.gettempdir()) / REPORT_DIR_NAME
        reports_dir.mkdir(parents=True, exist_ok=True)
    return reports_dir


def append_history(entry: dict):
    reports_dir = ensure_reports_dir()
    history_path = reports_dir / "scan_history.json"
    try:
        existing = []
        if history_path.exists():
            existing = json.loads(history_path.read_text(encoding="utf-8"))
            if not isinstance(existing, list):
                existing = []
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
    write_failures: int = 0
    read_failures: int = 0
    speed_drops: list = field(default_factory=list)
    fake_capacity_indicators: list = field(default_factory=list)
    issues: list = field(default_factory=list)
    report_path: str = ""
    json_report_path: str = ""
    csv_report_path: str = ""
    html_report_path: str = ""
    session_id: str = ""
    session_dir: str = ""
    scan_mode: str = "Balanced Scan"
    flush_policy: str = "Balanced"
    conclusion: str = ""


@dataclass
class ScannerSettings:
    default_scan_mode: str = "Balanced Scan"
    default_block_size_mb: str = "AUTO"
    flush_policy: str = "Balanced"
    retry_count: int = 2
    retry_delay_sec: float = 0.4
    report_formats: list = field(default_factory=lambda: ["Text", "JSON", "CSV", "HTML"])
    auto_cleanup_old_sessions: bool = False
    theme: str = "Cyber"
    show_advanced_warnings: bool = True
    exclude_system_drive: bool = True
    enable_smart_checks: bool = True
    enable_powershell_metadata: bool = True
    delayed_verify_seconds: int = 0
    random_recheck_percent: int = 8


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
        self.session = {}
        self.blocks = []
        self.test_file = None
        self.logger = logging.getLogger(APP_NAME)

    def cancel(self):
        self.cancelled = True

    def pause(self):
        self.paused = True

    def resume(self):
        self.paused = False

    def emergency(self):
        self.emergency_stop = True
        self.cancelled = True

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
                meta, warning = get_disk_metadata_for_drive(disk_root)
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
            self.log(traceback.format_exc())
            self.logger.exception("Scanner exception")
        finally:
            self.finish_session(result)
        return self.finalize(result)

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
        write_speeds = []
        read_speeds = []

        with open(self.test_file, mode, buffering=1024 * 1024) as fh:
            for block in self.blocks:
                self.wait_if_paused()
                if self.cancelled:
                    self.log("Scan stopped. Session checkpoint was preserved for resume.")
                    break
                if block.write_status == "written" and block.expected_sha256 and not self.recheck_all:
                    continue
                ok = self.retry_io(lambda b=block: self.write_block(fh, b), block)
                if not ok:
                    block.write_status = "failed"
                    result.write_failures += 1
                    self.log(f"[High] Write failure at block {block.index + 1}: {block.error_details}")
                    self.save_checkpoint()
                    continue
                written_bytes += block.size
                write_speeds.append(block.write_speed_mb_s)
                self.save_checkpoint()
                pct = 23 + int((written_bytes / max(1, result.test_size_bytes)) * 34)
                self.progress(min(57, pct))
                self.metric({"phase": "Writing", "write_speed": block.write_speed_mb_s, "block": block.index + 1})
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
            for block in verify_plan:
                self.wait_if_paused()
                if self.cancelled:
                    self.log("Scan stopped. Session checkpoint was preserved for resume.")
                    break
                if block.verification_result == "ok" and not self.recheck_all:
                    continue
                ok = self.retry_io(lambda b=block: self.read_verify_block(fh, b), block)
                if not ok:
                    block.read_status = "failed"
                    block.verification_result = "read_failed"
                    result.read_failures += 1
                    self.log(f"[High] Read failure at block {block.index + 1}: {block.error_details}")
                elif block.verification_result == "corrupt":
                    result.corrupted_blocks += 1
                    self.log(f"[Critical] Data corruption detected at block {block.index + 1}")
                else:
                    verified_bytes += block.size
                    read_speeds.append(block.read_speed_mb_s)
                self.save_checkpoint()
                pct = 57 + int((verified_bytes / max(1, result.test_size_bytes)) * 31)
                self.progress(min(88, pct))
                self.metric({"phase": "Verifying", "read_speed": block.read_speed_mb_s, "block": block.index + 1})
                if block.index % 4 == 0 or block.index == verify_plan[-1].index:
                    self.log(f"Verified {human_bytes(verified_bytes)} / {human_bytes(result.test_size_bytes)}")

            self.random_recheck(fh, result, read_speeds)

        result.blocks_tested = len([b for b in self.blocks if b.write_status == "written"])
        result.verified_blocks = len([b for b in self.blocks if b.verification_result == "ok"])
        result.failed_blocks = len([b for b in self.blocks if b.verification_result in ("corrupt", "read_failed") or b.write_status == "failed"])
        if write_speeds:
            result.write_mb_s = sum(write_speeds) / len(write_speeds)
        else:
            prior = [b.write_speed_mb_s for b in self.blocks if b.write_speed_mb_s > 0]
            result.write_mb_s = sum(prior) / len(prior) if prior else 0
        all_read = [b.read_speed_mb_s for b in self.blocks if b.read_speed_mb_s > 0]
        result.read_mb_s = sum(all_read) / len(all_read) if all_read else 0
        self.detect_speed_anomalies(result)

        if result.write_failures:
            self.add_issue(result, "High", "Write failure detected", "The device failed during temporary test data writing.", 32)
        if result.corrupted_blocks:
            self.add_issue(
                result,
                "Critical",
                "Data corruption detected",
                f"{result.corrupted_blocks} block(s) changed after writing. This is a strong counterfeit/failing-device signal.",
                60,
            )
        if result.read_failures:
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
                    result.corrupted_blocks += 1
                    self.log(f"[Critical] Random recheck failed at block {block.index + 1}")
            else:
                block.verification_result = "read_failed"
                result.read_failures += 1
            if previous != block.verification_result:
                self.save_checkpoint()

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
        self.session["status"] = "completed" if not self.cancelled and not result.failed_blocks else "active"
        self.session["result_status"] = result.status
        try:
            self.save_checkpoint()
            self.write_session_block_csv(Path(self.session["session_dir"]) / BLOCK_REPORT_NAME)
            if self.cancelled:
                self.log("Resume mode active: unfinished test files were preserved.")
        except Exception as exc:
            self.log(f"[Warning] Could not update session checkpoint: {exc}")

    def finalize(self, result: ScanResult):
        result.completed_at = now_stamp()
        result.risk_score = min(100, max(0, result.risk_score))
        critical = any(i.severity == "Critical" for i in result.issues)
        high_count = sum(1 for i in result.issues if i.severity == "High")
        if critical or result.risk_score >= 70:
            result.status = "Likely Fake or Failing"
        elif high_count >= 1 or result.risk_score >= 45:
            result.status = "Suspicious"
        elif result.risk_score >= 18:
            result.status = "Needs Deeper Testing"
        elif result.test_size_bytes == 0 or self.cancelled:
            result.status = "Inconclusive"
        else:
            result.status = "No Major Issues Found"
        result.conclusion = self.make_conclusion(result)
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
                    "session_dir": result.session_dir,
                }
            )
        except Exception as exc:
            self.log(f"[Warning] Report generation failed: {exc}")
            self.logger.exception("Report generation failed")
        self.progress(100)
        self.log(f"Scan completed. Final status: {result.status}")
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
        result.csv_report_path = str(base.with_suffix(".csv"))
        self.write_session_block_csv(Path(result.csv_report_path))
        data = self.result_to_dict(result)
        result.json_report_path = str(base.with_suffix(".json"))
        Path(result.json_report_path).write_text(json.dumps(data, indent=2), encoding="utf-8")
        result.report_path = str(base.with_suffix(".txt"))
        Path(result.report_path).write_text(self.text_report(result), encoding="utf-8")
        result.html_report_path = str(base.with_suffix(".html"))
        Path(result.html_report_path).write_text(self.html_report(result), encoding="utf-8")

    def result_to_dict(self, result):
        data = asdict(result)
        data["issues"] = [asdict(i) if hasattr(i, "__dataclass_fields__") else i for i in result.issues]
        data["blocks"] = [asdict(b) for b in self.blocks]
        return data

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
            f"Verified Blocks:      {result.verified_blocks}",
            f"Failed Blocks:        {result.failed_blocks}",
            f"Average Write Speed:  {result.write_mb_s:.2f} MB/s",
            f"Average Read Speed:   {result.read_mb_s:.2f} MB/s",
            f"Speed Variation:      {result.speed_variation_percent:.1f}%",
            f"Write Failures:       {result.write_failures}",
            f"Read Failures:        {result.read_failures}",
            f"Corrupted Blocks:     {result.corrupted_blocks}",
            "",
            "SPEED DROPS",
            "-" * 78,
        ]
        lines += [json.dumps(d) for d in result.speed_drops] or ["None recorded."]
        lines += ["", "FAKE-CAPACITY INDICATORS", "-" * 78]
        lines += result.fake_capacity_indicators or ["No strong fake-capacity indicators recorded."]
        lines += ["", "DEVICE / FILESYSTEM METADATA", "-" * 78, f"Drive Type: {result.drive_type}"]
        for k, v in (result.volume_info or {}).items():
            lines.append(f"{k}: {v}")
        for k, v in (result.disk_metadata or {}).items():
            lines.append(f"{k}: {v}")
        if result.metadata_warning:
            lines.append(f"Metadata Warning: {result.metadata_warning}")
        if result.smart_warning:
            lines.append(f"SMART Note: {result.smart_warning}")
        lines += ["", "FINDINGS", "-" * 78]
        if result.issues:
            for issue in result.issues:
                lines.append(f"[{issue.severity}] {issue.title}")
                lines.append(f"  {issue.detail}")
        else:
            lines.append("No major suspicious findings were detected during this scan.")
        lines += [
            "",
            "LIMITATIONS",
            "-" * 78,
            "The tool writes only normal test files in the selected folder. It does not overwrite raw disks.",
            "A partial scan cannot prove an entire large-capacity device is genuine. Full validation is strongest.",
            "=" * 78,
        ]
        return "\n".join(lines)

    def html_report(self, result: ScanResult) -> str:
        rows = "".join(
            f"<tr><td>{b.index}</td><td>{human_bytes(b.offset)}</td><td>{human_bytes(b.size)}</td>"
            f"<td>{html.escape(b.write_status)}</td><td>{html.escape(b.verification_result)}</td>"
            f"<td>{b.write_speed_mb_s:.2f}</td><td>{b.read_speed_mb_s:.2f}</td>"
            f"<td>{html.escape(b.error_details)}</td></tr>"
            for b in self.blocks[:500]
        )
        issues = "".join(f"<li><b>{html.escape(i.severity)} - {html.escape(i.title)}</b>: {html.escape(i.detail)}</li>" for i in result.issues)
        return f"""<!doctype html>
<html><head><meta charset="utf-8"><title>{APP_NAME} Report</title>
<style>
body{{font-family:Segoe UI,Arial,sans-serif;background:#070B14;color:#D7F7FF;margin:24px}}
.card{{background:#0B1220;border:1px solid #1B3355;padding:16px;margin:12px 0}}
h1,h2{{color:#00E5FF}} table{{width:100%;border-collapse:collapse;font-size:12px}}
td,th{{border:1px solid #1B3355;padding:6px;text-align:left}} th{{background:#101A2C}}
.status{{color:#39FF88;font-weight:700}} .risk{{color:#FFD166;font-weight:700}}
</style></head><body>
<h1>{APP_NAME} v{APP_VERSION}</h1>
<div class="card"><h2>Final Result</h2><p class="status">{html.escape(result.status)}</p>
<p class="risk">Risk score: {result.risk_score}/100</p><p>{html.escape(result.conclusion)}</p></div>
<div class="card"><h2>Timeline</h2><p>Started: {result.started_at}<br>Completed: {result.completed_at}<br>Session: {html.escape(result.session_id)}</p></div>
<div class="card"><h2>Drive Metadata</h2><pre>{html.escape(json.dumps(result.disk_metadata, indent=2))}</pre></div>
<div class="card"><h2>Findings</h2><ul>{issues or '<li>No major suspicious findings were detected.</li>'}</ul></div>
<div class="card"><h2>Block Report Preview</h2><table><tr><th>#</th><th>Offset</th><th>Size</th><th>Write</th><th>Verify</th><th>Write MB/s</th><th>Read MB/s</th><th>Error</th></tr>{rows}</table></div>
</body></html>"""


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
        self.scan_thread = None
        self.scanner = None
        self.last_result = None
        self.settings = ScannerSettings()
        self.resume_session_path = None
        self.setup_logging()
        self.setup_style()
        self.create_ui()
        self.refresh_drives()
        self.refresh_sessions()
        self.refresh_history()
        self.after(100, self.process_queues)
        self.protocol("WM_DELETE_WINDOW", self.on_close)

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
        for name in ("Dashboard", "Scan Controls", "Active Scan", "Device Metadata", "Findings", "Reports", "Scan History", "Settings", "Help Center"):
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
        self.create_settings_tab()
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
            ("Corrupted Blocks", "0", CYBER_RED),
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
        ttk.Button(panel, text="Browse", style="Cyber.TButton", command=self.browse_path).grid(row=r, column=2, sticky="ew", padx=18, pady=5)
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
        panel = self.make_panel(tab)
        panel.grid(row=0, column=0, sticky="new", padx=8, pady=8)
        panel.grid_columnconfigure((0, 1, 2, 3), weight=1)
        self.section_title(panel, "REPORTS").grid(row=0, column=0, columnspan=4, sticky="w", padx=14, pady=(12, 8))
        ttk.Button(panel, text="Open Text Report", style="Cyber.TButton", command=lambda: self.open_path("report_path")).grid(row=1, column=0, sticky="ew", padx=8, pady=12)
        ttk.Button(panel, text="Open JSON Report", style="Cyber.TButton", command=lambda: self.open_path("json_report_path")).grid(row=1, column=1, sticky="ew", padx=8, pady=12)
        ttk.Button(panel, text="Open CSV Block Report", style="Cyber.TButton", command=lambda: self.open_path("csv_report_path")).grid(row=1, column=2, sticky="ew", padx=8, pady=12)
        ttk.Button(panel, text="Open HTML Report", style="Cyber.TButton", command=lambda: self.open_path("html_report_path")).grid(row=1, column=3, sticky="ew", padx=8, pady=12)
        ttk.Button(panel, text="Open Reports Folder", style="Cyber.TButton", command=lambda: self.open_file(str(ensure_reports_dir()))).grid(row=2, column=0, columnspan=4, sticky="ew", padx=8, pady=(0, 12))

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
        tk.Label(sidebar, text="TOPICS", bg=CYBER_PANEL, fg=CYBER_CYAN, font=("Consolas", 12, "bold")).grid(row=0, column=0, sticky="w", padx=12, pady=(12, 8))
        self.help_nav_frame = tk.Frame(sidebar, bg=CYBER_PANEL)
        self.help_nav_frame.grid(row=1, column=0, sticky="nsew", padx=8, pady=(0, 8))

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
        self.help_canvas.bind_all("<MouseWheel>", self._help_mousewheel)
        self.help_search_var.trace_add("write", lambda *_: self.refresh_help_content())
        self.help_sections_open = {}
        self.help_section_widgets = {}
        self.refresh_help_content()

    def get_help_sections(self):
        py_version = sys.version.split()[0]
        os_label = f"{platform.system()} {platform.release()} ({platform.version()})"
        smart_state = "Available" if smartctl_available() else "Not detected"
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
                    "Developer: Rush",
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
                "Version Information",
                "Build and runtime details",
                [
                    f"Application: {APP_NAME}",
                    f"Version: {APP_VERSION}",
                    f"Build Time: Runtime build on {now_stamp()}",
                    f"Python: {sys.version}",
                    f"Platform: {platform.platform()}",
                    f"Executable: {sys.executable}",
                    "Compatibility Target: Windows 11 with Python 3.9+.",
                ],
                "info",
            ),
            (
                "Changelog / Update Notes",
                "Major feature history",
                [
                    "v2.0: Added resumable block scan sessions, JSON checkpoints, per-block metadata, random rechecks, delayed verification, scan history, and multi-format reports.",
                    "v2.0: Added Quick, Balanced, Deep, Full Capacity Validation, Random Spot Check, Fake-Capacity Boundary, and Quick Health modes.",
                    "v2.0: Added enterprise-style tabbed UI, dashboard cards, active progress views, settings, improved input styling, and safer cleanup.",
                    "v2.0: Improved metadata checks, SMART integration, speed anomaly detection, risk categories, and report conclusions.",
                    "v2.1 Help Center: Added integrated documentation, search, collapsible sections, exports, shortcuts, onboarding, context help, and developer credits.",
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
            self.help_nav_frame.grid_columnconfigure(0, weight=1)
            self.add_help_section(self.help_content_frame, title, subtitle, lines, kind, idx)
        self.help_content_frame.update_idletasks()
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
        subtitle_lbl = tk.Label(panel, text=subtitle, bg=CYBER_PANEL, fg=INPUT_MUTED, font=("Segoe UI", 9, "bold"), anchor="w")
        subtitle_lbl.grid(row=1, column=0, sticky="ew", pady=(2, 8))
        body = tk.Frame(panel, bg=CYBER_PANEL)
        if is_open:
            body.grid(row=2, column=0, sticky="ew")
        box = self.help_info_box(body, lines, kind)
        box.pack(fill="x", expand=True)
        self.help_section_widgets[title] = {"panel": panel, "body": body, "header": header}

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

    def _help_mousewheel(self, event):
        if self.notebook.select() == str(self.tabs["Help Center"]):
            self.help_canvas.yview_scroll(int(-1 * (event.delta / 120)), "units")

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
        for text, var in (
            ("Enable SMART checks", self.smart_var),
            ("Enable PowerShell metadata checks", self.ps_var),
            ("Exclude system drive by default", self.exclude_c_var),
            ("Show advanced warnings", self.warn_var),
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
        return frame

    def text_widget(self, frame):
        return frame.winfo_children()[0]

    def set_text(self, frame, content):
        text = self.text_widget(frame)
        text.configure(state="normal")
        text.delete("1.0", tk.END)
        text.insert(tk.END, content)
        text.configure(state="disabled")

    def append_text(self, frame, content):
        text = self.text_widget(frame)
        text.configure(state="normal")
        text.insert(tk.END, content)
        text.see(tk.END)
        text.configure(state="disabled")

    def log_callback(self, message):
        logging.info(message)
        self.log_queue.put(message)

    def progress_callback(self, value):
        self.progress_queue.put(value)

    def metric_callback(self, metrics):
        self.metric_queue.put(metrics)

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
        drives = get_windows_drives() or ["/"]
        if self.settings.exclude_system_drive and os.name == "nt":
            drives = [d for d in drives if not d.upper().startswith("C:")] or drives
        self.drive_combo["values"] = drives
        if drives:
            self.drive_combo.current(0)
            self.cards["Selected Drive"].value_label.config(text=drives[0])

    def browse_path(self):
        path = filedialog.askdirectory(title="Select Target Drive or Folder")
        if path:
            self.drive_var.set(path)
            self.cards["Selected Drive"].value_label.config(text=path)

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
        target = self.drive_var.get()
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
        for name, value in (("Current Phase", "Starting"), ("ETA", "Calculating"), ("Write Speed", "0 MB/s"), ("Read Speed", "0 MB/s"), ("Corrupted Blocks", "0"), ("Risk Score", "0 / 100")):
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
        coverage = (res.test_size_bytes / max(1, res.capacity_reported_bytes)) * 100 if res.capacity_reported_bytes else 0
        self.cards["Test Coverage"].value_label.config(text=f"{coverage:.2f}%")
        self.cards["Current Phase"].value_label.config(text=res.status)
        self.cards["Write Speed"].value_label.config(text=f"{res.write_mb_s:.2f} MB/s")
        self.cards["Read Speed"].value_label.config(text=f"{res.read_mb_s:.2f} MB/s")
        self.cards["Corrupted Blocks"].value_label.config(text=str(res.corrupted_blocks))
        self.cards["Risk Score"].value_label.config(text=f"{res.risk_score} / 100")
        risk_color = CYBER_RED if res.risk_score >= 70 else CYBER_ORANGE if res.risk_score >= 30 else CYBER_GREEN
        self.cards["Risk Score"].value_label.config(fg=risk_color)
        self.update_device_text(res)
        self.update_findings_text(res)
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
                    self.header_status.config(text="COMPLETED", fg=CYBER_GREEN)
                else:
                    self.append_text(self.log_text, str(msg) + "\n")
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
        except queue.Empty:
            pass
        self.after(100, self.process_queues)

    def apply_settings(self):
        self.settings.retry_count = max(0, safe_int(self.setting_vars.get("retry_count", tk.StringVar(value="2")).get(), 2))
        self.settings.retry_delay_sec = max(0.0, safe_float(self.setting_vars.get("retry_delay_sec", tk.StringVar(value="0.4")).get(), 0.4))
        self.settings.delayed_verify_seconds = max(0, safe_int(self.setting_vars.get("delayed_verify_seconds", tk.StringVar(value="0")).get(), 0))
        self.settings.random_recheck_percent = max(0, min(100, safe_int(self.setting_vars.get("random_recheck_percent", tk.StringVar(value="8")).get(), 8)))
        self.settings.enable_smart_checks = self.smart_var.get()
        self.settings.enable_powershell_metadata = self.ps_var.get()
        self.settings.exclude_system_drive = self.exclude_c_var.get()
        self.settings.show_advanced_warnings = self.warn_var.get()

    def discover_sessions(self):
        sessions = []
        roots = get_windows_drives() if os.name == "nt" else ["/"]
        target = self.drive_var.get()
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
        lines = []
        for item in entries[:80]:
            lines.append(f"{item.get('completed_at')} | {item.get('status')} | Risk {item.get('risk_score')} | {item.get('target')}")
            lines.append(f"  Mode: {item.get('scan_mode')} | Test: {item.get('test_size')}")
            lines.append(f"  Report: {item.get('report_path')}")
            lines.append("")
        self.set_text(self.history_text, "\n".join(lines) if lines else "No completed scan history yet.\n")

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
        self.destroy()


if __name__ == "__main__":
    app = CyberStorageVerifierApp()
    app.mainloop()
