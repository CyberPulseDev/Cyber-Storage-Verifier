import importlib.util
from pathlib import Path


APP_PATH = Path(__file__).with_name("Cyber Storage Verifier.py")


def load_app():
    spec = importlib.util.spec_from_file_location("cyber_storage_verifier", APP_PATH)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_smart_parser_and_risk_scoring():
    app = load_app()
    diag = app.StorageHealthDiagnostics("C:/")
    parsed = diag.parse_smart_output(
        "\n".join(
            [
                "Device Model: Samsung SSD 980 PRO",
                "Serial Number: ABC123",
                "SMART overall-health self-assessment test result: PASSED",
                "  5 Reallocated_Sector_Ct 0x0033 100 100 010 Pre-fail Always - 2",
                "197 Current_Pending_Sector 0x0012 100 100 000 Old_age Always - 1",
                "198 Offline_Uncorrectable 0x0010 100 100 000 Old_age Offline - 0",
                "199 UDMA_CRC_Error_Count 0x003e 200 200 000 Old_age Always - 3",
                "Temperature: 54 Celsius",
                "Percentage Used: 71%",
            ]
        )
    )
    assert parsed["overall_health"] == "PASSED"
    assert parsed["reallocated_sector_count"] == 2
    assert parsed["current_pending_sector_count"] == 1
    assert parsed["udma_crc_error_count"] == 3
    assert parsed["temperature_celsius"] == 54
    assert parsed["percentage_used"] == 71
    diag.merge_smart(parsed)
    diag.evaluate_smart_risk()
    assert diag.result.health_risk_score >= 40


def test_smart_device_match_prefers_serial_and_model():
    app = load_app()
    diag = app.StorageHealthDiagnostics("C:/")
    raw = "Device Model: Samsung SSD 980 PRO\nSerial Number: ABC123\n"
    score, reason = diag.score_smart_device_match(
        "/dev/sda",
        {},
        raw,
        {"SerialNumber": "ABC123", "Model": "Samsung SSD 980 PRO", "BusType": "NVMe"},
    )
    assert score >= 90
    assert "serial matched" in reason


def test_empty_surface_scan_is_inconclusive_not_error(tmp_path):
    app = load_app()
    diag = app.StorageHealthDiagnostics(str(tmp_path))
    diag.run_surface_read_stability_scan(max_bytes=1024 * 1024, chunk_size=1024 * 1024, max_seconds=2)
    assert diag.result.read_stability_status == "No readable sample"
    assert "read_only_scope" in diag.result.surface_results


def test_drive_health_risk_scoring_critical_values():
    app = load_app()
    score, status, recommendation, issues = app.drive_health_risk_from_values(
        smart_parsed={
            "overall_health": "FAILED",
            "current_pending_sector_count": 2,
            "offline_uncorrectable": 1,
            "temperature_celsius": 61,
            "nvme_media_data_integrity_errors": 1,
        },
        windows_parsed={"Disk.HealthStatus": "Warning"},
    )
    assert score < 40
    assert status == "CRITICAL"
    assert "important data" in recommendation.lower() or "replacement" in recommendation.lower()
    assert any(issue["title"] == "Offline uncorrectable sectors" for issue in issues)


def test_drive_snapshot_fallbacks_without_smartctl(monkeypatch, tmp_path):
    app = load_app()
    monkeypatch.setattr(app, "get_drive_type", lambda _root: "Unknown")
    monkeypatch.setattr(app, "get_volume_info", lambda _root: {"volume_name": "", "filesystem": "NTFS"})
    monkeypatch.setattr(app, "get_disk_metadata_for_drive_cached", lambda _root: ({}, "PowerShell unavailable"))
    monkeypatch.setattr(app, "collect_windows_health_for_root", lambda _root: ({}, "Windows unavailable"))
    usage = type("Usage", (), {"total": 128 * 1024**3, "used": 64 * 1024**3, "free": 64 * 1024**3})()
    monkeypatch.setattr(app.shutil, "disk_usage", lambda _root: usage)
    snapshot = app.build_drive_health_snapshot(str(tmp_path), [], "smartctl missing")
    assert snapshot.model == "Unknown"
    assert snapshot.capacity == usage.total
    assert snapshot.smart_status == "Unavailable"
    assert snapshot.health_status in ("UNKNOWN", "GOOD")
    assert any("smartctl missing" in issue["detail"] for issue in snapshot.issues)


def test_uncertain_smart_mapping_marks_low_confidence(monkeypatch, tmp_path):
    app = load_app()
    monkeypatch.setattr(app, "get_drive_type", lambda _root: "Fixed")
    monkeypatch.setattr(app, "get_volume_info", lambda _root: {"volume_name": "DATA", "filesystem": "NTFS"})
    monkeypatch.setattr(app, "get_disk_metadata_for_drive_cached", lambda _root: ({"Model": "Expected Model", "SerialNumber": "EXPECTED"}, ""))
    monkeypatch.setattr(app, "collect_windows_health_for_root", lambda _root: ({"Disk.HealthStatus": "Healthy"}, ""))
    usage = type("Usage", (), {"total": 1000, "used": 400, "free": 600})()
    monkeypatch.setattr(app.shutil, "disk_usage", lambda _root: usage)
    smart = [{
        "device": "/dev/sdz",
        "raw": "Device Model: Different Disk\nSerial Number: OTHER\nSMART overall-health self-assessment test result: PASSED",
        "parsed": {"overall_health": "PASSED", "model": "Different Disk", "serial_number": "OTHER"},
    }]
    snapshot = app.build_drive_health_snapshot(str(tmp_path), smart, "")
    assert snapshot.smart_match_confidence == "Low"
    assert any("Low confidence" in issue["detail"] for issue in snapshot.issues)


def test_extended_smart_parser_device_specific_attributes():
    app = load_app()
    diag = app.StorageHealthDiagnostics("C:/")
    parsed = diag.parse_smart_output(
        "\n".join(
            [
                "Spin_Retry_Count 0x0013 100 100 097 Pre-fail Always - 0",
                "Seek_Error_Rate 0x000f 083 060 030 Pre-fail Always - 123",
                "Start_Stop_Count 0x0032 100 100 020 Old_age Always - 42",
                "Load_Cycle_Count 0x0032 099 099 000 Old_age Always - 77",
                "Unsafe Shutdowns: 5",
                "Available Spare: 96%",
                "Available Spare Threshold: 10%",
                "Controller Busy Time: 12",
                "Host Read Commands: 1000",
                "Host Write Commands: 2000",
            ]
        )
    )
    assert parsed["spin_retry_count"] == 0
    assert parsed["seek_error_rate"] == 123
    assert parsed["start_stop_count"] == 42
    assert parsed["load_cycle_count"] == 77
    assert parsed["unsafe_shutdowns"] == 5
    assert parsed["nvme_available_spare"] == 96
    assert parsed["nvme_available_spare_threshold"] == 10
    assert parsed["nvme_controller_busy_time"] == 12
    assert parsed["nvme_host_read_commands"] == 1000
    assert parsed["nvme_host_write_commands"] == 2000


def test_hdd_wear_and_temperature_fallbacks_do_not_penalize(monkeypatch, tmp_path):
    app = load_app()
    monkeypatch.setattr(app, "get_drive_type", lambda _root: "Fixed")
    monkeypatch.setattr(app, "get_volume_info", lambda _root: {"volume_name": "ARCHIVE", "filesystem": "NTFS"})
    monkeypatch.setattr(app, "get_disk_metadata_for_drive_cached", lambda _root: ({"Model": "Seagate Barracuda", "PhysicalMediaType": "HDD", "BusType": "SATA"}, ""))
    monkeypatch.setattr(app, "collect_windows_health_for_root", lambda _root: ({"Disk.HealthStatus": "Healthy"}, ""))
    usage = type("Usage", (), {"total": 2 * 1024**4, "used": 1024**4, "free": 1024**4})()
    monkeypatch.setattr(app.shutil, "disk_usage", lambda _root: usage)
    smart = [{
        "device": "/dev/sda",
        "raw": "Device Model: Seagate Barracuda\nSerial Number: HDD1\nSMART overall-health self-assessment test result: PASSED",
        "parsed": {"overall_health": "PASSED", "model": "Seagate Barracuda", "serial_number": "HDD1"},
    }]
    snapshot = app.build_drive_health_snapshot(str(tmp_path), smart, "")
    assert snapshot.wear == "N/A (Mechanical HDD)"
    assert snapshot.temperature == "Not Exposed"
    assert snapshot.health_score == 100
    assert snapshot.recommendation == "Mechanical HDD operating normally"


def test_nvme_wear_and_temperature_display(monkeypatch, tmp_path):
    app = load_app()
    monkeypatch.setattr(app, "get_drive_type", lambda _root: "Fixed")
    monkeypatch.setattr(app, "get_volume_info", lambda _root: {"volume_name": "SYSTEM", "filesystem": "NTFS"})
    monkeypatch.setattr(app, "get_disk_metadata_for_drive_cached", lambda _root: ({"Model": "Samsung SSD 980 PRO", "PhysicalMediaType": "SSD", "BusType": "NVMe"}, ""))
    monkeypatch.setattr(app, "collect_windows_health_for_root", lambda _root: ({"Disk.HealthStatus": "Healthy"}, ""))
    usage = type("Usage", (), {"total": 1024**4, "used": 512 * 1024**3, "free": 512 * 1024**3})()
    monkeypatch.setattr(app.shutil, "disk_usage", lambda _root: usage)
    smart = [{
        "device": "/dev/nvme0",
        "raw": "Model Number: Samsung SSD 980 PRO\nSerial Number: NVME1\nSMART overall-health self-assessment test result: PASSED",
        "parsed": {"overall_health": "PASSED", "model": "Samsung SSD 980 PRO", "serial_number": "NVME1", "percentage_used": 3, "temperature_celsius": 42},
    }]
    snapshot = app.build_drive_health_snapshot(str(tmp_path), smart, "")
    assert snapshot.wear == "3% used"
    assert snapshot.temperature == "42 C"
    assert snapshot.recommendation == "SSD wear remains within normal range"


def test_usb_bridge_fallback_wording(monkeypatch, tmp_path):
    app = load_app()
    monkeypatch.setattr(app, "get_drive_type", lambda _root: "Removable")
    monkeypatch.setattr(app, "get_volume_info", lambda _root: {"volume_name": "USB", "filesystem": "exFAT"})
    monkeypatch.setattr(app, "get_disk_metadata_for_drive_cached", lambda _root: ({"Model": "USB Storage", "PhysicalMediaType": "Removable", "BusType": "USB"}, ""))
    monkeypatch.setattr(app, "collect_windows_health_for_root", lambda _root: ({"Disk.HealthStatus": "Healthy"}, ""))
    usage = type("Usage", (), {"total": 64 * 1024**3, "used": 8 * 1024**3, "free": 56 * 1024**3})()
    monkeypatch.setattr(app.shutil, "disk_usage", lambda _root: usage)
    snapshot = app.build_drive_health_snapshot(str(tmp_path), [], "smartctl missing")
    assert snapshot.temperature == "USB Bridge Hidden"
    assert snapshot.wear == "Not Exposed"
    assert snapshot.recommendation == "SMART data partially unavailable"
    assert snapshot.health_score == 100


def test_detail_window_opens_once_and_handles_missing_smart():
    app = load_app()
    tk_app = app.CyberStorageVerifierApp()
    try:
        snap = app.DriveHealthSnapshot(
            root="Z:/",
            drive_letter="Z:",
            model="USB Storage",
            capacity=64 * 1024**3,
            free=32 * 1024**3,
            used=32 * 1024**3,
            bus_type="USB",
            media_type="Removable",
            smart_status="Unavailable",
            temperature="USB Bridge Hidden",
            wear="Not Exposed",
            recommendation="SMART data partially unavailable",
            raw_smart_preview="",
        )
        tk_app.drive_health_snapshots = [snap]
        tk_app.open_drive_full_details("Z:/")
        tk_app.update()
        first = tk_app.drive_detail_windows["Z:/"]["window"]
        tk_app.open_drive_full_details("Z:/")
        tk_app.update()
        second = tk_app.drive_detail_windows["Z:/"]["window"]
        assert first == second
        raw_text = tk_app.text_widget(tk_app.drive_detail_windows["Z:/"]["widgets"]["raw_text"]).get("1.0", "end-1c")
        assert "No raw SMART output" in raw_text
    finally:
        tk_app.destroy()


def test_single_drive_export_generation(monkeypatch, tmp_path):
    app = load_app()
    tk_app = app.CyberStorageVerifierApp()
    try:
        monkeypatch.setattr(app, "ensure_reports_dir", lambda: tmp_path)
        monkeypatch.setattr(app, "append_health_history", lambda _entry: None)
        monkeypatch.setattr(tk_app, "open_file", lambda _path: None)
        snap = app.DriveHealthSnapshot(root="Y:/", drive_letter="Y:", model="Samsung SSD", health_score=97, smart_status="PASSED")
        tk_app.export_single_drive_health_report(snap, "txt")
        tk_app.export_single_drive_health_report(snap, "json")
        tk_app.export_single_drive_health_report(snap, "html")
        assert list(tmp_path.glob("storage_health_Y_*.txt"))
        assert list(tmp_path.glob("storage_health_Y_*.json"))
        assert list(tmp_path.glob("storage_health_Y_*.html"))
    finally:
        tk_app.destroy()


def test_history_loading_filter(monkeypatch):
    app = load_app()
    tk_app = app.CyberStorageVerifierApp()
    try:
        monkeypatch.setattr(app, "load_health_history", lambda: [{"completed_at": "now", "target": "X:/", "health_status": "GOOD", "health_risk_score": 0, "recommendation": "OK"}])
        snap = app.DriveHealthSnapshot(root="X:/", drive_letter="X:", model="HDD", health_score=100)
        tk_app.drive_health_snapshots = [snap]
        tk_app.open_drive_full_details("X:/")
        tk_app.populate_detail_history("X:/", snap)
        text_found = False
        frame = tk_app.drive_detail_windows["X:/"]["widgets"]["history"]["frame"]
        for child in frame.winfo_children():
            for nested in child.winfo_children():
                try:
                    if "GOOD" in nested.cget("text"):
                        text_found = True
                except Exception:
                    pass
        assert text_found
    finally:
        tk_app.destroy()


if __name__ == "__main__":
    import tempfile

    test_smart_parser_and_risk_scoring()
    test_smart_device_match_prefers_serial_and_model()
    with tempfile.TemporaryDirectory() as tmp:
        test_empty_surface_scan_is_inconclusive_not_error(Path(tmp))
    score_app = load_app()
    test_drive_health_risk_scoring_critical_values()
    with tempfile.TemporaryDirectory() as tmp:
        class MonkeyPatch:
            def __init__(self):
                self._items = []
            def setattr(self, obj, name, value):
                old = getattr(obj, name)
                self._items.append((obj, name, old))
                setattr(obj, name, value)
            def undo(self):
                for obj, name, old in reversed(self._items):
                    setattr(obj, name, old)
        mp = MonkeyPatch()
        try:
            test_drive_snapshot_fallbacks_without_smartctl(mp, Path(tmp))
        finally:
            mp.undo()
    with tempfile.TemporaryDirectory() as tmp:
        class MonkeyPatch:
            def __init__(self):
                self._items = []
            def setattr(self, obj, name, value):
                old = getattr(obj, name)
                self._items.append((obj, name, old))
                setattr(obj, name, value)
            def undo(self):
                for obj, name, old in reversed(self._items):
                    setattr(obj, name, old)
        mp = MonkeyPatch()
        try:
            test_uncertain_smart_mapping_marks_low_confidence(mp, Path(tmp))
        finally:
            mp.undo()
    test_extended_smart_parser_device_specific_attributes()
    for test_func in (
        test_hdd_wear_and_temperature_fallbacks_do_not_penalize,
        test_nvme_wear_and_temperature_display,
        test_usb_bridge_fallback_wording,
    ):
        with tempfile.TemporaryDirectory() as tmp:
            class MonkeyPatch:
                def __init__(self):
                    self._items = []
                def setattr(self, obj, name, value):
                    old = getattr(obj, name)
                    self._items.append((obj, name, old))
                    setattr(obj, name, value)
                def undo(self):
                    for obj, name, old in reversed(self._items):
                        setattr(obj, name, old)
            mp = MonkeyPatch()
            try:
                test_func(mp, Path(tmp))
            finally:
                mp.undo()
    test_detail_window_opens_once_and_handles_missing_smart()
    with tempfile.TemporaryDirectory() as tmp:
        class MonkeyPatch:
            def __init__(self):
                self._items = []
            def setattr(self, obj, name, value):
                old = getattr(obj, name)
                self._items.append((obj, name, old))
                setattr(obj, name, value)
            def undo(self):
                for obj, name, old in reversed(self._items):
                    setattr(obj, name, old)
        mp = MonkeyPatch()
        try:
            test_single_drive_export_generation(mp, Path(tmp))
        finally:
            mp.undo()
    class MonkeyPatch:
        def __init__(self):
            self._items = []
        def setattr(self, obj, name, value):
            old = getattr(obj, name)
            self._items.append((obj, name, old))
            setattr(obj, name, value)
        def undo(self):
            for obj, name, old in reversed(self._items):
                setattr(obj, name, old)
    mp = MonkeyPatch()
    try:
        test_history_loading_filter(mp)
    finally:
        mp.undo()
    print("health diagnostics tests passed")
