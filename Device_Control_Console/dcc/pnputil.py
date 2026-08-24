"""``pnputil.exe`` driver: enumeration via its XML output, plus the write actions.

pnputil on Windows 10 21H2+ / Windows 11 supports ``/format xml``, which makes
this layer locale-proof -- no scraping of ``Instance ID:`` labels that change
with the display language.  Enumeration goes through ``/output-file`` so the
console code page can never mangle non-ASCII names.
"""

from __future__ import annotations

import os
import re
import shutil
import subprocess
import tempfile
import xml.etree.ElementTree as ET

PNPUTIL = os.path.join(
    os.environ.get("SystemRoot", r"C:\Windows"), "System32", "pnputil.exe"
)

CREATE_NO_WINDOW = 0x08000000


class PnpUtilError(RuntimeError):
    def __init__(self, message: str, returncode: int = -1, output: str = ""):
        super().__init__(message)
        self.returncode = returncode
        self.output = output


def available() -> bool:
    return os.path.isfile(PNPUTIL) or shutil.which("pnputil.exe") is not None


def _exe() -> str:
    if os.path.isfile(PNPUTIL):
        return PNPUTIL
    found = shutil.which("pnputil.exe")
    if not found:
        raise PnpUtilError("pnputil.exe not found on this system")
    return found


def run(args: list[str], timeout: int = 180) -> subprocess.CompletedProcess:
    """Run pnputil and return the completed process (never raises on non-zero)."""
    return subprocess.run(
        [_exe(), *args],
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=timeout,
        creationflags=CREATE_NO_WINDOW,
    )


def run_xml(args: list[str], timeout: int = 180) -> ET.Element:
    """Run pnputil with ``/format xml /output-file`` and parse the result."""
    fd, path = tempfile.mkstemp(suffix=".xml", prefix="dcc_pnp_")
    os.close(fd)
    try:
        proc = run([*args, "/format", "xml", "/output-file", path], timeout=timeout)
        try:
            with open(path, "r", encoding="utf-8-sig", errors="replace") as fh:
                text = fh.read()
        except OSError:
            text = ""
        if not text.strip():
            # Older builds ignore /output-file for some verbs; fall back to stdout.
            text = proc.stdout
        if not text.strip():
            raise PnpUtilError(
                f"pnputil produced no output for {' '.join(args)}",
                proc.returncode,
                (proc.stderr or proc.stdout or "").strip(),
            )
        try:
            return ET.fromstring(text)
        except ET.ParseError as exc:
            raise PnpUtilError(
                f"could not parse pnputil XML: {exc}", proc.returncode, text[:2000]
            ) from exc
    finally:
        try:
            os.remove(path)
        except OSError:
            pass


# pnputil returns SetupAPI codes, which surface as large negative numbers.
# Only entries confirmed against this machine (or plain Win32) are named; the
# rest fall back to the hex value plus whatever pnputil printed.
EXIT_CODES = {
    0: "succeeded",
    3010: "succeeded, reboot required",
    2: "file not found",
    5: "access denied -- needs administrator",
    87: "invalid parameter",
    1223: "the UAC prompt was declined",
    -536870340: "not an installed OEM INF (already deleted?)",   # 0xE000023C
    -536870339: "still in use by the system",                    # 0xE000023D
}


def describe_exit_code(code: int) -> str:
    """A readable reason for a pnputil exit code."""
    if code in EXIT_CODES:
        return EXIT_CODES[code]
    if code < 0:
        unsigned = code & 0xFFFFFFFF
        if 0xE0000000 <= unsigned <= 0xE0000FFF:
            return "SetupAPI error 0x%08X" % unsigned
        return "error 0x%08X" % unsigned
    return "exit %d" % code


_BANNER = re.compile(r"^\s*Microsoft PnP Utility\s*\r?\n\s*\r?\n?", re.IGNORECASE)


def clean_output(text: str) -> str:
    """Drop pnputil's banner so the actual message is the first line."""
    if not text:
        return ""
    return _BANNER.sub("", text, count=1).strip()


def _text(node: ET.Element | None) -> str:
    if node is None or node.text is None:
        return ""
    return node.text.strip()


def _list(parent: ET.Element, container: str, child: str) -> list[str]:
    holder = parent.find(container)
    if holder is None:
        return []
    return [_text(n) for n in holder.findall(child) if _text(n)]


# --------------------------------------------------------------------------
# enumeration
# --------------------------------------------------------------------------
def enum_drivers(include_files: bool = False) -> list[dict]:
    """Third-party driver packages in the driver store (the ``oem*.inf`` cache)."""
    args = ["/enum-drivers", "/devices", "/ids"]
    if include_files:
        args.append("/files")
    root = run_xml(args, timeout=300)
    out: list[dict] = []
    for node in root.findall("Driver"):
        devices = []
        holder = node.find("Devices")
        if holder is not None:
            for dev in holder.findall("Device"):
                devices.append(
                    {
                        "instance_id": dev.get("InstanceId", ""),
                        "description": _text(dev.find("DeviceDescription")),
                        "status": _text(dev.find("Status")),
                    }
                )
        files = []
        fholder = node.find("Files")
        if fholder is not None:
            for f in fholder:
                val = _text(f) or f.get("Path", "")
                if val:
                    files.append(val)
        out.append(
            {
                "driver_name": node.get("DriverName", ""),
                "original_name": _text(node.find("OriginalName")),
                "provider_name": _text(node.find("ProviderName")),
                "class_name": _text(node.find("ClassName")),
                "class_guid": _text(node.find("ClassGuid")),
                "driver_version": _text(node.find("DriverVersion")),
                "signer_name": _text(node.find("SignerName")),
                "attributes": _list(node, "CatalogAttributes", "Attribute"),
                "whcp_version": _text(node.find("WhcpVersion")),
                "driver_package_id": _text(node.find("DriverPackageId")),
                "family_id": _text(node.find("FamilyId")),
                "devices": devices,
                "files": files,
            }
        )
    return out


def enum_devices() -> list[dict]:
    """Every device pnputil knows about, connected and disconnected alike."""
    root = run_xml(["/enum-devices"], timeout=300)
    out: list[dict] = []
    for node in root.findall("Device"):
        out.append(
            {
                "instance_id": node.get("InstanceId", ""),
                "description": _text(node.find("DeviceDescription")),
                "class_name": _text(node.find("ClassName")),
                "class_guid": _text(node.find("ClassGuid")),
                "manufacturer": _text(node.find("ManufacturerName")),
                "status": _text(node.find("Status")),
                "driver_name": _text(node.find("DriverName")),
                "extension_drivers": _list(node, "ExtensionDriverNames", "DriverName"),
            }
        )
    return out


def enum_classes() -> list[dict]:
    try:
        root = run_xml(["/enum-classes"], timeout=120)
    except PnpUtilError:
        return []
    out = []
    for node in root.findall("Class"):
        out.append(
            {
                "class_name": node.get("ClassName") or _text(node.find("ClassName")),
                "class_guid": node.get("ClassGuid") or _text(node.find("ClassGuid")),
                "description": _text(node.find("ClassDescription")),
            }
        )
    return out


# --------------------------------------------------------------------------
# actions (most require elevation)
# --------------------------------------------------------------------------
def _action(args: list[str], timeout: int = 300) -> dict:
    proc = run(args, timeout=timeout)
    output = (proc.stdout or "").strip()
    err = (proc.stderr or "").strip()
    return {
        "command": "pnputil " + " ".join(args),
        "returncode": proc.returncode,
        "ok": proc.returncode in (0, 3010),  # 3010 == success, reboot required
        "reboot_required": proc.returncode == 3010,
        "reason": describe_exit_code(proc.returncode),
        "output": clean_output(output or err),
    }


def delete_driver(oem_inf: str, uninstall: bool = False, force: bool = False,
                  reboot: bool = False) -> dict:
    args = ["/delete-driver", oem_inf]
    if uninstall:
        args.append("/uninstall")
    if force:
        args.append("/force")
    if reboot:
        args.append("/reboot")
    return _action(args)


def add_driver(inf_path: str, subdirs: bool = False, install: bool = False) -> dict:
    args = ["/add-driver", inf_path]
    if subdirs:
        args.append("/subdirs")
    if install:
        args.append("/install")
    return _action(args)


def export_driver(oem_inf: str, target_dir: str) -> dict:
    return _action(["/export-driver", oem_inf, target_dir])


def disable_device(instance_id: str) -> dict:
    return _action(["/disable-device", instance_id])


def enable_device(instance_id: str) -> dict:
    return _action(["/enable-device", instance_id])


def restart_device(instance_id: str) -> dict:
    return _action(["/restart-device", instance_id])


def remove_device(instance_id: str, subtree: bool = False) -> dict:
    args = ["/remove-device", instance_id]
    if subtree:
        args.append("/subtree")
    return _action(args)


def scan_devices() -> dict:
    return _action(["/scan-devices"])
