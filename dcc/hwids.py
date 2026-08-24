"""Offline USB / PCI vendor+product ID database.

Windows only tells you what the INF says.  When an INF is generic
(``USB Composite Device``) the vendor and product still live in the VID/PID,
so this module resolves those against the public ``usb.ids`` / ``pci.ids``
tables.

The tables are *not* bundled -- they are downloaded on demand (CLI
``dcc update-hwids``, or the "Update HW ID database" button in the UI) and
cached under ``%LOCALAPPDATA%\\DeviceControlConsole``.  Until then a small
built-in seed of common vendors is used, so the tool is never useless offline.
"""

from __future__ import annotations

import os
import re
import threading
import urllib.request

CACHE_DIR = os.path.join(
    os.environ.get("LOCALAPPDATA", os.path.expanduser("~")), "DeviceControlConsole"
)

SOURCES = {
    "usb.ids": "http://www.linux-usb.org/usb.ids",
    "pci.ids": "https://pci-ids.ucw.cz/v2.2/pci.ids",
}

# A deliberately small offline fallback: vendors common on consumer PCs.
SEED_USB_VENDORS = {
    "03F0": "HP", "0403": "FTDI", "0409": "NEC", "041E": "Creative Technology",
    "0424": "Microchip (SMSC)", "0430": "Sun", "0451": "Texas Instruments",
    "045E": "Microsoft", "046D": "Logitech", "0471": "Philips",
    "04A9": "Canon", "04B3": "IBM", "04B4": "Cypress", "04B8": "Seiko Epson",
    "04CA": "Lite-On", "04D8": "Microchip", "04E8": "Samsung", "04F2": "Chicony",
    "04F3": "Elan Microelectronics", "0502": "Acer", "050D": "Belkin",
    "0525": "Netchip", "054C": "Sony", "056A": "Wacom", "0574": "City University",
    "057E": "Nintendo", "058F": "Alcor Micro", "05AC": "Apple", "05C6": "Qualcomm",
    "05E3": "Genesys Logic", "0644": "TEAC", "0665": "Cypress",
    "067B": "Prolific", "06CB": "Synaptics", "0718": "Imation",
    "0765": "X-Rite", "07CA": "AVerMedia", "0781": "SanDisk", "07B4": "Olympus",
    "0836": "Sierra Wireless", "0846": "NetGear", "08BB": "Texas Instruments",
    "08E6": "Gemalto", "090C": "Silicon Motion", "0930": "Toshiba",
    "093A": "Pixart Imaging", "0951": "Kingston", "09DA": "A4Tech",
    "0A05": "Unknown Manufacturer", "0A12": "Cambridge Silicon Radio",
    "0A5C": "Broadcom", "0B05": "ASUSTek", "0B0E": "GN Netcom (Jabra)",
    "0B95": "ASIX", "0BB4": "HTC", "0BC2": "Seagate", "0BDA": "Realtek",
    "0C45": "Microdia", "0C76": "JMTek", "0CF3": "Qualcomm Atheros",
    "0D8C": "C-Media", "0E8D": "MediaTek", "0EA0": "Ours Technology",
    "0F42": "Nuvoton", "1004": "LG Electronics", "1038": "SteelSeries ApS",
    "1050": "Yubico", "1058": "Western Digital", "10C4": "Silicon Labs",
    "1130": "Tenx Technology", "1199": "Sierra Wireless", "12D1": "Huawei",
    "1301": "Kingston", "13D3": "IMC Networks", "1462": "MSI",
    "1532": "Razer", "1546": "u-blox", "15A9": "Gemtek", "15D9": "Trust",
    "16C0": "Van Ooijen Technische Informatica", "1725": "Vitesse",
    "174C": "ASMedia", "17EF": "Lenovo", "1852": "GYROCOM",
    "18D1": "Google", "1915": "Nordic Semiconductor", "1A2C": "China Resource",
    "1A40": "Terminus Technology", "1A86": "QinHeng Electronics",
    "1B1C": "Corsair", "1B3F": "Generalplus", "1BCF": "Sunplus",
    "1D50": "OpenMoko", "1D6B": "Linux Foundation", "1E7D": "ROCCAT",
    "2109": "VIA Labs", "20A0": "Clay Logic", "2188": "Realtek",
    "22B8": "Motorola", "2341": "Arduino", "2357": "TP-Link",
    "2717": "Xiaomi", "27C6": "Goodix", "28DE": "Valve",
    "2C7C": "Quectel", "2E8A": "Raspberry Pi", "413C": "Dell",
    "5986": "Acer/Bison Electronics", "8087": "Intel", "8086": "Intel",
}

SEED_PCI_VENDORS = {
    "1002": "Advanced Micro Devices, Inc. [AMD/ATI]",
    "1013": "Cirrus Logic", "1022": "Advanced Micro Devices, Inc. [AMD]",
    "1028": "Dell", "103C": "Hewlett-Packard", "1043": "ASUSTeK",
    "104C": "Texas Instruments", "1106": "VIA Technologies",
    "10DE": "NVIDIA Corporation", "10EC": "Realtek Semiconductor",
    "1102": "Creative Labs", "1179": "Toshiba", "11AB": "Marvell",
    "126F": "Silicon Motion", "144D": "Samsung Electronics",
    "14E4": "Broadcom", "15AD": "VMware", "15B7": "Sandisk",
    "1682": "XFX", "168C": "Qualcomm Atheros", "1969": "Qualcomm Atheros",
    "197B": "JMicron", "1AF4": "Red Hat (Virtio)", "1B21": "ASMedia",
    "1B4B": "Marvell", "1C5C": "SK hynix", "1CC1": "ADATA",
    "1D6A": "Aquantia", "1DEE": "Biwin", "1E0F": "KIOXIA",
    "2646": "Kingston Technology", "8086": "Intel Corporation",
    "8087": "Intel Corporation", "9005": "Adaptec",
}

_LOCK = threading.Lock()
_DB: dict[str, dict] = {}


def cache_path(name: str) -> str:
    return os.path.join(CACHE_DIR, name)


def _parse_ids(text: str) -> dict:
    """Parse the shared usb.ids / pci.ids format into {vid: {'name':.., 'products':{}}}."""
    vendors: dict[str, dict] = {}
    current: dict | None = None
    for line in text.splitlines():
        if not line or line.startswith("#"):
            continue
        if line.startswith("\t\t"):
            continue  # interface / subsystem level -- not needed here
        if line.startswith("\t"):
            if current is None:
                continue
            m = re.match(r"\t([0-9a-fA-F]{4})\s+(.*)", line)
            if m:
                current["products"][m.group(1).upper()] = m.group(2).strip()
            continue
        m = re.match(r"([0-9a-fA-F]{4})\s+(.*)", line)
        if m:
            current = {"name": m.group(2).strip(), "products": {}}
            vendors[m.group(1).upper()] = current
        else:
            current = None  # a section like "C 00  (Un)classified device"
    return vendors


def _load(name: str) -> dict:
    with _LOCK:
        if name in _DB:
            return _DB[name]
        path = cache_path(name)
        vendors: dict[str, dict] = {}
        if os.path.isfile(path):
            try:
                with open(path, "r", encoding="utf-8", errors="replace") as fh:
                    vendors = _parse_ids(fh.read())
            except OSError:
                vendors = {}
        if not vendors:
            seed = SEED_USB_VENDORS if name == "usb.ids" else SEED_PCI_VENDORS
            vendors = {k: {"name": v, "products": {}} for k, v in seed.items()}
        _DB[name] = vendors
        return vendors


def status() -> dict:
    out = {}
    for name in SOURCES:
        path = cache_path(name)
        exists = os.path.isfile(path)
        out[name] = {
            "path": path,
            "downloaded": exists,
            "size": os.path.getsize(path) if exists else 0,
            "mtime": (
                __import__("datetime")
                .datetime.fromtimestamp(os.path.getmtime(path))
                .isoformat(timespec="seconds")
                if exists
                else None
            ),
            "vendors": len(_load(name)),
        }
    return out


def update(names: list[str] | None = None, timeout: int = 60) -> dict:
    """Download the ID tables.  Explicit action -- never runs on its own."""
    os.makedirs(CACHE_DIR, exist_ok=True)
    results = {}
    for name in names or list(SOURCES):
        url = SOURCES.get(name)
        if not url:
            results[name] = {"ok": False, "error": "unknown table"}
            continue
        try:
            req = urllib.request.Request(
                url, headers={"User-Agent": "DeviceControlConsole/1.0"}
            )
            with urllib.request.urlopen(req, timeout=timeout) as resp:
                data = resp.read()
            text = data.decode("utf-8", "replace")
            if len(text) < 10000 or not _parse_ids(text):
                raise ValueError("downloaded file does not look like an ID table")
            with open(cache_path(name), "w", encoding="utf-8", newline="\n") as fh:
                fh.write(text)
            with _LOCK:
                _DB.pop(name, None)
            results[name] = {"ok": True, "bytes": len(data), "vendors": len(_load(name))}
        except Exception as exc:  # network / parse / disk -- all reported the same
            results[name] = {"ok": False, "error": f"{type(exc).__name__}: {exc}"}
    return results


def lookup_usb(vid: str, pid: str | None = None) -> tuple[str | None, str | None]:
    return _lookup("usb.ids", vid, pid)


def lookup_pci(vid: str, pid: str | None = None) -> tuple[str | None, str | None]:
    return _lookup("pci.ids", vid, pid)


def _lookup(table: str, vid: str, pid: str | None) -> tuple[str | None, str | None]:
    if not vid:
        return None, None
    vendors = _load(table)
    entry = vendors.get(vid.upper())
    if not entry:
        return None, None
    product = entry["products"].get(pid.upper()) if pid else None
    return entry["name"] or None, product
