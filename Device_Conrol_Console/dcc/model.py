"""Builds the snapshot the console works on: devices, driver store, relations.

Two sources are merged:

* :mod:`dcc.cfgmgr` -- the Configuration Manager, which knows every device node
  (present or phantom), its real properties and the device tree;
* :mod:`dcc.pnputil` -- authoritative for the *driver store* (``oem*.inf``),
  extension drivers, and the driver->device mapping.

Everything downstream (HTTP API, CLI) consumes :class:`Snapshot`.
"""

from __future__ import annotations

import datetime
import re
import threading

from . import cfgmgr, devprops as dp, pnputil
from .resolve import Resolver, parse_ids

_VERSION_RE = re.compile(r"^\s*(\d{1,2}/\d{1,2}/\d{4})\s+(\S+)\s*$")


def _split_driver_version(text: str) -> tuple[str | None, str | None, tuple]:
    """``05/19/2026 15.11.30.14`` -> (iso date, version string, sortable tuple)."""
    if not text:
        return None, None, ()
    m = _VERSION_RE.match(text)
    if not m:
        return None, text.strip() or None, ()
    raw_date, version = m.group(1), m.group(2)
    iso = None
    for fmt in ("%m/%d/%Y", "%d/%m/%Y"):
        try:
            iso = datetime.datetime.strptime(raw_date, fmt).date().isoformat()
            break
        except ValueError:
            continue
    parts = tuple(int(p) if p.isdigit() else 0 for p in version.split("."))
    return iso, version, parts


def _is_oem_inf(name: str | None) -> bool:
    return bool(name) and bool(re.fullmatch(r"oem\d+\.inf", name.strip(), re.IGNORECASE))


class Snapshot:
    """An immutable view of the machine's devices and driver store."""

    def __init__(self, devices: list[dict], drivers: list[dict], meta: dict):
        self.devices = devices
        self.drivers = drivers
        self.meta = meta
        self.device_index = {d["instance_id"]: d for d in devices}
        self.driver_index = {d["driver_name"].lower(): d for d in drivers}

    def as_dict(self) -> dict:
        return {"meta": self.meta, "devices": self.devices, "drivers": self.drivers}


def _scan_devices() -> dict[str, dict]:
    """Every device node the Configuration Manager knows about."""
    devices: dict[str, dict] = {}
    for iid in cfgmgr.list_instance_ids(present_only=False):
        node = cfgmgr.locate(iid)
        if node is None:
            continue
        props = cfgmgr.get_properties(node.devinst, dp.SCAN_KEYS)
        children = props.get("Children") or cfgmgr.children_of(node.devinst)
        parent = props.get("Parent") or cfgmgr.parent_of(node.devinst)
        hardware_ids = props.get("HardwareIds") or []
        status = dp.decode_status(
            props.get("DevNodeStatus"), props.get("Problem"), node.present
        )
        devices[iid] = {
            "instance_id": iid,
            "description": props.get("DeviceDesc", ""),
            "friendly_name": props.get("FriendlyName", ""),
            "bus_reported": props.get("BusReportedDeviceDesc", ""),
            "class_name": props.get("Class", ""),
            "class_guid": (props.get("ClassGuid") or "").lower(),
            "manufacturer": props.get("Manufacturer", ""),
            "service": props.get("Service", ""),
            "hardware_ids": hardware_ids,
            "compatible_ids": [],
            "driver_inf": props.get("DriverInfPath", ""),
            "driver_version": props.get("DriverVersion", ""),
            "driver_provider": props.get("DriverProvider", ""),
            "driver_date": props.get("DriverDate", ""),
            "parent": parent or "",
            "children": children,
            "container_id": (props.get("ContainerId") or "").lower(),
            "location": props.get("LocationInfo", ""),
            "install_date": props.get("InstallDate", ""),
            "last_arrival": props.get("LastArrivalDate", ""),
            "last_removal": props.get("LastRemovalDate", ""),
            "present": node.present,
            "status": status["status"],
            "problem_code": status["problem_code"],
            "problem_text": status["problem_text"],
            "status_flags": status["flags"],
            "ids": parse_ids(iid, hardware_ids),
            "extension_drivers": [],
            "driver_name": "",
            "source": "cfgmgr",
        }
    return devices


def _merge_pnputil_devices(devices: dict[str, dict]) -> tuple[int, str]:
    """Overlay pnputil's device view: driver name + extension drivers."""
    try:
        rows = pnputil.enum_devices()
    except pnputil.PnpUtilError as exc:
        return 0, str(exc)
    added = 0
    for row in rows:
        iid = row["instance_id"]
        dev = devices.get(iid)
        if dev is None:
            # pnputil saw something CM did not (rare: certain phantom nodes).
            dev = {
                "instance_id": iid,
                "description": row["description"],
                "friendly_name": "",
                "bus_reported": "",
                "class_name": row["class_name"],
                "class_guid": (row["class_guid"] or "").lower(),
                "manufacturer": row["manufacturer"],
                "service": "",
                "hardware_ids": [],
                "compatible_ids": [],
                "driver_inf": "",
                "driver_version": "",
                "driver_provider": "",
                "driver_date": "",
                "parent": "",
                "children": [],
                "container_id": "",
                "location": "",
                "install_date": "",
                "last_arrival": "",
                "last_removal": "",
                "present": row["status"] != "Disconnected",
                "status": row["status"],
                "problem_code": 0,
                "problem_text": "",
                "status_flags": [],
                "ids": parse_ids(iid, []),
                "extension_drivers": [],
                "driver_name": "",
                "source": "pnputil",
            }
            devices[iid] = dev
            added += 1
        dev["driver_name"] = row["driver_name"]
        dev["extension_drivers"] = row["extension_drivers"]
        if not dev.get("description"):
            dev["description"] = row["description"]
        if not dev.get("class_name"):
            dev["class_name"] = row["class_name"]
        if not dev.get("manufacturer"):
            dev["manufacturer"] = row["manufacturer"]
        # pnputil's Status string is the one users recognise from the CLI
        dev["pnputil_status"] = row["status"]
    return added, ""


def _build_drivers(devices: dict[str, dict], include_files: bool) -> tuple[list[dict], str]:
    try:
        rows = pnputil.enum_drivers(include_files=include_files)
    except pnputil.PnpUtilError as exc:
        return [], str(exc)

    # Which devices point at each oem*.inf, from both directions.
    used_by: dict[str, set[str]] = {}
    for iid, dev in devices.items():
        for name in [dev.get("driver_name"), dev.get("driver_inf")]:
            if _is_oem_inf(name):
                used_by.setdefault(name.lower(), set()).add(iid)
        for ext in dev.get("extension_drivers") or []:
            if _is_oem_inf(ext):
                used_by.setdefault(ext.lower(), set()).add(iid)

    drivers: list[dict] = []
    for row in rows:
        key = row["driver_name"].lower()
        iso_date, version, version_tuple = _split_driver_version(row["driver_version"])
        linked = set(used_by.get(key, set()))
        for d in row["devices"]:
            linked.add(d["instance_id"])
        present = sum(
            1 for i in linked if devices.get(i, {}).get("present")
        )
        drivers.append(
            {
                **row,
                "version_date": iso_date,
                "version_number": version,
                "_version_tuple": version_tuple,
                "device_ids": sorted(linked),
                "device_count": len(linked),
                "present_device_count": present,
                "in_use": bool(linked),
                "is_extension": (row["class_name"] or "").lower() == "extension",
                "orphaned": not linked,
                "superseded_by": "",
                "family_members": [],
            }
        )

    # Older copies of the same package still sitting in the store.
    families: dict[str, list[dict]] = {}
    for drv in drivers:
        key = (drv["family_id"] or drv["original_name"] or drv["driver_name"]).lower()
        families.setdefault(key, []).append(drv)
    for key, members in families.items():
        if len(members) < 2:
            continue
        members.sort(key=lambda d: (d["_version_tuple"], d["version_date"] or ""), reverse=True)
        newest = members[0]
        for drv in members:
            drv["family_members"] = [m["driver_name"] for m in members]
        for older in members[1:]:
            older["superseded_by"] = newest["driver_name"]

    for drv in drivers:
        drv.pop("_version_tuple", None)
    return drivers, ""


def build(include_files: bool = False) -> Snapshot:
    warnings: list[str] = []
    devices = _scan_devices()
    added, warn = _merge_pnputil_devices(devices)
    if warn:
        warnings.append(f"pnputil /enum-devices: {warn}")
    drivers, warn = _build_drivers(devices, include_files)
    if warn:
        warnings.append(f"pnputil /enum-drivers: {warn}")

    resolver = Resolver(devices)
    driver_by_name = {d["driver_name"].lower(): d for d in drivers}
    for iid, dev in devices.items():
        dev.update(resolver.enrich(iid))
        dev["children"] = resolver.children_of(iid)
        dev["related"] = resolver.relatives(iid)[:32]
        dev["class_display"] = cfgmgr.class_display_name(dev.get("class_guid") or "") or ""
        name = dev.get("driver_name") or dev.get("driver_inf") or ""
        dev["driver_is_oem"] = _is_oem_inf(name)
        dev["driver_is_inbox"] = bool(name) and not dev["driver_is_oem"]
        pkg = driver_by_name.get(name.lower())
        dev["driver_package"] = (
            {
                "original_name": pkg["original_name"],
                "provider_name": pkg["provider_name"],
                "driver_version": pkg["driver_version"],
                "signer_name": pkg["signer_name"],
            }
            if pkg
            else None
        )
        dev["child_count"] = len(dev.get("children") or [])
        dev["search_blob"] = " ".join(
            str(x)
            for x in (
                iid,
                dev.get("resolved_name"),
                dev.get("description"),
                dev.get("friendly_name"),
                dev.get("bus_reported"),
                dev.get("class_name"),
                dev.get("class_display"),
                dev.get("manufacturer"),
                dev.get("vendor"),
                dev.get("device_type"),
                dev.get("service"),
                dev.get("driver_name"),
                dev.get("driver_inf"),
                " ".join(dev.get("extension_drivers") or []),
                " ".join(dev.get("hardware_ids") or []),
                dev.get("status"),
                dev.get("problem_text"),
            )
            if x
        ).lower()

    for drv in drivers:
        names = [devices.get(i, {}).get("resolved_name", "") for i in drv["device_ids"]]
        drv["device_names"] = [n for n in names if n]
        drv["search_blob"] = " ".join(
            str(x)
            for x in (
                drv["driver_name"],
                drv["original_name"],
                drv["provider_name"],
                drv["class_name"],
                drv["driver_version"],
                drv["signer_name"],
                drv["driver_package_id"],
                drv["family_id"],
                " ".join(drv["attributes"]),
                " ".join(drv["device_names"]),
            )
            if x
        ).lower()

    device_list = sorted(devices.values(), key=lambda d: d["instance_id"])
    drivers.sort(key=lambda d: _oem_sort_key(d["driver_name"]))

    meta = {
        "generated_at": datetime.datetime.now().astimezone().isoformat(timespec="seconds"),
        "device_count": len(device_list),
        "present_count": sum(1 for d in device_list if d["present"]),
        "ghost_count": sum(1 for d in device_list if not d["present"]),
        "problem_count": sum(1 for d in device_list if d["problem_code"]),
        "driver_count": len(drivers),
        "orphan_driver_count": sum(1 for d in drivers if d["orphaned"]),
        "superseded_driver_count": sum(1 for d in drivers if d["superseded_by"]),
        "pnputil_devices_only": added,
        "warnings": warnings,
    }
    return Snapshot(device_list, drivers, meta)


def _oem_sort_key(name: str) -> tuple:
    m = re.fullmatch(r"oem(\d+)\.inf", (name or "").strip(), re.IGNORECASE)
    return (0, int(m.group(1))) if m else (1, 0, name.lower())


def device_detail(instance_id: str) -> dict:
    """Full property dump for a single device (used by the detail pane)."""
    node = cfgmgr.locate(instance_id)
    if node is None:
        return {}
    props = cfgmgr.get_properties(node.devinst, dp.DETAIL_KEYS)
    props["_present"] = node.present
    props["_children_walked"] = cfgmgr.children_of(node.devinst)
    props["_parent_walked"] = cfgmgr.parent_of(node.devinst) or ""
    return props


class SnapshotCache:
    """Keeps one snapshot in memory; refresh is explicit and thread-safe."""

    def __init__(self):
        self._lock = threading.Lock()
        self._snapshot: Snapshot | None = None

    def get(self, refresh: bool = False, include_files: bool = False) -> Snapshot:
        with self._lock:
            if refresh or self._snapshot is None:
                self._snapshot = build(include_files=include_files)
            return self._snapshot

    def invalidate(self) -> None:
        with self._lock:
            self._snapshot = None
