"""Turn an instance ID into the thing a human actually owns.

``USB\\VID_1038&PID_1838\\6&2ae87d4e&0&1`` is reported by Windows as
"USB Composite Device" made by "(Standard USB Host Controller)".  Neither is
useful.  The real name -- *SteelSeries Aerox 3 Wireless* -- is available
locally in three places, and this module tries them in order of trust:

1. the device's own friendly name;
2. the string the bus reported (``DEVPKEY_Device_BusReportedDeviceDesc``, i.e.
   the USB ``iProduct`` descriptor);
3. a vendor-specific child of the same physical device -- a composite mouse
   exposes ``USB\\VID_1038&PID_1838&MI_00`` whose INF *does* name the product;
4. the public USB/PCI ID tables (see :mod:`dcc.hwids`).

Device *type* ("mouse") is inferred from HID usage pages, the setup class of
the node, and the setup classes of its descendants.
"""

from __future__ import annotations

import re

from . import devprops as dp
from . import hwids

# Descriptions that name a Windows-supplied enumerator rather than a product.
GENERIC_DESC = (
    "usb composite device",
    "usb input device",
    "usb root hub",
    "generic usb hub",
    "usb hub",
    "unknown device",
    "usb mass storage device",
    "usb attached scsi (uas) mass storage device",
    "composite bus enumerator",
    "hid-compliant mouse",
    "hid-compliant device",
    "hid-compliant consumer control device",
    "hid-compliant vendor-defined device",
    "hid-compliant system controller",
    "hid keyboard device",
    "hid-compliant touch pad",
    "usb printing support",
    "generic pnp monitor",
    "pci device",
    "pci standard host cb bridge",
    "base system device",
    "usb serial converter",
    "microsoft usb generic device",
    "usb device",
    "bluetooth device",
    "generic bluetooth adapter",
    "standard nvm express controller",
    "standard sata ahci controller",
    "sd host controller",
    "unknown usb device",
    "audio endpoint",
)

GENERIC_MFG_PREFIX = ("(standard", "(generic", "(default", "(retired")
GENERIC_MFG_EXACT = ("microsoft", "generic", "compatible", "system", "unknown")

_RE_USB = re.compile(r"VID_([0-9A-Fa-f]{4}).*?PID_([0-9A-Fa-f]{4})")
_RE_PCI = re.compile(r"VEN_([0-9A-Fa-f]{4}).*?DEV_([0-9A-Fa-f]{4})")
_RE_SUBSYS = re.compile(r"SUBSYS_([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})")
_RE_HID_USAGE = re.compile(r"UP:([0-9A-Fa-f]{4})_U:([0-9A-Fa-f]{4})")
_RE_BTH = re.compile(r"BTHENUM\\.*?_([0-9A-Fa-f]{4})", re.IGNORECASE)


def is_generic_desc(desc: str | None) -> bool:
    if not desc:
        return True
    low = desc.strip().lower()
    return any(low == g or low.startswith(g) for g in GENERIC_DESC)


def is_generic_mfg(mfg: str | None) -> bool:
    if not mfg:
        return True
    low = mfg.strip().lower()
    return low in GENERIC_MFG_EXACT or low.startswith(GENERIC_MFG_PREFIX)


def parse_ids(instance_id: str, hardware_ids: list[str] | None = None) -> dict:
    """Extract bus, vendor and product IDs from an instance/hardware ID."""
    text = instance_id or ""
    pool = [text] + list(hardware_ids or [])
    bus = text.split("\\", 1)[0].upper() if "\\" in text else text.upper()
    out: dict = {"bus": bus, "vid": None, "pid": None, "subsys_vendor": None,
                 "subsys_device": None, "rev": None}
    for candidate in pool:
        m = _RE_USB.search(candidate)
        if m:
            out["vid"], out["pid"] = m.group(1).upper(), m.group(2).upper()
            out["id_kind"] = "usb"
            break
        m = _RE_PCI.search(candidate)
        if m:
            out["vid"], out["pid"] = m.group(1).upper(), m.group(2).upper()
            out["id_kind"] = "pci"
            break
    for candidate in pool:
        m = _RE_SUBSYS.search(candidate)
        if m:
            out["subsys_device"] = m.group(1).upper()
            out["subsys_vendor"] = m.group(2).upper()
            break
    out.setdefault("id_kind", None)
    return out


def hid_usage_type(hardware_ids: list[str] | None,
                   compatible_ids: list[str] | None = None) -> str | None:
    for hid in list(hardware_ids or []) + list(compatible_ids or []):
        m = _RE_HID_USAGE.search(hid)
        if m:
            hit = dp.HID_USAGE_TO_TYPE.get((m.group(1).upper(), m.group(2).upper()))
            if hit:
                return hit
        upper = hid.upper()
        if upper.endswith("HID_DEVICE_SYSTEM_MOUSE"):
            return "Mouse"
        if upper.endswith("HID_DEVICE_SYSTEM_KEYBOARD"):
            return "Keyboard"
        if upper.endswith("HID_DEVICE_SYSTEM_GAME"):
            return "Gamepad"
    return None


def class_type(class_name: str | None) -> str | None:
    if not class_name:
        return None
    return dp.CLASS_TO_TYPE.get(class_name.strip().lower())


def vendor_from_ids(ids: dict) -> tuple[str | None, str | None]:
    """(vendor, product) from the public ID tables, for USB and PCI alike."""
    kind = ids.get("id_kind")
    if kind == "usb":
        return hwids.lookup_usb(ids["vid"], ids["pid"])
    if kind == "pci":
        vendor, product = hwids.lookup_pci(ids["vid"], ids["pid"])
        if not vendor and ids.get("subsys_vendor"):
            vendor, _ = hwids.lookup_pci(ids["subsys_vendor"], None)
        return vendor, product
    return None, None


class Resolver:
    """Resolves names/types across a whole device snapshot.

    Needs the full index because the good name for a composite device lives on
    one of its children, and the good name for a disconnected device may live
    on a sibling instance of the same hardware.
    """

    #: Types that describe a container or a bus rather than the thing itself.
    CONTAINER_CLASSES = {
        "usb", "usbdevice", "system", "computer", "softwaredevice", "extension",
        "volume", "hdc", "scsiadapter", "unknown", "usbfnproviders",
    }
    #: Types that are technically correct but say little; a sibling that says
    #: "Mouse" always wins over one that says "HID".
    WEAK_TYPES = {
        "HID", "Consumer control", "Vendor-specific", "System control",
        "USB device", "USB controller/hub", "Unknown", "Software device",
        "Software component", "Driver extension", "System device", "HID device",
    }

    def __init__(self, devices: dict[str, dict]):
        self.devices = devices
        self._by_vidpid: dict[tuple[str, str], list[str]] = {}
        self._by_container: dict[str, list[str]] = {}
        self._children: dict[str, list[str]] = {}
        for iid, dev in devices.items():
            ids = dev.get("ids") or {}
            vid, pid = ids.get("vid"), ids.get("pid")
            if vid and pid:
                self._by_vidpid.setdefault((vid, pid), []).append(iid)
            container = dev.get("container_id")
            if container and not container.startswith("{00000000"):
                self._by_container.setdefault(container, []).append(iid)
            kids = list(dev.get("children") or [])
            if kids:
                self._children.setdefault(iid, []).extend(kids)
        # Reverse the parent links too: DEVPKEY_Device_Children is absent on
        # plenty of nodes, but the child always remembers its parent.
        for iid, dev in devices.items():
            parent = dev.get("parent")
            if parent and parent in devices:
                bucket = self._children.setdefault(parent, [])
                if iid not in bucket:
                    bucket.append(iid)

    def children_of(self, iid: str) -> list[str]:
        """Children from DEVPKEY plus children recovered from parent links."""
        return list(self._children.get(iid, ()))

    def same_physical_device(self, a: str, b: str) -> bool:
        """True when two nodes are functions of one piece of hardware.

        Without this a root or hub node would happily borrow the name of some
        unrelated device hanging off it -- Windows' own container ID (and, as a
        fallback, an identical VID/PID) is the honest test.
        """
        da, db = self.devices.get(a, {}), self.devices.get(b, {})
        ca, cb = da.get("container_id"), db.get("container_id")
        if ca and ca == cb and not ca.startswith(("{00000000", "{ffffffff")):
            return True
        ia, ib = da.get("ids") or {}, db.get("ids") or {}
        if ia.get("vid") and ia.get("vid") == ib.get("vid") and ia.get("pid") == ib.get("pid"):
            return True
        return False

    def kin(self, iid: str, depth: int = 4) -> list[str]:
        """Descendants and relatives that are part of the same physical device."""
        out = []
        for other in self.descendants(iid, depth) + self.relatives(iid):
            if other not in out and self.same_physical_device(iid, other):
                out.append(other)
        return out

    def relatives(self, iid: str) -> list[str]:
        """Other instances of the same hardware, or parts of the same physical unit."""
        dev = self.devices.get(iid, {})
        out: list[str] = []
        seen = {iid}
        ids = dev.get("ids") or {}
        vid, pid = ids.get("vid"), ids.get("pid")
        if vid and pid:
            for other in self._by_vidpid.get((vid, pid), []):
                if other not in seen:
                    seen.add(other)
                    out.append(other)
        container = dev.get("container_id")
        if container and not container.startswith("{00000000"):
            for other in self._by_container.get(container, []):
                if other not in seen:
                    seen.add(other)
                    out.append(other)
        return out

    # -- helpers ----------------------------------------------------------
    def descendants(self, iid: str, depth: int = 4) -> list[str]:
        out: list[str] = []
        frontier = [iid]
        seen = {iid}
        for _ in range(depth):
            nxt = []
            for cur in frontier:
                for child in self._children.get(cur, ()):
                    if child in seen or child not in self.devices:
                        continue
                    seen.add(child)
                    out.append(child)
                    nxt.append(child)
            if not nxt:
                break
            frontier = nxt
        return out

    def _vendor_named(self, iid: str) -> tuple[str, str] | None:
        """Return (name, source) if this node carries a real product name."""
        dev = self.devices.get(iid)
        if not dev:
            return None
        friendly = dev.get("friendly_name")
        if friendly and not is_generic_desc(friendly):
            return friendly, "FriendlyName"
        bus_desc = dev.get("bus_reported")
        if bus_desc and not is_generic_desc(bus_desc):
            return bus_desc, "BusReportedDeviceDesc"
        desc = dev.get("description")
        if desc and not is_generic_desc(desc) and not is_generic_mfg(dev.get("manufacturer")):
            return desc, "DeviceDesc"
        return None

    # -- public -----------------------------------------------------------
    def resolve_name(self, iid: str) -> dict:
        dev = self.devices.get(iid, {})
        direct = self._vendor_named(iid)
        if direct:
            name, source = direct
            return {"resolved_name": name, "resolved_from": source,
                    "resolved_confidence": "high"}

        # 2. a vendor-named node belonging to the same physical device: the
        #    interface children of a composite device, or another instance of
        #    the very same hardware on a different port.
        for other in self.kin(iid):
            hit = self._vendor_named(other)
            if hit:
                return {
                    "resolved_name": hit[0],
                    "resolved_from": f"{other} ({hit[1]})",
                    "resolved_confidence": "high" if other in self._children.get(iid, ())
                    else "medium",
                }

        # 3. the public ID tables
        ids = dev.get("ids") or {}
        vendor, product = vendor_from_ids(ids)
        if vendor and product:
            return {"resolved_name": f"{vendor} {product}",
                    "resolved_from": f"{ids['id_kind']}.ids VID_{ids['vid']}/PID_{ids['pid']}",
                    "resolved_confidence": "medium"}
        if vendor:
            base = dev.get("description") or "device"
            return {"resolved_name": f"{vendor} {base}",
                    "resolved_from": f"{ids['id_kind']}.ids vendor VID_{ids['vid']}",
                    "resolved_confidence": "low"}

        return {"resolved_name": dev.get("description") or iid,
                "resolved_from": "DeviceDesc",
                "resolved_confidence": "none"}

    def _own_type(self, iid: str) -> tuple[str, str] | None:
        """(type, how) from this node alone, ignoring the tree."""
        dev = self.devices.get(iid, {})
        hid = hid_usage_type(dev.get("hardware_ids"), dev.get("compatible_ids"))
        if hid:
            return hid, "HID usage page"
        own = class_type(dev.get("class_name"))
        if own and (dev.get("class_name") or "").lower() not in self.CONTAINER_CLASSES:
            return own, "setup class"
        return None

    def resolve_type(self, iid: str) -> dict:
        dev = self.devices.get(iid, {})
        direct = self._own_type(iid)
        if direct and direct[1] == "HID usage page":
            return {"device_type": direct[0], "type_from": direct[1]}
        if direct and direct[0] not in self.WEAK_TYPES:
            return {"device_type": direct[0], "type_from": direct[1]}

        # Widen: children first, then other instances of the same hardware and
        # the rest of the physical device container.  A disconnected composite
        # node has no live children, so relatives are what make it work.
        candidates: list[tuple[int, str, str]] = []
        own_children = self._children.get(iid, ())

        def consider(other: str, rank_base: int) -> None:
            hit = self._own_type(other)
            if not hit:
                return
            weak = 1 if hit[0] in self.WEAK_TYPES else 0
            precise = 0 if hit[1] == "HID usage page" else 1
            candidates.append((rank_base + weak * 4 + precise, hit[0], f"{other} ({hit[1]})"))

        for other in self.kin(iid):
            consider(other, 0 if other in own_children else 2)

        if candidates:
            candidates.sort(key=lambda c: c[0])
            best = candidates[0]
            return {"device_type": best[1], "type_from": best[2]}

        if direct:
            return {"device_type": direct[0], "type_from": direct[1]}
        own = class_type(dev.get("class_name"))
        if own:
            return {"device_type": own, "type_from": "setup class"}
        return {"device_type": dev.get("class_name") or "Unknown", "type_from": "class name"}

    def resolve_vendor(self, iid: str) -> dict:
        dev = self.devices.get(iid, {})
        ids = dev.get("ids") or {}
        vendor, _product = vendor_from_ids(ids)
        mfg = dev.get("manufacturer")
        if mfg and not is_generic_mfg(mfg):
            return {"vendor": mfg, "vendor_from": "ManufacturerName"}
        for other in self.kin(iid):
            omfg = self.devices.get(other, {}).get("manufacturer")
            if omfg and not is_generic_mfg(omfg):
                return {"vendor": omfg, "vendor_from": other}
        if vendor:
            return {"vendor": vendor, "vendor_from": f"{ids.get('id_kind')}.ids"}
        return {"vendor": mfg or "", "vendor_from": "ManufacturerName"}

    def enrich(self, iid: str) -> dict:
        out = {}
        out.update(self.resolve_name(iid))
        out.update(self.resolve_type(iid))
        out.update(self.resolve_vendor(iid))
        out["type_icon"] = dp.TYPE_ICON.get(out.get("device_type", ""), "?")
        return out
