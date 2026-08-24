"""Thin ctypes wrapper over ``cfgmgr32.dll`` (the Windows Configuration Manager).

``pnputil /enum-devices`` prints a fixed, localised set of six fields.  The
Configuration Manager API behind it exposes the whole device node -- friendly
names, the bus-reported product string, parent/child relations, install and
arrival timestamps -- and does it in about half a second for the entire
machine, without elevation.  This module is that access layer; nothing here
knows about the UI.
"""

from __future__ import annotations

import ctypes
import datetime
import sys
from ctypes import wintypes as wt

from . import devprops as dp

if sys.platform != "win32":  # pragma: no cover - the whole tool is Windows-only
    raise RuntimeError("Device Control Console requires Windows")

_cfgmgr = ctypes.WinDLL("cfgmgr32", use_last_error=True)

CR_SUCCESS = 0
CR_NO_SUCH_VALUE = 37
CR_NO_SUCH_DEVNODE = 13

CM_LOCATE_DEVNODE_NORMAL = 0x00000000
CM_LOCATE_DEVNODE_PHANTOM = 0x00000001
CM_LOCATE_DEVNODE_CANCELREMOVE = 0x00000002
CM_LOCATE_DEVNODE_NOVALIDATION = 0x00000004

CM_GETIDLIST_FILTER_NONE = 0x00000000
CM_GETIDLIST_FILTER_PRESENT = 0x00000100
CM_GETIDLIST_DONOTGENERATE = 0x10000040


class GUID(ctypes.Structure):
    _fields_ = [
        ("Data1", ctypes.c_uint32),
        ("Data2", ctypes.c_uint16),
        ("Data3", ctypes.c_uint16),
        ("Data4", ctypes.c_ubyte * 8),
    ]

    def __init__(self, text: str = "{00000000-0000-0000-0000-000000000000}"):
        super().__init__()
        parts = text.strip().strip("{}").split("-")
        if len(parts) != 5:
            raise ValueError(f"bad GUID: {text!r}")
        self.Data1 = int(parts[0], 16)
        self.Data2 = int(parts[1], 16)
        self.Data3 = int(parts[2], 16)
        tail = bytes.fromhex(parts[3] + parts[4])
        self.Data4 = (ctypes.c_ubyte * 8)(*tail)

    def __str__(self) -> str:
        tail = bytes(self.Data4)
        return "{%08x-%04x-%04x-%s-%s}" % (
            self.Data1,
            self.Data2,
            self.Data3,
            tail[:2].hex(),
            tail[2:].hex(),
        )


class DEVPROPKEY(ctypes.Structure):
    _fields_ = [("fmtid", GUID), ("pid", ctypes.c_ulong)]


_KEY_CACHE: dict[str, DEVPROPKEY] = {}


def _key(name: str) -> DEVPROPKEY:
    k = _KEY_CACHE.get(name)
    if k is None:
        fmt, pid = dp.DEVPKEYS[name]
        k = DEVPROPKEY(GUID(fmt), pid)
        _KEY_CACHE[name] = k
    return k


_cfgmgr.CM_Get_Device_ID_List_SizeW.argtypes = [
    ctypes.POINTER(ctypes.c_ulong),
    wt.LPCWSTR,
    ctypes.c_ulong,
]
_cfgmgr.CM_Get_Device_ID_ListW.argtypes = [
    wt.LPCWSTR,
    wt.LPWSTR,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
_cfgmgr.CM_Locate_DevNodeW.argtypes = [
    ctypes.POINTER(ctypes.c_ulong),
    wt.LPCWSTR,
    ctypes.c_ulong,
]
_cfgmgr.CM_Get_DevNode_PropertyW.argtypes = [
    ctypes.c_ulong,
    ctypes.POINTER(DEVPROPKEY),
    ctypes.POINTER(ctypes.c_ulong),
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_ulong),
    ctypes.c_ulong,
]
_cfgmgr.CM_Get_Class_PropertyW.argtypes = [
    ctypes.POINTER(GUID),
    ctypes.POINTER(DEVPROPKEY),
    ctypes.POINTER(ctypes.c_ulong),
    ctypes.c_void_p,
    ctypes.POINTER(ctypes.c_ulong),
    ctypes.c_ulong,
]
_cfgmgr.CM_Get_Device_IDW.argtypes = [
    ctypes.c_ulong,
    wt.LPWSTR,
    ctypes.c_ulong,
    ctypes.c_ulong,
]
_cfgmgr.CM_Get_Parent.argtypes = [
    ctypes.POINTER(ctypes.c_ulong),
    ctypes.c_ulong,
    ctypes.c_ulong,
]
_cfgmgr.CM_Get_Child.argtypes = [
    ctypes.POINTER(ctypes.c_ulong),
    ctypes.c_ulong,
    ctypes.c_ulong,
]
_cfgmgr.CM_Get_Sibling.argtypes = [
    ctypes.POINTER(ctypes.c_ulong),
    ctypes.c_ulong,
    ctypes.c_ulong,
]

_EPOCH_DELTA = 116444736000000000  # 1601-01-01 -> 1970-01-01 in 100ns ticks


def _filetime_to_iso(raw: bytes) -> str | None:
    if len(raw) < 8:
        return None
    ticks = int.from_bytes(raw[:8], "little")
    if ticks == 0:
        return None
    seconds = (ticks - _EPOCH_DELTA) / 10_000_000
    try:
        dt = datetime.datetime.fromtimestamp(seconds, datetime.timezone.utc)
    except (OverflowError, OSError, ValueError):
        return None
    return dt.isoformat(timespec="seconds")


def _decode(prop_type: int, raw: bytes):
    """Decode a DEVPROP blob into a plain Python value."""
    if prop_type == dp.DEVPROP_TYPE_STRING:
        return raw.decode("utf-16-le", "replace").rstrip("\x00")
    if prop_type == dp.DEVPROP_TYPE_STRING_LIST:
        text = raw.decode("utf-16-le", "replace")
        return [s for s in text.split("\x00") if s]
    if prop_type == dp.DEVPROP_TYPE_UINT32:
        return int.from_bytes(raw[:4], "little")
    if prop_type == dp.DEVPROP_TYPE_INT32:
        return int.from_bytes(raw[:4], "little", signed=True)
    if prop_type == dp.DEVPROP_TYPE_UINT64:
        return int.from_bytes(raw[:8], "little")
    if prop_type == dp.DEVPROP_TYPE_BOOLEAN:
        return raw[0] != 0
    if prop_type == dp.DEVPROP_TYPE_BYTE:
        return raw[0]
    if prop_type == dp.DEVPROP_TYPE_FILETIME:
        return _filetime_to_iso(raw)
    if prop_type == dp.DEVPROP_TYPE_GUID and len(raw) >= 16:
        g = GUID.from_buffer_copy(raw[:16])
        return str(g)
    if prop_type == dp.DEVPROP_TYPE_SECURITY_DESCRIPTOR:
        return None
    if prop_type == dp.DEVPROP_TYPE_BINARY:
        return raw.hex()
    return None


class DevNode:
    """A located device node handle plus its instance id."""

    __slots__ = ("devinst", "instance_id", "present")

    def __init__(self, devinst: int, instance_id: str, present: bool):
        self.devinst = devinst
        self.instance_id = instance_id
        self.present = present


def list_instance_ids(present_only: bool = False) -> list[str]:
    """Every device instance id known to the system (including phantoms)."""
    flags = CM_GETIDLIST_FILTER_PRESENT if present_only else CM_GETIDLIST_FILTER_NONE
    size = ctypes.c_ulong(0)
    if _cfgmgr.CM_Get_Device_ID_List_SizeW(ctypes.byref(size), None, flags) != CR_SUCCESS:
        return []
    if size.value == 0:
        return []
    buf = ctypes.create_unicode_buffer(size.value)
    if _cfgmgr.CM_Get_Device_ID_ListW(None, buf, size.value, flags) != CR_SUCCESS:
        return []
    return [s for s in buf[: size.value].split("\x00") if s]


def locate(instance_id: str) -> DevNode | None:
    """Locate a devnode, falling back to a phantom (not-present) lookup."""
    devinst = ctypes.c_ulong(0)
    rc = _cfgmgr.CM_Locate_DevNodeW(
        ctypes.byref(devinst), instance_id, CM_LOCATE_DEVNODE_NORMAL
    )
    if rc == CR_SUCCESS:
        return DevNode(devinst.value, instance_id, True)
    rc = _cfgmgr.CM_Locate_DevNodeW(
        ctypes.byref(devinst), instance_id, CM_LOCATE_DEVNODE_PHANTOM
    )
    if rc == CR_SUCCESS:
        return DevNode(devinst.value, instance_id, False)
    return None


def get_property(devinst: int, name: str):
    """Read a single DEVPKEY from a devnode.  ``None`` when the node has none."""
    key = _key(name)
    ptype = ctypes.c_ulong(0)
    size = ctypes.c_ulong(0)
    _cfgmgr.CM_Get_DevNode_PropertyW(
        devinst, ctypes.byref(key), ctypes.byref(ptype), None, ctypes.byref(size), 0
    )
    if size.value == 0:
        return None
    buf = (ctypes.c_ubyte * size.value)()
    rc = _cfgmgr.CM_Get_DevNode_PropertyW(
        devinst,
        ctypes.byref(key),
        ctypes.byref(ptype),
        ctypes.cast(buf, ctypes.c_void_p),
        ctypes.byref(size),
        0,
    )
    if rc != CR_SUCCESS:
        return None
    return _decode(ptype.value, bytes(buf)[: size.value])


def get_properties(devinst: int, names) -> dict:
    out = {}
    for name in names:
        value = get_property(devinst, name)
        if value not in (None, "", []):
            out[name] = value
    return out


def device_id(devinst: int) -> str | None:
    buf = ctypes.create_unicode_buffer(512)
    if _cfgmgr.CM_Get_Device_IDW(devinst, buf, 512, 0) != CR_SUCCESS:
        return None
    return buf.value


def parent_of(devinst: int) -> str | None:
    out = ctypes.c_ulong(0)
    if _cfgmgr.CM_Get_Parent(ctypes.byref(out), devinst, 0) != CR_SUCCESS:
        return None
    return device_id(out.value)


def children_of(devinst: int) -> list[str]:
    """Walk child + sibling links; works even when DEVPKEY_Device_Children is absent."""
    out = ctypes.c_ulong(0)
    if _cfgmgr.CM_Get_Child(ctypes.byref(out), devinst, 0) != CR_SUCCESS:
        return []
    ids = []
    cur = out.value
    while True:
        cid = device_id(cur)
        if cid:
            ids.append(cid)
        nxt = ctypes.c_ulong(0)
        if _cfgmgr.CM_Get_Sibling(ctypes.byref(nxt), cur, 0) != CR_SUCCESS:
            break
        cur = nxt.value
        if len(ids) > 4096:  # defensive: never loop forever on a corrupt tree
            break
    return ids


_CLASS_NAME_CACHE: dict[str, str] = {}


def class_display_name(class_guid: str) -> str | None:
    """The friendly setup-class name, e.g. ``{4d36e96f-...}`` -> ``Mice and other...``."""
    if not class_guid:
        return None
    cached = _CLASS_NAME_CACHE.get(class_guid.lower())
    if cached is not None:
        return cached or None
    try:
        guid = GUID(class_guid)
    except ValueError:
        _CLASS_NAME_CACHE[class_guid.lower()] = ""
        return None
    fmt, pid = dp.DEVPKEY_DeviceClass_Name
    key = DEVPROPKEY(GUID(fmt), pid)
    ptype = ctypes.c_ulong(0)
    size = ctypes.c_ulong(0)
    _cfgmgr.CM_Get_Class_PropertyW(
        ctypes.byref(guid),
        ctypes.byref(key),
        ctypes.byref(ptype),
        None,
        ctypes.byref(size),
        0,
    )
    name = ""
    if size.value:
        buf = (ctypes.c_ubyte * size.value)()
        rc = _cfgmgr.CM_Get_Class_PropertyW(
            ctypes.byref(guid),
            ctypes.byref(key),
            ctypes.byref(ptype),
            ctypes.cast(buf, ctypes.c_void_p),
            ctypes.byref(size),
            0,
        )
        if rc == CR_SUCCESS:
            decoded = _decode(ptype.value, bytes(buf)[: size.value])
            if isinstance(decoded, str):
                name = decoded
    _CLASS_NAME_CACHE[class_guid.lower()] = name
    return name or None
