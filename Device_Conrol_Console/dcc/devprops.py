"""DEVPKEY property keys, device-node status/problem decoding, and setup class tables.

Everything in here is data: the numeric constants Windows uses to describe a
device node.  Keeping it separate from the ctypes plumbing (``cfgmgr.py``) keeps
both readable.
"""

from __future__ import annotations

# --- DEVPROPTYPE ----------------------------------------------------------
DEVPROP_TYPE_EMPTY = 0x00000000
DEVPROP_TYPE_NULL = 0x00000001
DEVPROP_TYPE_SBYTE = 0x00000002
DEVPROP_TYPE_BYTE = 0x00000003
DEVPROP_TYPE_INT16 = 0x00000004
DEVPROP_TYPE_UINT16 = 0x00000005
DEVPROP_TYPE_INT32 = 0x00000006
DEVPROP_TYPE_UINT32 = 0x00000007
DEVPROP_TYPE_INT64 = 0x00000008
DEVPROP_TYPE_UINT64 = 0x00000009
DEVPROP_TYPE_FLOAT = 0x0000000A
DEVPROP_TYPE_DOUBLE = 0x0000000B
DEVPROP_TYPE_DECIMAL = 0x0000000C
DEVPROP_TYPE_GUID = 0x0000000D
DEVPROP_TYPE_DATE = 0x0000000F
DEVPROP_TYPE_FILETIME = 0x00000010
DEVPROP_TYPE_BOOLEAN = 0x00000011
DEVPROP_TYPE_STRING = 0x00000012
DEVPROP_TYPE_SECURITY_DESCRIPTOR = 0x00000013
DEVPROP_TYPE_BINARY = 0x00001003
DEVPROP_TYPE_STRING_LIST = 0x00002012

# --- DEVPKEY format GUIDs -------------------------------------------------
_DEV = "{a45c254e-df1c-4efd-8020-67d146a850e0}"       # base device properties
_DEV2 = "{540b947e-8b40-45bc-a8a2-6a0b894cbda2}"      # bus-reported / misc
_DEVNODE = "{4340a6c5-93fa-4706-972c-7b648008a5a7}"   # relations + status
_DRV = "{a8b865dd-2e3d-4094-ad97-e593a70c75d6}"       # the selected driver
_DATES = "{83da6326-97a6-4088-9453-a1923f573b29}"     # install/arrival dates
_CONT = "{8c7ed206-3f8a-4827-b3ab-ae9e1faefc6c}"      # container id
_MODEL = "{78c34fc8-104a-4aca-9ea4-524d52996e57}"     # instance id / model
_CLASS = "{259abffc-50a7-47ce-af08-68c9a7d73366}"     # setup class properties
_SAFE = "{afd97640-86a3-4210-b67c-289c41aabe55}"      # safe removal

#: name -> (format GUID, property id).  Used by :mod:`dcc.cfgmgr`.
DEVPKEYS: dict[str, tuple[str, int]] = {
    # identity / description
    "DeviceDesc": (_DEV, 2),
    "HardwareIds": (_DEV, 3),
    "CompatibleIds": (_DEV, 4),
    "Service": (_DEV, 6),
    "Class": (_DEV, 9),
    "ClassGuid": (_DEV, 10),
    "DriverKey": (_DEV, 11),
    "ConfigFlags": (_DEV, 12),
    "Manufacturer": (_DEV, 13),
    "FriendlyName": (_DEV, 14),
    "LocationInfo": (_DEV, 15),
    "PDOName": (_DEV, 16),
    "Capabilities": (_DEV, 17),
    "UINumber": (_DEV, 18),
    "UpperFilters": (_DEV, 19),
    "LowerFilters": (_DEV, 20),
    "EnumeratorName": (_DEV, 24),
    "InstallState": (_DEV, 36),
    "LocationPaths": (_DEV, 37),
    "BaseContainerId": (_DEV, 38),
    "InstanceId": (_MODEL, 256),
    "Model": (_MODEL, 39),
    "ContainerId": (_CONT, 2),
    # what the bus itself reported (USB iProduct string, BT name, ...)
    "BusReportedDeviceDesc": (_DEV2, 4),
    "SafeRemovalRequired": (_SAFE, 2),
    # devnode status + relations
    "DevNodeStatus": (_DEVNODE, 2),
    "Problem": (_DEVNODE, 3),
    "EjectionRelations": (_DEVNODE, 4),
    "RemovalRelations": (_DEVNODE, 5),
    "PowerRelations": (_DEVNODE, 6),
    "BusRelations": (_DEVNODE, 7),
    "Parent": (_DEVNODE, 8),
    "Children": (_DEVNODE, 9),
    "Siblings": (_DEVNODE, 10),
    "TransportRelations": (_DEVNODE, 11),
    # selected driver
    "DriverDate": (_DRV, 2),
    "DriverVersion": (_DRV, 3),
    "DriverDesc": (_DRV, 4),
    "DriverInfPath": (_DRV, 5),
    "DriverInfSection": (_DRV, 6),
    "DriverInfSectionExt": (_DRV, 7),
    "MatchingDeviceId": (_DRV, 8),
    "DriverProvider": (_DRV, 9),
    "DriverRank": (_DRV, 14),
    # timestamps
    "InstallDate": (_DATES, 100),
    "FirstInstallDate": (_DATES, 101),
    "LastArrivalDate": (_DATES, 102),
    "LastRemovalDate": (_DATES, 103),
}

#: Properties fetched for every device on a full scan.  Kept deliberately small
#: -- the rest are pulled on demand when a single device is inspected.
SCAN_KEYS = (
    "DeviceDesc",
    "FriendlyName",
    "BusReportedDeviceDesc",
    "Class",
    "ClassGuid",
    "Manufacturer",
    "Service",
    "HardwareIds",
    "DriverInfPath",
    "DriverVersion",
    "DriverProvider",
    "DriverDate",
    "Parent",
    "Children",
    "DevNodeStatus",
    "Problem",
    "ContainerId",
    "LocationInfo",
    "LastArrivalDate",
    "LastRemovalDate",
    "InstallDate",
)

DETAIL_KEYS = SCAN_KEYS + (
    "CompatibleIds",
    "DriverKey",
    "DriverDesc",
    "DriverInfSection",
    "MatchingDeviceId",
    "DriverRank",
    "PDOName",
    "LocationPaths",
    "UpperFilters",
    "LowerFilters",
    "EnumeratorName",
    "InstallState",
    "Siblings",
    "Model",
    "FirstInstallDate",
    "SafeRemovalRequired",
    "ConfigFlags",
    "Capabilities",
)

# --- setup class property keys -------------------------------------------
DEVPKEY_DeviceClass_Name = (_CLASS, 2)
DEVPKEY_DeviceClass_ClassName = (_CLASS, 3)

# --- DN_* device node status flags ---------------------------------------
DN_FLAGS = [
    (0x00000001, "ROOT_ENUMERATED"),
    (0x00000002, "DRIVER_LOADED"),
    (0x00000004, "ENUM_LOADED"),
    (0x00000008, "STARTED"),
    (0x00000010, "MANUAL"),
    (0x00000020, "NEED_TO_ENUM"),
    (0x00000040, "NOT_FIRST_TIME"),
    (0x00000080, "HARDWARE_ENUM"),
    (0x00000100, "LIAR"),
    (0x00000200, "HAS_MARK"),
    (0x00000400, "HAS_PROBLEM"),
    (0x00000800, "FILTERED"),
    (0x00001000, "MOVED"),
    (0x00002000, "DISABLEABLE"),
    (0x00004000, "REMOVABLE"),
    (0x00008000, "PRIVATE_PROBLEM"),
    (0x00010000, "MF_PARENT"),
    (0x00020000, "MF_CHILD"),
    (0x00040000, "WILL_BE_REMOVED"),
    (0x00080000, "NOT_FIRST_TIMEE"),
    (0x00100000, "STOP_FREE_RES"),
    (0x00200000, "REBAL_CANDIDATE"),
    (0x00400000, "BAD_PARTIAL"),
    (0x00800000, "NT_ENUMERATOR"),
    (0x01000000, "NT_DRIVER"),
    (0x02000000, "NEEDS_LOCKING"),
    (0x04000000, "ARM_WAKEUP"),
    (0x08000000, "APM_ENUMERATOR"),
    (0x10000000, "APM_DRIVER"),
    (0x20000000, "SILENT_INSTALL"),
    (0x40000000, "NO_SHOW_IN_DM"),
    (0x80000000, "BOOT_LOG_PROB"),
]

DN_STARTED = 0x00000008
DN_HAS_PROBLEM = 0x00000400
DN_DRIVER_LOADED = 0x00000002
DN_DISABLEABLE = 0x00002000
DN_REMOVABLE = 0x00004000

#: CM_PROB_* problem codes (the numbers Device Manager shows as "Code 43" etc.)
CM_PROBLEMS = {
    0: "",
    1: "Not configured correctly",
    2: "Cannot load the driver for this device",
    3: "Driver may be corrupted, or the system is low on memory",
    4: "The device is not working properly (registry may be corrupt)",
    5: "The driver requires a resource that Windows cannot manage",
    6: "The boot configuration conflicts with other devices",
    7: "Cannot filter",
    8: "The driver loader for the device is missing",
    9: "The firmware reported incorrect information about the device",
    10: "The device cannot start",
    11: "The device failed",
    12: "Cannot find enough free resources",
    13: "Windows cannot verify the device's resources",
    14: "Restart the computer to use this device",
    15: "A re-enumeration problem (resource conflict)",
    16: "Windows cannot identify all the resources this device uses",
    17: "The device is asking for an unknown resource type",
    18: "Reinstall the drivers for this device",
    19: "The registry configuration is incomplete or damaged",
    20: "Failed to load one of the drivers (VxD loader)",
    21: "Windows is removing the device",
    22: "The device is disabled",
    23: "System failure (try changing the driver)",
    24: "Device is not present, not working properly, or missing drivers",
    25: "Windows is still setting up this device",
    26: "Windows is still setting up this device",
    27: "The device does not have valid log configuration",
    28: "The drivers for this device are not installed",
    29: "The device is disabled because its firmware did not give it resources",
    30: "The device is using an IRQ resource another device is using",
    31: "The device is not working because Windows cannot load its drivers",
    32: "A driver for this device has been disabled (start type is disabled)",
    33: "Cannot determine which resources are required for this device",
    34: "Manual configuration required",
    35: "The firmware does not include enough information (MPS table)",
    36: "The device is requesting a PCI interrupt but is configured for ISA",
    37: "The driver returned a failure when it executed DriverEntry",
    38: "A previous instance of the driver is still in memory",
    39: "The driver is corrupted or missing",
    40: "The service key information in the registry is missing or invalid",
    41: "A legacy driver loaded but Windows cannot find the device",
    42: "A duplicate device is already running",
    43: "Windows stopped this device because it reported problems",
    44: "An application or service shut down this device",
    45: "The device is not connected to the computer",
    46: "The device is unavailable because the system is shutting down",
    47: "The device is prepared for safe removal but has not been removed",
    48: "The software for this device has been blocked",
    49: "The system hive has exceeded its size limit",
    50: "Windows cannot apply all of the properties for this device",
    51: "The device is waiting on another device or set of devices",
    52: "The driver's digital signature could not be verified",
    53: "The device has been reserved for use by the Windows kernel debugger",
    54: "The device has failed and is undergoing a reset",
    55: "The driver is not ready",
}

#: A pragmatic setup-class -> human "device type" map.  Used to answer the
#: "if there is option include type: mouse" part of the brief.
CLASS_TO_TYPE = {
    "mouse": "Mouse",
    "keyboard": "Keyboard",
    "hidclass": "HID",
    "display": "Graphics",
    "monitor": "Monitor",
    "net": "Network adapter",
    "netclient": "Network client",
    "netservice": "Network service",
    "nettrans": "Network protocol",
    "media": "Audio/Video",
    "audioendpoint": "Audio endpoint",
    "audioprocessingobject": "Audio processing",
    "sound": "Audio",
    "usb": "USB controller/hub",
    "usbdevice": "USB device",
    "diskdrive": "Disk",
    "cdrom": "Optical drive",
    "volume": "Volume",
    "volumesnapshot": "Volume snapshot",
    "scsiadapter": "Storage controller",
    "hdc": "Storage controller",
    "printer": "Printer",
    "printqueue": "Print queue",
    "image": "Camera/Scanner",
    "camera": "Camera",
    "bluetooth": "Bluetooth",
    "ports": "Serial/Parallel port",
    "modem": "Modem",
    "battery": "Battery",
    "processor": "Processor",
    "system": "System device",
    "computer": "Computer",
    "firmware": "Firmware",
    "securitydevices": "Security device",
    "smartcardreader": "Smart card reader",
    "biometric": "Biometric",
    "sensor": "Sensor",
    "wpd": "Portable device",
    "aenetdevice": "Network device",
    "softwarecomponent": "Software component",
    "softwaredevice": "Software device",
    "extension": "Driver extension",
    "dot4": "Multi-function printer",
    "dot4print": "Printer function",
    "medialocation": "Media location",
    "infrared": "Infrared",
    "smartcardfilter": "Smart card filter",
    "memory": "Memory technology",
    "mtd": "Memory technology",
    "computeaccelerator": "Compute accelerator",
    "1394": "IEEE 1394",
    "pcmcia": "PCMCIA",
    "fdc": "Floppy controller",
    "floppydisk": "Floppy drive",
    "tapedrive": "Tape drive",
    "unknown": "Unknown",
}

#: Emoji-free glyph hints for the UI (kept ASCII-safe on purpose).
TYPE_ICON = {
    "Mouse": "M",
    "Keyboard": "K",
    "HID": "H",
    "Graphics": "G",
    "Monitor": "D",
    "Network adapter": "N",
    "Audio": "A",
    "Audio/Video": "A",
    "Audio endpoint": "A",
    "USB controller/hub": "U",
    "USB device": "U",
    "Disk": "S",
    "Printer": "P",
    "Camera": "C",
    "Bluetooth": "B",
    "Battery": "E",
    "Processor": "X",
    "System device": "Y",
}

#: HID usage page / usage -> type.  Parsed out of hardware IDs shaped like
#: ``HID\VID_1038&UP:0001_U:0002``.
HID_USAGE_TO_TYPE = {
    ("0001", "0002"): "Mouse",
    ("0001", "0004"): "Joystick",
    ("0001", "0005"): "Gamepad",
    ("0001", "0006"): "Keyboard",
    ("0001", "0007"): "Keypad",
    ("0001", "0080"): "System control",
    ("000C", "0001"): "Consumer control",
    ("000D", "0001"): "Digitizer",
    ("000D", "0002"): "Pen",
    ("000D", "0004"): "Touch screen",
    ("000D", "0005"): "Touch pad",
    ("0080", "0001"): "Smart card",
    ("FF00", "0001"): "Vendor-specific",
}


def decode_status(status: int | None, problem: int | None, present: bool) -> dict:
    """Turn DevNodeStatus/Problem into the fields the UI shows."""
    if not present:
        return {
            "status": "Disconnected",
            "problem_code": problem or 0,
            "problem_text": CM_PROBLEMS.get(problem or 0, ""),
            "flags": [],
        }
    status = status or 0
    flags = [name for bit, name in DN_FLAGS if status & bit]
    if status & DN_HAS_PROBLEM and problem:
        if problem == 22:
            label = "Disabled"
        elif problem == 45:
            label = "Disconnected"
        else:
            label = "Problem"
    elif status & DN_STARTED:
        label = "Started"
    else:
        label = "Stopped"
    return {
        "status": label,
        "problem_code": problem or 0,
        "problem_text": CM_PROBLEMS.get(problem or 0, "") if problem else "",
        "flags": flags,
    }
