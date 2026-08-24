// DEVPKEY property keys, device-node status decoding, and the setup-class
// tables.  Data only -- the ctypes/P-Invoke plumbing lives in CfgMgr.cs.
// Mirrors dcc/devprops.py in the Python implementation.
using System;
using System.Collections.Generic;

namespace DeviceControlConsole
{
    public static class DevProps
    {
        // ----------------------------------------------------- DEVPROPTYPE
        public const uint TypeEmpty = 0x00000000;
        public const uint TypeByte = 0x00000003;
        public const uint TypeInt32 = 0x00000006;
        public const uint TypeUInt32 = 0x00000007;
        public const uint TypeUInt64 = 0x00000009;
        public const uint TypeGuid = 0x0000000D;
        public const uint TypeFileTime = 0x00000010;
        public const uint TypeBoolean = 0x00000011;
        public const uint TypeString = 0x00000012;
        public const uint TypeSecurityDescriptor = 0x00000013;
        public const uint TypeBinary = 0x00001003;
        public const uint TypeStringList = 0x00002012;

        // ------------------------------------------------ DEVPKEY fmt GUIDs
        private const string Dev = "{a45c254e-df1c-4efd-8020-67d146a850e0}";
        private const string Dev2 = "{540b947e-8b40-45bc-a8a2-6a0b894cbda2}";
        private const string DevNode = "{4340a6c5-93fa-4706-972c-7b648008a5a7}";
        private const string Drv = "{a8b865dd-2e3d-4094-ad97-e593a70c75d6}";
        private const string Dates = "{83da6326-97a6-4088-9453-a1923f573b29}";
        private const string Cont = "{8c7ed206-3f8a-4827-b3ab-ae9e1faefc6c}";
        private const string Model = "{78c34fc8-104a-4aca-9ea4-524d52996e57}";
        private const string ClassFmt = "{259abffc-50a7-47ce-af08-68c9a7d73366}";
        private const string Safe = "{afd97640-86a3-4210-b67c-289c41aabe55}";

        public sealed class PropKey
        {
            public readonly string Fmtid;
            public readonly uint Pid;
            public PropKey(string fmtid, uint pid) { Fmtid = fmtid; Pid = pid; }
        }

        public static readonly Dictionary<string, PropKey> Keys = BuildKeys();

        private static Dictionary<string, PropKey> BuildKeys()
        {
            Dictionary<string, PropKey> k = new Dictionary<string, PropKey>(StringComparer.Ordinal);
            // identity / description
            k["DeviceDesc"] = new PropKey(Dev, 2);
            k["HardwareIds"] = new PropKey(Dev, 3);
            k["CompatibleIds"] = new PropKey(Dev, 4);
            k["Service"] = new PropKey(Dev, 6);
            k["Class"] = new PropKey(Dev, 9);
            k["ClassGuid"] = new PropKey(Dev, 10);
            k["DriverKey"] = new PropKey(Dev, 11);
            k["ConfigFlags"] = new PropKey(Dev, 12);
            k["Manufacturer"] = new PropKey(Dev, 13);
            k["FriendlyName"] = new PropKey(Dev, 14);
            k["LocationInfo"] = new PropKey(Dev, 15);
            k["PDOName"] = new PropKey(Dev, 16);
            k["Capabilities"] = new PropKey(Dev, 17);
            k["UINumber"] = new PropKey(Dev, 18);
            k["UpperFilters"] = new PropKey(Dev, 19);
            k["LowerFilters"] = new PropKey(Dev, 20);
            k["EnumeratorName"] = new PropKey(Dev, 24);
            k["InstallState"] = new PropKey(Dev, 36);
            k["LocationPaths"] = new PropKey(Dev, 37);
            k["BaseContainerId"] = new PropKey(Dev, 38);
            k["InstanceId"] = new PropKey(Model, 256);
            k["Model"] = new PropKey(Model, 39);
            k["ContainerId"] = new PropKey(Cont, 2);
            // what the bus itself reported (the USB iProduct string)
            k["BusReportedDeviceDesc"] = new PropKey(Dev2, 4);
            k["SafeRemovalRequired"] = new PropKey(Safe, 2);
            // devnode status + relations
            k["DevNodeStatus"] = new PropKey(DevNode, 2);
            k["Problem"] = new PropKey(DevNode, 3);
            k["Parent"] = new PropKey(DevNode, 8);
            k["Children"] = new PropKey(DevNode, 9);
            k["Siblings"] = new PropKey(DevNode, 10);
            // the selected driver
            k["DriverDate"] = new PropKey(Drv, 2);
            k["DriverVersion"] = new PropKey(Drv, 3);
            k["DriverDesc"] = new PropKey(Drv, 4);
            k["DriverInfPath"] = new PropKey(Drv, 5);
            k["DriverInfSection"] = new PropKey(Drv, 6);
            k["MatchingDeviceId"] = new PropKey(Drv, 8);
            k["DriverProvider"] = new PropKey(Drv, 9);
            k["DriverRank"] = new PropKey(Drv, 14);
            // timestamps
            k["InstallDate"] = new PropKey(Dates, 100);
            k["FirstInstallDate"] = new PropKey(Dates, 101);
            k["LastArrivalDate"] = new PropKey(Dates, 102);
            k["LastRemovalDate"] = new PropKey(Dates, 103);
            return k;
        }

        public static readonly PropKey ClassName = new PropKey(ClassFmt, 2);

        /// <summary>Properties read for every device during a full scan.</summary>
        public static readonly string[] ScanKeys = new string[]
        {
            "DeviceDesc", "FriendlyName", "BusReportedDeviceDesc", "Class", "ClassGuid",
            "Manufacturer", "Service", "HardwareIds", "DriverInfPath", "DriverVersion",
            "DriverProvider", "DriverDate", "Parent", "Children", "DevNodeStatus",
            "Problem", "ContainerId", "LocationInfo", "LastArrivalDate",
            "LastRemovalDate", "InstallDate",
        };

        /// <summary>Everything, pulled on demand when one device is inspected.</summary>
        public static readonly string[] DetailKeys = new string[]
        {
            "DeviceDesc", "FriendlyName", "BusReportedDeviceDesc", "Class", "ClassGuid",
            "Manufacturer", "Service", "HardwareIds", "DriverInfPath", "DriverVersion",
            "DriverProvider", "DriverDate", "Parent", "Children", "DevNodeStatus",
            "Problem", "ContainerId", "LocationInfo", "LastArrivalDate",
            "LastRemovalDate", "InstallDate",
            "CompatibleIds", "DriverKey", "DriverDesc", "DriverInfSection",
            "MatchingDeviceId", "DriverRank", "PDOName", "LocationPaths", "UpperFilters",
            "LowerFilters", "EnumeratorName", "InstallState", "Siblings", "Model",
            "FirstInstallDate", "SafeRemovalRequired", "ConfigFlags", "Capabilities",
        };

        // -------------------------------------------------- DN_* status bits
        public const uint DnRootEnumerated = 0x00000001;
        public const uint DnDriverLoaded = 0x00000002;
        public const uint DnStarted = 0x00000008;
        public const uint DnHasProblem = 0x00000400;
        public const uint DnDisableable = 0x00002000;
        public const uint DnRemovable = 0x00004000;

        private static readonly string[] FlagNames = new string[]
        {
            "ROOT_ENUMERATED", "DRIVER_LOADED", "ENUM_LOADED", "STARTED", "MANUAL",
            "NEED_TO_ENUM", "NOT_FIRST_TIME", "HARDWARE_ENUM", "LIAR", "HAS_MARK",
            "HAS_PROBLEM", "FILTERED", "MOVED", "DISABLEABLE", "REMOVABLE",
            "PRIVATE_PROBLEM", "MF_PARENT", "MF_CHILD", "WILL_BE_REMOVED",
            "NOT_FIRST_TIMEE", "STOP_FREE_RES", "REBAL_CANDIDATE", "BAD_PARTIAL",
            "NT_ENUMERATOR", "NT_DRIVER", "NEEDS_LOCKING", "ARM_WAKEUP",
            "APM_ENUMERATOR", "APM_DRIVER", "SILENT_INSTALL", "NO_SHOW_IN_DM",
            "BOOT_LOG_PROB",
        };

        public static List<string> StatusFlags(uint status)
        {
            List<string> found = new List<string>();
            for (int bit = 0; bit < FlagNames.Length; bit++)
            {
                if ((status & (1u << bit)) != 0) found.Add(FlagNames[bit]);
            }
            return found;
        }

        // ------------------------------------------------ CM_PROB_* messages
        private static readonly Dictionary<int, string> Problems = BuildProblems();

        private static Dictionary<int, string> BuildProblems()
        {
            Dictionary<int, string> p = new Dictionary<int, string>();
            p[1] = "Not configured correctly";
            p[2] = "Cannot load the driver for this device";
            p[3] = "Driver may be corrupted, or the system is low on memory";
            p[4] = "The device is not working properly (registry may be corrupt)";
            p[5] = "The driver requires a resource that Windows cannot manage";
            p[6] = "The boot configuration conflicts with other devices";
            p[7] = "Cannot filter";
            p[8] = "The driver loader for the device is missing";
            p[9] = "The firmware reported incorrect information about the device";
            p[10] = "The device cannot start";
            p[11] = "The device failed";
            p[12] = "Cannot find enough free resources";
            p[13] = "Windows cannot verify the device's resources";
            p[14] = "Restart the computer to use this device";
            p[15] = "A re-enumeration problem (resource conflict)";
            p[16] = "Windows cannot identify all the resources this device uses";
            p[17] = "The device is asking for an unknown resource type";
            p[18] = "Reinstall the drivers for this device";
            p[19] = "The registry configuration is incomplete or damaged";
            p[20] = "Failed to load one of the drivers";
            p[21] = "Windows is removing the device";
            p[22] = "The device is disabled";
            p[23] = "System failure (try changing the driver)";
            p[24] = "Device is not present, not working properly, or missing drivers";
            p[25] = "Windows is still setting up this device";
            p[26] = "Windows is still setting up this device";
            p[27] = "The device does not have valid log configuration";
            p[28] = "The drivers for this device are not installed";
            p[29] = "The device is disabled because its firmware did not give it resources";
            p[30] = "The device is using an IRQ resource another device is using";
            p[31] = "The device is not working because Windows cannot load its drivers";
            p[32] = "A driver for this device has been disabled (start type is disabled)";
            p[33] = "Cannot determine which resources are required for this device";
            p[34] = "Manual configuration required";
            p[35] = "The firmware does not include enough information (MPS table)";
            p[36] = "The device is requesting a PCI interrupt but is configured for ISA";
            p[37] = "The driver returned a failure when it executed DriverEntry";
            p[38] = "A previous instance of the driver is still in memory";
            p[39] = "The driver is corrupted or missing";
            p[40] = "The service key information in the registry is missing or invalid";
            p[41] = "A legacy driver loaded but Windows cannot find the device";
            p[42] = "A duplicate device is already running";
            p[43] = "Windows stopped this device because it reported problems";
            p[44] = "An application or service shut down this device";
            p[45] = "The device is not connected to the computer";
            p[46] = "The device is unavailable because the system is shutting down";
            p[47] = "The device is prepared for safe removal but has not been removed";
            p[48] = "The software for this device has been blocked";
            p[49] = "The system hive has exceeded its size limit";
            p[50] = "Windows cannot apply all of the properties for this device";
            p[51] = "The device is waiting on another device or set of devices";
            p[52] = "The driver's digital signature could not be verified";
            p[53] = "The device has been reserved for use by the Windows kernel debugger";
            p[54] = "The device has failed and is undergoing a reset";
            p[55] = "The driver is not ready";
            return p;
        }

        public static string ProblemText(int code)
        {
            string text;
            if (code != 0 && Problems.TryGetValue(code, out text)) return text;
            return "";
        }

        /// <summary>Turns DevNodeStatus/Problem into the fields the UI shows.</summary>
        public static void DecodeStatus(uint status, int problem, bool present,
            out string label, out string problemText, out List<string> flags)
        {
            if (!present)
            {
                label = "Disconnected";
                problemText = ProblemText(problem);
                flags = new List<string>();
                return;
            }
            flags = StatusFlags(status);
            if ((status & DnHasProblem) != 0 && problem != 0)
            {
                if (problem == 22) label = "Disabled";
                else if (problem == 45) label = "Disconnected";
                else label = "Problem";
            }
            else if ((status & DnStarted) != 0) label = "Started";
            else label = "Stopped";
            problemText = problem != 0 ? ProblemText(problem) : "";
        }

        // ------------------------------------------- setup class -> "type"
        private static readonly Dictionary<string, string> ClassTypes = BuildClassTypes();

        private static Dictionary<string, string> BuildClassTypes()
        {
            Dictionary<string, string> m = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            m["mouse"] = "Mouse";
            m["keyboard"] = "Keyboard";
            m["hidclass"] = "HID";
            m["display"] = "Graphics";
            m["monitor"] = "Monitor";
            m["net"] = "Network adapter";
            m["netclient"] = "Network client";
            m["netservice"] = "Network service";
            m["nettrans"] = "Network protocol";
            m["media"] = "Audio/Video";
            m["audioendpoint"] = "Audio endpoint";
            m["audioprocessingobject"] = "Audio processing";
            m["sound"] = "Audio";
            m["usb"] = "USB controller/hub";
            m["usbdevice"] = "USB device";
            m["diskdrive"] = "Disk";
            m["cdrom"] = "Optical drive";
            m["volume"] = "Volume";
            m["volumesnapshot"] = "Volume snapshot";
            m["scsiadapter"] = "Storage controller";
            m["hdc"] = "Storage controller";
            m["printer"] = "Printer";
            m["printqueue"] = "Print queue";
            m["image"] = "Camera/Scanner";
            m["camera"] = "Camera";
            m["bluetooth"] = "Bluetooth";
            m["ports"] = "Serial/Parallel port";
            m["modem"] = "Modem";
            m["battery"] = "Battery";
            m["processor"] = "Processor";
            m["system"] = "System device";
            m["computer"] = "Computer";
            m["firmware"] = "Firmware";
            m["securitydevices"] = "Security device";
            m["smartcardreader"] = "Smart card reader";
            m["biometric"] = "Biometric";
            m["sensor"] = "Sensor";
            m["wpd"] = "Portable device";
            m["aenetdevice"] = "Network device";
            m["softwarecomponent"] = "Software component";
            m["softwaredevice"] = "Software device";
            m["extension"] = "Driver extension";
            m["dot4"] = "Multi-function printer";
            m["dot4print"] = "Printer function";
            m["medialocation"] = "Media location";
            m["infrared"] = "Infrared";
            m["smartcardfilter"] = "Smart card filter";
            m["memory"] = "Memory technology";
            m["1394"] = "IEEE 1394";
            m["pcmcia"] = "PCMCIA";
            m["fdc"] = "Floppy controller";
            m["floppydisk"] = "Floppy drive";
            m["tapedrive"] = "Tape drive";
            m["computeaccelerator"] = "Compute accelerator";
            m["mtd"] = "Memory technology";
            m["unknown"] = "Unknown";
            return m;
        }

        public static string ClassToType(string className)
        {
            if (string.IsNullOrEmpty(className)) return null;
            string type;
            if (ClassTypes.TryGetValue(className.Trim(), out type)) return type;
            return null;
        }

        // ------------------------------------------- HID usage page -> type
        private static readonly Dictionary<string, string> HidUsages = BuildHidUsages();

        private static Dictionary<string, string> BuildHidUsages()
        {
            Dictionary<string, string> m = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            m["0001:0002"] = "Mouse";
            m["0001:0004"] = "Joystick";
            m["0001:0005"] = "Gamepad";
            m["0001:0006"] = "Keyboard";
            m["0001:0007"] = "Keypad";
            m["0001:0080"] = "System control";
            m["000C:0001"] = "Consumer control";
            m["000D:0001"] = "Digitizer";
            m["000D:0002"] = "Pen";
            m["000D:0004"] = "Touch screen";
            m["000D:0005"] = "Touch pad";
            m["0080:0001"] = "Smart card";
            m["FF00:0001"] = "Vendor-specific";
            return m;
        }

        public static string HidUsageToType(string usagePage, string usage)
        {
            string type;
            if (HidUsages.TryGetValue(usagePage + ":" + usage, out type)) return type;
            return null;
        }
    }
}
