// Turns an instance ID into the thing a human actually owns.
//
// "USB\VID_1038&PID_1838\6&2ae87d4e&0&1" is reported by Windows as a
// "USB Composite Device" from "(Standard USB Host Controller)".  The real name
// -- SteelSeries Aerox 3 Wireless -- is on the machine already, just not in a
// field pnputil prints.  Tried in order of trust:
//
//   1. the device's own friendly name;
//   2. the string the bus reported (the USB iProduct descriptor);
//   3. another node of the same physical device -- a composite device's
//      interface children are installed from the vendor's own INF;
//   4. the public USB/PCI ID tables.
//
// Mirrors dcc/resolve.py in the Python implementation.
using System;
using System.Collections.Generic;
using System.Text.RegularExpressions;

namespace DeviceControlConsole
{
    public sealed class HwIds
    {
        public string Bus = "";
        public string Vid;
        public string Pid;
        public string SubsysVendor;
        public string SubsysDevice;
        public string Kind;  // "usb", "pci" or null

        public Dictionary<string, object> ToMap()
        {
            Dictionary<string, object> m = Json.Obj();
            m["bus"] = Bus;
            m["vid"] = Vid;
            m["pid"] = Pid;
            m["subsys_vendor"] = SubsysVendor;
            m["subsys_device"] = SubsysDevice;
            m["id_kind"] = Kind;
            return m;
        }
    }

    public static class Ids
    {
        private static readonly Regex UsbRe =
            new Regex(@"VID_([0-9A-Fa-f]{4}).*?PID_([0-9A-Fa-f]{4})", RegexOptions.Compiled);
        private static readonly Regex PciRe =
            new Regex(@"VEN_([0-9A-Fa-f]{4}).*?DEV_([0-9A-Fa-f]{4})", RegexOptions.Compiled);
        private static readonly Regex SubsysRe =
            new Regex(@"SUBSYS_([0-9A-Fa-f]{4})([0-9A-Fa-f]{4})", RegexOptions.Compiled);
        private static readonly Regex HidUsageRe =
            new Regex(@"UP:([0-9A-Fa-f]{4})_U:([0-9A-Fa-f]{4})", RegexOptions.Compiled);

        public static HwIds Parse(string instanceId, List<string> hardwareIds)
        {
            HwIds ids = new HwIds();
            string text = instanceId == null ? "" : instanceId;
            int slash = text.IndexOf('\\');
            ids.Bus = slash > 0 ? text.Substring(0, slash).ToUpperInvariant() : text.ToUpperInvariant();

            List<string> pool = new List<string>();
            pool.Add(text);
            if (hardwareIds != null) pool.AddRange(hardwareIds);

            foreach (string candidate in pool)
            {
                Match m = UsbRe.Match(candidate);
                if (m.Success)
                {
                    ids.Vid = m.Groups[1].Value.ToUpperInvariant();
                    ids.Pid = m.Groups[2].Value.ToUpperInvariant();
                    ids.Kind = "usb";
                    break;
                }
                m = PciRe.Match(candidate);
                if (m.Success)
                {
                    ids.Vid = m.Groups[1].Value.ToUpperInvariant();
                    ids.Pid = m.Groups[2].Value.ToUpperInvariant();
                    ids.Kind = "pci";
                    break;
                }
            }
            foreach (string candidate in pool)
            {
                Match m = SubsysRe.Match(candidate);
                if (m.Success)
                {
                    ids.SubsysDevice = m.Groups[1].Value.ToUpperInvariant();
                    ids.SubsysVendor = m.Groups[2].Value.ToUpperInvariant();
                    break;
                }
            }
            return ids;
        }

        public static string HidUsageType(List<string> hardwareIds, List<string> compatibleIds)
        {
            List<string> all = new List<string>();
            if (hardwareIds != null) all.AddRange(hardwareIds);
            if (compatibleIds != null) all.AddRange(compatibleIds);
            foreach (string hid in all)
            {
                Match m = HidUsageRe.Match(hid);
                if (m.Success)
                {
                    string hit = DevProps.HidUsageToType(
                        m.Groups[1].Value.ToUpperInvariant(), m.Groups[2].Value.ToUpperInvariant());
                    if (hit != null) return hit;
                }
                string upper = hid.ToUpperInvariant();
                if (upper.EndsWith("HID_DEVICE_SYSTEM_MOUSE")) return "Mouse";
                if (upper.EndsWith("HID_DEVICE_SYSTEM_KEYBOARD")) return "Keyboard";
                if (upper.EndsWith("HID_DEVICE_SYSTEM_GAME")) return "Gamepad";
            }
            return null;
        }
    }

    public static class Generic
    {
        // Descriptions that name a Windows enumerator rather than a product.
        private static readonly string[] Descriptions = new string[]
        {
            "usb composite device", "usb input device", "usb root hub", "generic usb hub",
            "usb hub", "unknown device", "usb mass storage device",
            "usb attached scsi (uas) mass storage device", "composite bus enumerator",
            "hid-compliant mouse", "hid-compliant device",
            "hid-compliant consumer control device", "hid-compliant vendor-defined device",
            "hid-compliant system controller", "hid keyboard device",
            "hid-compliant touch pad", "usb printing support", "generic pnp monitor",
            "pci device", "pci standard host cb bridge", "base system device",
            "usb serial converter", "microsoft usb generic device", "usb device",
            "bluetooth device", "generic bluetooth adapter",
            "standard nvm express controller", "standard sata ahci controller",
            "sd host controller", "unknown usb device", "audio endpoint",
        };

        private static readonly string[] MfgPrefixes =
            new string[] { "(standard", "(generic", "(default", "(retired" };
        private static readonly string[] MfgExact =
            new string[] { "microsoft", "generic", "compatible", "system", "unknown" };

        public static bool IsGenericDesc(string desc)
        {
            if (string.IsNullOrEmpty(desc)) return true;
            string low = desc.Trim().ToLowerInvariant();
            foreach (string g in Descriptions)
                if (low == g || low.StartsWith(g, StringComparison.Ordinal)) return true;
            return false;
        }

        public static bool IsGenericMfg(string mfg)
        {
            if (string.IsNullOrEmpty(mfg)) return true;
            string low = mfg.Trim().ToLowerInvariant();
            foreach (string g in MfgExact) if (low == g) return true;
            foreach (string g in MfgPrefixes)
                if (low.StartsWith(g, StringComparison.Ordinal)) return true;
            return false;
        }
    }

    public sealed class Resolution
    {
        public string Name = "";
        public string From = "";
        public string Confidence = "none";
        public string Type = "";
        public string TypeFrom = "";
        public string Vendor = "";
        public string VendorFrom = "";
    }

    /// <summary>Resolves names and types across a whole snapshot.</summary>
    public sealed class Resolver
    {
        // Classes that describe a container or a bus rather than the thing itself.
        private static readonly HashSet<string> ContainerClasses =
            new HashSet<string>(StringComparer.OrdinalIgnoreCase)
            { "usb", "usbdevice", "system", "computer", "softwaredevice", "extension",
              "volume", "hdc", "scsiadapter", "unknown", "usbfnproviders" };

        // Types that are correct but say little; a sibling saying "Mouse" wins.
        private static readonly HashSet<string> WeakTypes =
            new HashSet<string>(StringComparer.Ordinal)
            { "HID", "Consumer control", "Vendor-specific", "System control", "USB device",
              "USB controller/hub", "Unknown", "Software device", "Software component",
              "Driver extension", "System device", "HID device" };

        private readonly Dictionary<string, Device> _devices;
        private readonly Dictionary<string, List<string>> _children =
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, List<string>> _byVidPid =
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);
        private readonly Dictionary<string, List<string>> _byContainer =
            new Dictionary<string, List<string>>(StringComparer.OrdinalIgnoreCase);

        public Resolver(Dictionary<string, Device> devices)
        {
            _devices = devices;
            foreach (KeyValuePair<string, Device> kv in devices)
            {
                Device d = kv.Value;
                if (!string.IsNullOrEmpty(d.Ids.Vid) && !string.IsNullOrEmpty(d.Ids.Pid))
                    Add(_byVidPid, d.Ids.Vid + ":" + d.Ids.Pid, kv.Key);
                if (IsRealContainer(d.ContainerId))
                    Add(_byContainer, d.ContainerId, kv.Key);
                if (d.Children != null)
                    foreach (string c in d.Children) Add(_children, kv.Key, c);
            }
            // DEVPKEY_Device_Children is absent on plenty of nodes, but the
            // child always remembers its parent.
            foreach (KeyValuePair<string, Device> kv in devices)
            {
                string parent = kv.Value.Parent;
                if (string.IsNullOrEmpty(parent) || !devices.ContainsKey(parent)) continue;
                List<string> bucket;
                if (!_children.TryGetValue(parent, out bucket))
                {
                    bucket = new List<string>();
                    _children[parent] = bucket;
                }
                if (!bucket.Contains(kv.Key)) bucket.Add(kv.Key);
            }
        }

        private static void Add(Dictionary<string, List<string>> map, string key, string value)
        {
            List<string> list;
            if (!map.TryGetValue(key, out list)) { list = new List<string>(); map[key] = list; }
            if (!list.Contains(value)) list.Add(value);
        }

        private static bool IsRealContainer(string containerId)
        {
            if (string.IsNullOrEmpty(containerId)) return false;
            string low = containerId.ToLowerInvariant();
            return !low.StartsWith("{00000000", StringComparison.Ordinal)
                && !low.StartsWith("{ffffffff", StringComparison.Ordinal);
        }

        public List<string> ChildrenOf(string instanceId)
        {
            List<string> list;
            if (_children.TryGetValue(instanceId, out list)) return new List<string>(list);
            return new List<string>();
        }

        /// <summary>True when two nodes are functions of one piece of hardware.</summary>
        public bool SamePhysicalDevice(string a, string b)
        {
            Device da, db;
            if (!_devices.TryGetValue(a, out da) || !_devices.TryGetValue(b, out db)) return false;
            if (IsRealContainer(da.ContainerId)
                && string.Equals(da.ContainerId, db.ContainerId, StringComparison.OrdinalIgnoreCase))
                return true;
            if (!string.IsNullOrEmpty(da.Ids.Vid)
                && string.Equals(da.Ids.Vid, db.Ids.Vid, StringComparison.OrdinalIgnoreCase)
                && string.Equals(da.Ids.Pid, db.Ids.Pid, StringComparison.OrdinalIgnoreCase))
                return true;
            return false;
        }

        public List<string> Descendants(string instanceId, int depth)
        {
            List<string> found = new List<string>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            seen.Add(instanceId);
            List<string> frontier = new List<string>();
            frontier.Add(instanceId);
            for (int level = 0; level < depth; level++)
            {
                List<string> next = new List<string>();
                foreach (string current in frontier)
                {
                    List<string> kids;
                    if (!_children.TryGetValue(current, out kids)) continue;
                    foreach (string child in kids)
                    {
                        if (seen.Contains(child) || !_devices.ContainsKey(child)) continue;
                        seen.Add(child);
                        found.Add(child);
                        next.Add(child);
                    }
                }
                if (next.Count == 0) break;
                frontier = next;
            }
            return found;
        }

        public List<string> Relatives(string instanceId)
        {
            List<string> found = new List<string>();
            HashSet<string> seen = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
            seen.Add(instanceId);
            Device d;
            if (!_devices.TryGetValue(instanceId, out d)) return found;

            List<string> bucket;
            if (!string.IsNullOrEmpty(d.Ids.Vid) && !string.IsNullOrEmpty(d.Ids.Pid)
                && _byVidPid.TryGetValue(d.Ids.Vid + ":" + d.Ids.Pid, out bucket))
                foreach (string other in bucket)
                    if (seen.Add(other)) found.Add(other);

            if (IsRealContainer(d.ContainerId) && _byContainer.TryGetValue(d.ContainerId, out bucket))
                foreach (string other in bucket)
                    if (seen.Add(other)) found.Add(other);

            return found;
        }

        /// <summary>Descendants and relatives belonging to the same physical device.</summary>
        public List<string> Kin(string instanceId)
        {
            List<string> found = new List<string>();
            List<string> pool = Descendants(instanceId, 4);
            pool.AddRange(Relatives(instanceId));
            foreach (string other in pool)
                if (!found.Contains(other) && SamePhysicalDevice(instanceId, other))
                    found.Add(other);
            return found;
        }

        // ------------------------------------------------------- name
        private bool VendorNamed(string instanceId, out string name, out string source)
        {
            name = null; source = null;
            Device d;
            if (!_devices.TryGetValue(instanceId, out d)) return false;
            if (!string.IsNullOrEmpty(d.FriendlyName) && !Generic.IsGenericDesc(d.FriendlyName))
            {
                name = d.FriendlyName; source = "FriendlyName"; return true;
            }
            if (!string.IsNullOrEmpty(d.BusReported) && !Generic.IsGenericDesc(d.BusReported))
            {
                name = d.BusReported; source = "BusReportedDeviceDesc"; return true;
            }
            if (!string.IsNullOrEmpty(d.Description) && !Generic.IsGenericDesc(d.Description)
                && !Generic.IsGenericMfg(d.Manufacturer))
            {
                name = d.Description; source = "DeviceDesc"; return true;
            }
            return false;
        }

        public void ResolveName(string instanceId, Resolution into)
        {
            Device d;
            _devices.TryGetValue(instanceId, out d);

            // 1. the node names itself
            string name, source;
            if (VendorNamed(instanceId, out name, out source))
            {
                into.Name = name; into.From = source; into.Confidence = "high";
                return;
            }

            // 2. another node of the same physical device
            List<string> ownChildren = ChildrenOf(instanceId);
            foreach (string other in Kin(instanceId))
            {
                if (VendorNamed(other, out name, out source))
                {
                    into.Name = name;
                    into.From = other + " (" + source + ")";
                    into.Confidence = ownChildren.Contains(other) ? "high" : "medium";
                    return;
                }
            }

            // 3. the public ID tables
            if (d != null)
            {
                string vendor, product;
                HwDb.Lookup(d.Ids, out vendor, out product);
                if (vendor != null && product != null)
                {
                    into.Name = vendor + " " + product;
                    into.From = d.Ids.Kind + ".ids VID_" + d.Ids.Vid + "/PID_" + d.Ids.Pid;
                    into.Confidence = "medium";
                    return;
                }
                if (vendor != null)
                {
                    string basis = string.IsNullOrEmpty(d.Description) ? "device" : d.Description;
                    into.Name = vendor + " " + basis;
                    into.From = d.Ids.Kind + ".ids vendor VID_" + d.Ids.Vid;
                    into.Confidence = "low";
                    return;
                }
            }

            into.Name = (d != null && !string.IsNullOrEmpty(d.Description)) ? d.Description : instanceId;
            into.From = "DeviceDesc";
            into.Confidence = "none";
        }

        // ------------------------------------------------------- type
        private bool OwnType(string instanceId, out string type, out string how)
        {
            type = null; how = null;
            Device d;
            if (!_devices.TryGetValue(instanceId, out d)) return false;
            string hid = Ids.HidUsageType(d.HardwareIds, d.CompatibleIds);
            if (hid != null) { type = hid; how = "HID usage page"; return true; }
            string own = DevProps.ClassToType(d.ClassName);
            if (own != null && !ContainerClasses.Contains(d.ClassName == null ? "" : d.ClassName))
            {
                type = own; how = "setup class"; return true;
            }
            return false;
        }

        public void ResolveType(string instanceId, Resolution into)
        {
            Device d;
            _devices.TryGetValue(instanceId, out d);

            string directType, directHow;
            bool haveDirect = OwnType(instanceId, out directType, out directHow);
            if (haveDirect && (directHow == "HID usage page" || !WeakTypes.Contains(directType)))
            {
                into.Type = directType; into.TypeFrom = directHow;
                return;
            }

            // Widen to the rest of the same physical device.  A disconnected
            // composite node has no live children, so relatives are what make
            // this work at all.
            List<string> ownChildren = ChildrenOf(instanceId);
            int bestRank = int.MaxValue;
            string bestType = null, bestFrom = null;
            foreach (string other in Kin(instanceId))
            {
                string t, how;
                if (!OwnType(other, out t, out how)) continue;
                int rank = ownChildren.Contains(other) ? 0 : 2;
                if (WeakTypes.Contains(t)) rank += 4;
                if (how != "HID usage page") rank += 1;
                if (rank < bestRank)
                {
                    bestRank = rank; bestType = t; bestFrom = other + " (" + how + ")";
                }
            }
            if (bestType != null) { into.Type = bestType; into.TypeFrom = bestFrom; return; }

            if (haveDirect) { into.Type = directType; into.TypeFrom = directHow; return; }
            string fallback = d == null ? null : DevProps.ClassToType(d.ClassName);
            if (fallback != null) { into.Type = fallback; into.TypeFrom = "setup class"; return; }
            into.Type = (d != null && !string.IsNullOrEmpty(d.ClassName)) ? d.ClassName : "Unknown";
            into.TypeFrom = "class name";
        }

        // ----------------------------------------------------- vendor
        public void ResolveVendor(string instanceId, Resolution into)
        {
            Device d;
            if (!_devices.TryGetValue(instanceId, out d)) { into.Vendor = ""; return; }

            if (!string.IsNullOrEmpty(d.Manufacturer) && !Generic.IsGenericMfg(d.Manufacturer))
            {
                into.Vendor = d.Manufacturer; into.VendorFrom = "ManufacturerName"; return;
            }
            foreach (string other in Kin(instanceId))
            {
                Device o;
                if (!_devices.TryGetValue(other, out o)) continue;
                if (!string.IsNullOrEmpty(o.Manufacturer) && !Generic.IsGenericMfg(o.Manufacturer))
                {
                    into.Vendor = o.Manufacturer; into.VendorFrom = other; return;
                }
            }
            string vendor, product;
            HwDb.Lookup(d.Ids, out vendor, out product);
            if (vendor != null)
            {
                into.Vendor = vendor; into.VendorFrom = d.Ids.Kind + ".ids"; return;
            }
            into.Vendor = d.Manufacturer == null ? "" : d.Manufacturer;
            into.VendorFrom = "ManufacturerName";
        }

        public Resolution Enrich(string instanceId)
        {
            Resolution r = new Resolution();
            ResolveName(instanceId, r);
            ResolveType(instanceId, r);
            ResolveVendor(instanceId, r);
            return r;
        }
    }
}
