// The snapshot the console works on: devices, the driver store, and the
// relations between them.  Mirrors dcc/model.py in the Python implementation.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Text;
using System.Text.RegularExpressions;

namespace DeviceControlConsole
{
    public sealed class Device
    {
        public string InstanceId = "";
        public string Description = "";
        public string FriendlyName = "";
        public string BusReported = "";
        public string ClassName = "";
        public string ClassGuid = "";
        public string ClassDisplay = "";
        public string Manufacturer = "";
        public string Service = "";
        public List<string> HardwareIds = new List<string>();
        public List<string> CompatibleIds = new List<string>();
        public string DriverInf = "";
        public string DriverVersion = "";
        public string DriverProvider = "";
        public string DriverDate = "";
        public string Parent = "";
        public List<string> Children = new List<string>();
        public string ContainerId = "";
        public string Location = "";
        public string InstallDate = "";
        public string LastArrival = "";
        public string LastRemoval = "";
        public bool Present;
        public string Status = "";
        public int ProblemCode;
        public string ProblemText = "";
        public List<string> StatusFlags = new List<string>();
        public HwIds Ids = new HwIds();
        public string DriverName = "";
        public List<string> ExtensionDrivers = new List<string>();

        // filled in by the resolver
        public string ResolvedName = "";
        public string ResolvedFrom = "";
        public string ResolvedConfidence = "none";
        public string DeviceType = "";
        public string TypeFrom = "";
        public string Vendor = "";
        public string VendorFrom = "";
        public List<string> Related = new List<string>();
        public bool DriverIsOem;
        public string SearchBlob = "";

        public Dictionary<string, object> ToMap()
        {
            Dictionary<string, object> m = Json.Obj();
            m["instance_id"] = InstanceId;
            m["description"] = Description;
            m["friendly_name"] = FriendlyName;
            m["bus_reported"] = BusReported;
            m["class_name"] = ClassName;
            m["class_guid"] = ClassGuid;
            m["class_display"] = ClassDisplay;
            m["manufacturer"] = Manufacturer;
            m["service"] = Service;
            m["hardware_ids"] = HardwareIds;
            m["compatible_ids"] = CompatibleIds;
            m["driver_inf"] = DriverInf;
            m["driver_version"] = DriverVersion;
            m["driver_provider"] = DriverProvider;
            m["driver_date"] = DriverDate;
            m["parent"] = Parent;
            m["children"] = Children;
            m["related"] = Related;
            m["container_id"] = ContainerId;
            m["location"] = Location;
            m["install_date"] = InstallDate;
            m["last_arrival"] = LastArrival;
            m["last_removal"] = LastRemoval;
            m["present"] = Present;
            m["status"] = Status;
            m["problem_code"] = ProblemCode;
            m["problem_text"] = ProblemText;
            m["status_flags"] = StatusFlags;
            m["ids"] = Ids.ToMap();
            m["driver_name"] = DriverName;
            m["extension_drivers"] = ExtensionDrivers;
            m["resolved_name"] = ResolvedName;
            m["resolved_from"] = ResolvedFrom;
            m["resolved_confidence"] = ResolvedConfidence;
            m["device_type"] = DeviceType;
            m["type_from"] = TypeFrom;
            m["vendor"] = Vendor;
            m["vendor_from"] = VendorFrom;
            m["driver_is_oem"] = DriverIsOem;
            m["child_count"] = Children.Count;
            m["search_blob"] = SearchBlob;
            return m;
        }
    }

    public sealed class DriverEntry
    {
        public DriverPackage Package;
        public string VersionDate;
        public string VersionNumber;
        public int[] VersionParts = new int[0];
        public List<string> DeviceIds = new List<string>();
        public List<string> DeviceNames = new List<string>();
        public int PresentDeviceCount;
        public bool IsExtension;
        public bool Orphaned;
        public string SupersededBy = "";
        public List<string> FamilyMembers = new List<string>();
        public string SearchBlob = "";

        public Dictionary<string, object> ToMap()
        {
            Dictionary<string, object> m = Json.Obj();
            m["driver_name"] = Package.DriverName;
            m["original_name"] = Package.OriginalName;
            m["provider_name"] = Package.ProviderName;
            m["class_name"] = Package.ClassName;
            m["class_guid"] = Package.ClassGuid;
            m["driver_version"] = Package.DriverVersion;
            m["signer_name"] = Package.SignerName;
            m["attributes"] = Package.Attributes;
            m["whcp_version"] = Package.WhcpVersion;
            m["driver_package_id"] = Package.DriverPackageId;
            m["family_id"] = Package.FamilyId;
            m["version_date"] = VersionDate;
            m["version_number"] = VersionNumber;
            m["device_ids"] = DeviceIds;
            m["device_names"] = DeviceNames;
            m["device_count"] = DeviceIds.Count;
            m["present_device_count"] = PresentDeviceCount;
            m["in_use"] = DeviceIds.Count > 0;
            m["is_extension"] = IsExtension;
            m["orphaned"] = Orphaned;
            m["superseded_by"] = SupersededBy;
            m["family_members"] = FamilyMembers;
            m["search_blob"] = SearchBlob;
            return m;
        }
    }

    public sealed class Snapshot
    {
        public List<Device> Devices = new List<Device>();
        public Dictionary<string, Device> DeviceIndex =
            new Dictionary<string, Device>(StringComparer.OrdinalIgnoreCase);
        public List<DriverEntry> Drivers = new List<DriverEntry>();
        public Dictionary<string, DriverEntry> DriverIndex =
            new Dictionary<string, DriverEntry>(StringComparer.OrdinalIgnoreCase);
        public Resolver Resolver;
        public List<string> Warnings = new List<string>();
        public DateTime GeneratedAt = DateTime.Now;

        public Dictionary<string, object> Meta()
        {
            int present = 0, problems = 0;
            foreach (Device d in Devices)
            {
                if (d.Present) present++;
                if (d.ProblemCode != 0) problems++;
            }
            int orphans = 0, superseded = 0;
            foreach (DriverEntry e in Drivers)
            {
                if (e.Orphaned) orphans++;
                if (e.SupersededBy.Length > 0) superseded++;
            }
            Dictionary<string, object> m = Json.Obj();
            m["generated_at"] = GeneratedAt.ToString("yyyy-MM-dd'T'HH:mm:sszzz", CultureInfo.InvariantCulture);
            m["device_count"] = Devices.Count;
            m["present_count"] = present;
            m["ghost_count"] = Devices.Count - present;
            m["problem_count"] = problems;
            m["driver_count"] = Drivers.Count;
            m["orphan_driver_count"] = orphans;
            m["superseded_driver_count"] = superseded;
            m["warnings"] = Warnings;
            return m;
        }
    }

    public static class Model
    {
        private static readonly Regex OemInfRe =
            new Regex(@"^oem\d+\.inf$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex VersionRe =
            new Regex(@"^\s*(\d{1,2}/\d{1,2}/\d{4})\s+(\S+)\s*$", RegexOptions.Compiled);
        private static readonly Regex OemNumRe =
            new Regex(@"^oem(\d+)\.inf$", RegexOptions.IgnoreCase | RegexOptions.Compiled);

        public static bool IsOemInf(string name)
        {
            return !string.IsNullOrEmpty(name) && OemInfRe.IsMatch(name.Trim());
        }

        public static void SplitDriverVersion(string text, out string isoDate,
            out string version, out int[] parts)
        {
            isoDate = null; version = null; parts = new int[0];
            if (string.IsNullOrEmpty(text)) return;
            Match m = VersionRe.Match(text);
            if (!m.Success) { version = text.Trim(); return; }
            version = m.Groups[2].Value;
            DateTime parsed;
            string[] formats = { "MM/dd/yyyy", "dd/MM/yyyy" };
            if (DateTime.TryParseExact(m.Groups[1].Value, formats, CultureInfo.InvariantCulture,
                    DateTimeStyles.None, out parsed))
                isoDate = parsed.ToString("yyyy-MM-dd", CultureInfo.InvariantCulture);
            string[] chunks = version.Split('.');
            parts = new int[chunks.Length];
            for (int i = 0; i < chunks.Length; i++)
            {
                int n;
                parts[i] = int.TryParse(chunks[i], out n) ? n : 0;
            }
        }

        private static int CompareVersions(int[] a, int[] b)
        {
            int len = Math.Max(a.Length, b.Length);
            for (int i = 0; i < len; i++)
            {
                int x = i < a.Length ? a[i] : 0;
                int y = i < b.Length ? b[i] : 0;
                if (x != y) return x.CompareTo(y);
            }
            return 0;
        }

        private static string Text(Dictionary<string, object> props, string key)
        {
            object v;
            if (!props.TryGetValue(key, out v) || v == null) return "";
            return v.ToString();
        }

        private static List<string> TextList(Dictionary<string, object> props, string key)
        {
            object v;
            if (!props.TryGetValue(key, out v) || v == null) return new List<string>();
            List<string> list = v as List<string>;
            return list != null ? list : new List<string>();
        }

        private static uint UInt(Dictionary<string, object> props, string key)
        {
            object v;
            if (!props.TryGetValue(key, out v) || v == null) return 0;
            try { return Convert.ToUInt32(v, CultureInfo.InvariantCulture); }
            catch (Exception) { return 0; }
        }

        public static Snapshot Build()
        {
            Snapshot snap = new Snapshot();

            // ---- devices from the Configuration Manager
            foreach (string id in CfgMgr.ListInstanceIds(false))
            {
                DevNode node = CfgMgr.Locate(id);
                if (node == null) continue;
                Dictionary<string, object> props = CfgMgr.GetProperties(node.DevInst, DevProps.ScanKeys);

                Device d = new Device();
                d.InstanceId = id;
                d.Description = Text(props, "DeviceDesc");
                d.FriendlyName = Text(props, "FriendlyName");
                d.BusReported = Text(props, "BusReportedDeviceDesc");
                d.ClassName = Text(props, "Class");
                d.ClassGuid = Text(props, "ClassGuid").ToLowerInvariant();
                d.Manufacturer = Text(props, "Manufacturer");
                d.Service = Text(props, "Service");
                d.HardwareIds = TextList(props, "HardwareIds");
                d.DriverInf = Text(props, "DriverInfPath");
                d.DriverVersion = Text(props, "DriverVersion");
                d.DriverProvider = Text(props, "DriverProvider");
                d.DriverDate = Text(props, "DriverDate");
                d.ContainerId = Text(props, "ContainerId").ToLowerInvariant();
                d.Location = Text(props, "LocationInfo");
                d.InstallDate = Text(props, "InstallDate");
                d.LastArrival = Text(props, "LastArrivalDate");
                d.LastRemoval = Text(props, "LastRemovalDate");
                d.Present = node.Present;

                d.Children = TextList(props, "Children");
                if (d.Children.Count == 0) d.Children = CfgMgr.ChildrenOf(node.DevInst);
                d.Parent = Text(props, "Parent");
                if (d.Parent.Length == 0)
                {
                    string walked = CfgMgr.ParentOf(node.DevInst);
                    d.Parent = walked == null ? "" : walked;
                }

                int problem = (int)UInt(props, "Problem");
                string label, problemText;
                List<string> flags;
                DevProps.DecodeStatus(UInt(props, "DevNodeStatus"), problem, node.Present,
                    out label, out problemText, out flags);
                d.Status = label;
                d.ProblemCode = problem;
                d.ProblemText = problemText;
                d.StatusFlags = flags;
                d.Ids = Ids.Parse(id, d.HardwareIds);

                snap.Devices.Add(d);
                snap.DeviceIndex[id] = d;
            }

            // ---- overlay pnputil's device view (driver + extension drivers)
            try
            {
                foreach (PnpDeviceRow row in PnpUtil.EnumDevices())
                {
                    Device d;
                    if (!snap.DeviceIndex.TryGetValue(row.InstanceId, out d))
                    {
                        d = new Device();
                        d.InstanceId = row.InstanceId;
                        d.Description = row.Description;
                        d.ClassName = row.ClassName;
                        d.ClassGuid = (row.ClassGuid ?? "").ToLowerInvariant();
                        d.Manufacturer = row.Manufacturer;
                        d.Present = row.Status != "Disconnected";
                        d.Status = row.Status;
                        d.Ids = Ids.Parse(row.InstanceId, null);
                        snap.Devices.Add(d);
                        snap.DeviceIndex[row.InstanceId] = d;
                    }
                    d.DriverName = row.DriverName;
                    d.ExtensionDrivers = row.ExtensionDrivers;
                    if (d.Description.Length == 0) d.Description = row.Description;
                    if (d.ClassName.Length == 0) d.ClassName = row.ClassName;
                    if (d.Manufacturer.Length == 0) d.Manufacturer = row.Manufacturer;
                }
            }
            catch (PnpUtilException ex)
            {
                snap.Warnings.Add("pnputil /enum-devices: " + ex.Message);
            }

            // ---- the driver store
            List<DriverPackage> packages = new List<DriverPackage>();
            try { packages = PnpUtil.EnumDrivers(); }
            catch (PnpUtilException ex) { snap.Warnings.Add("pnputil /enum-drivers: " + ex.Message); }

            Dictionary<string, HashSet<string>> usedBy =
                new Dictionary<string, HashSet<string>>(StringComparer.OrdinalIgnoreCase);
            foreach (Device d in snap.Devices)
            {
                AddUse(usedBy, d.DriverName, d.InstanceId);
                AddUse(usedBy, d.DriverInf, d.InstanceId);
                foreach (string ext in d.ExtensionDrivers) AddUse(usedBy, ext, d.InstanceId);
            }

            foreach (DriverPackage pkg in packages)
            {
                DriverEntry e = new DriverEntry();
                e.Package = pkg;
                string iso, version;
                int[] parts;
                SplitDriverVersion(pkg.DriverVersion, out iso, out version, out parts);
                e.VersionDate = iso;
                e.VersionNumber = version;
                e.VersionParts = parts;

                HashSet<string> linked = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                HashSet<string> fromDevices;
                if (usedBy.TryGetValue(pkg.DriverName, out fromDevices))
                    foreach (string id in fromDevices) linked.Add(id);
                foreach (string id in pkg.DeviceIds) linked.Add(id);

                e.DeviceIds = new List<string>(linked);
                e.DeviceIds.Sort(StringComparer.OrdinalIgnoreCase);
                foreach (string id in e.DeviceIds)
                {
                    Device d;
                    if (snap.DeviceIndex.TryGetValue(id, out d) && d.Present) e.PresentDeviceCount++;
                }
                e.IsExtension = string.Equals(pkg.ClassName, "Extension", StringComparison.OrdinalIgnoreCase);
                e.Orphaned = e.DeviceIds.Count == 0;

                snap.Drivers.Add(e);
                snap.DriverIndex[pkg.DriverName] = e;
            }

            // ---- older copies of the same package still in the store
            Dictionary<string, List<DriverEntry>> families =
                new Dictionary<string, List<DriverEntry>>(StringComparer.OrdinalIgnoreCase);
            foreach (DriverEntry e in snap.Drivers)
            {
                string key = e.Package.FamilyId;
                if (string.IsNullOrEmpty(key)) key = e.Package.OriginalName;
                if (string.IsNullOrEmpty(key)) key = e.Package.DriverName;
                List<DriverEntry> members;
                if (!families.TryGetValue(key, out members))
                {
                    members = new List<DriverEntry>();
                    families[key] = members;
                }
                members.Add(e);
            }
            foreach (KeyValuePair<string, List<DriverEntry>> kv in families)
            {
                List<DriverEntry> members = kv.Value;
                if (members.Count < 2) continue;
                members.Sort(delegate (DriverEntry a, DriverEntry b)
                {
                    int c = CompareVersions(b.VersionParts, a.VersionParts);
                    if (c != 0) return c;
                    return string.CompareOrdinal(b.VersionDate ?? "", a.VersionDate ?? "");
                });
                List<string> names = new List<string>();
                foreach (DriverEntry m in members) names.Add(m.Package.DriverName);
                foreach (DriverEntry m in members) m.FamilyMembers = names;
                for (int i = 1; i < members.Count; i++)
                    members[i].SupersededBy = members[0].Package.DriverName;
            }

            // ---- resolve names, types and vendors
            Resolver resolver = new Resolver(snap.DeviceIndex);
            snap.Resolver = resolver;
            foreach (Device d in snap.Devices)
            {
                Resolution r = resolver.Enrich(d.InstanceId);
                d.ResolvedName = r.Name;
                d.ResolvedFrom = r.From;
                d.ResolvedConfidence = r.Confidence;
                d.DeviceType = r.Type;
                d.TypeFrom = r.TypeFrom;
                d.Vendor = r.Vendor;
                d.VendorFrom = r.VendorFrom;
                d.Children = resolver.ChildrenOf(d.InstanceId);
                List<string> related = resolver.Relatives(d.InstanceId);
                if (related.Count > 32) related = related.GetRange(0, 32);
                d.Related = related;
                string display = CfgMgr.ClassDisplayName(d.ClassGuid);
                d.ClassDisplay = display == null ? "" : display;
                string driverName = d.DriverName.Length > 0 ? d.DriverName : d.DriverInf;
                d.DriverIsOem = IsOemInf(driverName);
                d.SearchBlob = BuildDeviceBlob(d);
            }

            foreach (DriverEntry e in snap.Drivers)
            {
                foreach (string id in e.DeviceIds)
                {
                    Device d;
                    if (snap.DeviceIndex.TryGetValue(id, out d) && d.ResolvedName.Length > 0)
                        e.DeviceNames.Add(d.ResolvedName);
                }
                e.SearchBlob = BuildDriverBlob(e);
            }

            snap.Devices.Sort(delegate (Device a, Device b)
            {
                return string.Compare(a.InstanceId, b.InstanceId, StringComparison.OrdinalIgnoreCase);
            });
            snap.Drivers.Sort(delegate (DriverEntry a, DriverEntry b)
            {
                return OemSortKey(a.Package.DriverName).CompareTo(OemSortKey(b.Package.DriverName));
            });
            return snap;
        }

        private static void AddUse(Dictionary<string, HashSet<string>> map, string inf, string instanceId)
        {
            if (!IsOemInf(inf)) return;
            HashSet<string> set;
            if (!map.TryGetValue(inf, out set))
            {
                set = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
                map[inf] = set;
            }
            set.Add(instanceId);
        }

        private static long OemSortKey(string name)
        {
            Match m = OemNumRe.Match(name == null ? "" : name.Trim());
            if (!m.Success) return 1000000;
            return long.Parse(m.Groups[1].Value, CultureInfo.InvariantCulture);
        }

        private static string BuildDeviceBlob(Device d)
        {
            StringBuilder sb = new StringBuilder(256);
            Append(sb, d.InstanceId); Append(sb, d.ResolvedName); Append(sb, d.Description);
            Append(sb, d.FriendlyName); Append(sb, d.BusReported); Append(sb, d.ClassName);
            Append(sb, d.ClassDisplay); Append(sb, d.Manufacturer); Append(sb, d.Vendor);
            Append(sb, d.DeviceType); Append(sb, d.Service); Append(sb, d.DriverName);
            Append(sb, d.DriverInf); Append(sb, d.Status); Append(sb, d.ProblemText);
            foreach (string e in d.ExtensionDrivers) Append(sb, e);
            foreach (string h in d.HardwareIds) Append(sb, h);
            return sb.ToString().ToLowerInvariant();
        }

        private static string BuildDriverBlob(DriverEntry e)
        {
            StringBuilder sb = new StringBuilder(256);
            Append(sb, e.Package.DriverName); Append(sb, e.Package.OriginalName);
            Append(sb, e.Package.ProviderName); Append(sb, e.Package.ClassName);
            Append(sb, e.Package.DriverVersion); Append(sb, e.Package.SignerName);
            Append(sb, e.Package.DriverPackageId); Append(sb, e.Package.FamilyId);
            foreach (string a in e.Package.Attributes) Append(sb, a);
            foreach (string n in e.DeviceNames) Append(sb, n);
            return sb.ToString().ToLowerInvariant();
        }

        private static void Append(StringBuilder sb, string value)
        {
            if (string.IsNullOrEmpty(value)) return;
            if (sb.Length > 0) sb.Append(' ');
            sb.Append(value);
        }

        /// <summary>Full property dump for one device, for the detail pane.</summary>
        public static Dictionary<string, object> DeviceDetail(string instanceId)
        {
            DevNode node = CfgMgr.Locate(instanceId);
            if (node == null) return Json.Obj();
            return CfgMgr.GetProperties(node.DevInst, DevProps.DetailKeys);
        }
    }

    /// <summary>Holds one snapshot in memory; refresh is explicit and thread-safe.</summary>
    public sealed class SnapshotCache
    {
        private readonly object _gate = new object();
        private Snapshot _snapshot;

        public Snapshot Get(bool refresh)
        {
            lock (_gate)
            {
                if (refresh || _snapshot == null) _snapshot = Model.Build();
                return _snapshot;
            }
        }

        public void Invalidate()
        {
            lock (_gate) { _snapshot = null; }
        }
    }
}
