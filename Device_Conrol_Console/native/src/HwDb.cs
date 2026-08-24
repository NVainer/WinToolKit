// Offline USB / PCI vendor+product tables.
//
// Windows only reports what the INF says.  When the INF is generic the vendor
// and product still live in the VID/PID, so this resolves those against the
// public usb.ids / pci.ids tables.
//
// The tables are not bundled: they are fetched on request (the "Update USB/PCI
// ID database" button, or --update-hwids) and cached next to the executable so
// a portable copy on a USB stick keeps them.  Until then a built-in list of
// common vendors is used, so the tool is never useless offline.
//
// Mirrors dcc/hwids.py in the Python implementation.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.IO;
using System.Net;
using System.Text;
using System.Text.RegularExpressions;

namespace DeviceControlConsole
{
    public static class HwDb
    {
        public sealed class Vendor
        {
            public string Name = "";
            public Dictionary<string, string> Products =
                new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
        }

        public static readonly Dictionary<string, string> Sources = BuildSources();

        private static Dictionary<string, string> BuildSources()
        {
            Dictionary<string, string> m = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            m["usb.ids"] = "http://www.linux-usb.org/usb.ids";
            m["pci.ids"] = "https://pci-ids.ucw.cz/v2.2/pci.ids";
            return m;
        }

        /// <summary>Cache lives beside the exe so a portable copy carries it along.</summary>
        public static string CacheDir
        {
            get
            {
                string exe = System.Reflection.Assembly.GetExecutingAssembly().Location;
                string dir = Path.GetDirectoryName(exe);
                if (string.IsNullOrEmpty(dir)) dir = Environment.CurrentDirectory;
                string candidate = Path.Combine(dir, "hwids");
                try
                {
                    if (!Directory.Exists(candidate)) Directory.CreateDirectory(candidate);
                    // Confirm it is actually writable -- Program Files is not.
                    string probe = Path.Combine(candidate, ".writable");
                    File.WriteAllText(probe, "");
                    File.Delete(probe);
                    return candidate;
                }
                catch (Exception)
                {
                    string appData = Path.Combine(
                        Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData),
                        "DeviceControlConsole");
                    try { if (!Directory.Exists(appData)) Directory.CreateDirectory(appData); }
                    catch (Exception) { }
                    return appData;
                }
            }
        }

        private static readonly object Gate = new object();
        private static readonly Dictionary<string, Dictionary<string, Vendor>> Loaded =
            new Dictionary<string, Dictionary<string, Vendor>>(StringComparer.OrdinalIgnoreCase);

        private static readonly Regex VendorLine =
            new Regex(@"^([0-9a-fA-F]{4})\s+(.*)$", RegexOptions.Compiled);
        private static readonly Regex ProductLine =
            new Regex(@"^\t([0-9a-fA-F]{4})\s+(.*)$", RegexOptions.Compiled);

        public static Dictionary<string, Vendor> Parse(string text)
        {
            Dictionary<string, Vendor> vendors =
                new Dictionary<string, Vendor>(StringComparer.OrdinalIgnoreCase);
            Vendor current = null;
            foreach (string rawLine in text.Split('\n'))
            {
                string line = rawLine.TrimEnd('\r');
                if (line.Length == 0 || line[0] == '#') continue;
                if (line.StartsWith("\t\t", StringComparison.Ordinal)) continue; // interface level
                if (line[0] == '\t')
                {
                    if (current == null) continue;
                    Match pm = ProductLine.Match(line);
                    if (pm.Success)
                        current.Products[pm.Groups[1].Value.ToUpperInvariant()] = pm.Groups[2].Value.Trim();
                    continue;
                }
                Match vm = VendorLine.Match(line);
                if (vm.Success)
                {
                    current = new Vendor();
                    current.Name = vm.Groups[2].Value.Trim();
                    vendors[vm.Groups[1].Value.ToUpperInvariant()] = current;
                }
                else current = null;  // a section header such as "C 00 ..."
            }
            return vendors;
        }

        private static Dictionary<string, Vendor> Load(string table)
        {
            lock (Gate)
            {
                Dictionary<string, Vendor> cached;
                if (Loaded.TryGetValue(table, out cached)) return cached;

                Dictionary<string, Vendor> vendors = null;
                string path = Path.Combine(CacheDir, table);
                if (File.Exists(path))
                {
                    try { vendors = Parse(File.ReadAllText(path, Encoding.UTF8)); }
                    catch (IOException) { vendors = null; }
                }
                if (vendors == null || vendors.Count == 0)
                {
                    vendors = new Dictionary<string, Vendor>(StringComparer.OrdinalIgnoreCase);
                    string[] seed = table.Equals("usb.ids", StringComparison.OrdinalIgnoreCase)
                        ? SeedUsb : SeedPci;
                    for (int i = 0; i + 1 < seed.Length; i += 2)
                    {
                        Vendor v = new Vendor();
                        v.Name = seed[i + 1];
                        vendors[seed[i]] = v;
                    }
                }
                Loaded[table] = vendors;
                return vendors;
            }
        }

        public static void Lookup(HwIds ids, out string vendor, out string product)
        {
            vendor = null; product = null;
            if (ids == null || ids.Kind == null || string.IsNullOrEmpty(ids.Vid)) return;
            string table = ids.Kind == "usb" ? "usb.ids" : "pci.ids";
            Dictionary<string, Vendor> vendors = Load(table);
            Vendor entry;
            if (vendors.TryGetValue(ids.Vid, out entry))
            {
                vendor = entry.Name.Length > 0 ? entry.Name : null;
                if (!string.IsNullOrEmpty(ids.Pid))
                {
                    string hit;
                    if (entry.Products.TryGetValue(ids.Pid, out hit)) product = hit;
                }
                return;
            }
            if (ids.Kind == "pci" && !string.IsNullOrEmpty(ids.SubsysVendor)
                && vendors.TryGetValue(ids.SubsysVendor, out entry))
            {
                vendor = entry.Name.Length > 0 ? entry.Name : null;
            }
        }

        public static Dictionary<string, object> Status()
        {
            Dictionary<string, object> all = Json.Obj();
            foreach (KeyValuePair<string, string> kv in Sources)
            {
                string path = Path.Combine(CacheDir, kv.Key);
                bool exists = File.Exists(path);
                Dictionary<string, object> info = Json.Obj();
                info["path"] = path;
                info["downloaded"] = exists;
                info["size"] = exists ? new FileInfo(path).Length : 0L;
                info["mtime"] = exists
                    ? File.GetLastWriteTime(path).ToString("s", CultureInfo.InvariantCulture)
                    : null;
                info["vendors"] = Load(kv.Key).Count;
                all[kv.Key] = info;
            }
            return all;
        }

        /// <summary>Downloads the tables.  Explicit action -- never runs on its own.</summary>
        public static Dictionary<string, object> Update(List<string> names)
        {
            Dictionary<string, object> results = Json.Obj();
            List<string> wanted = new List<string>();
            if (names != null && names.Count > 0) wanted.AddRange(names);
            else foreach (KeyValuePair<string, string> kv in Sources) wanted.Add(kv.Key);

            foreach (string name in wanted)
            {
                Dictionary<string, object> outcome = Json.Obj();
                string url;
                if (!Sources.TryGetValue(name, out url))
                {
                    outcome["ok"] = false;
                    outcome["error"] = "unknown table";
                    results[name] = outcome;
                    continue;
                }
                try
                {
                    ServicePointManager.SecurityProtocol =
                        SecurityProtocolType.Tls12 | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls;
                    using (WebClient client = new WebClient())
                    {
                        client.Headers.Add("User-Agent", "DeviceControlConsole/1.0");
                        byte[] data = client.DownloadData(url);
                        string text = Encoding.UTF8.GetString(data);
                        Dictionary<string, Vendor> parsed = Parse(text);
                        if (text.Length < 10000 || parsed.Count == 0)
                            throw new InvalidDataException("that does not look like an ID table");
                        File.WriteAllText(Path.Combine(CacheDir, name), text, Encoding.UTF8);
                        lock (Gate) { Loaded.Remove(name); }
                        outcome["ok"] = true;
                        outcome["bytes"] = data.Length;
                        outcome["vendors"] = Load(name).Count;
                    }
                }
                catch (Exception ex)
                {
                    outcome["ok"] = false;
                    outcome["error"] = ex.GetType().Name + ": " + ex.Message;
                }
                results[name] = outcome;
            }
            return results;
        }

        // Offline fallback: vendors common on consumer and business PCs.
        private static readonly string[] SeedUsb = new string[]
        {
            "03F0", "HP", "0403", "FTDI", "0409", "NEC", "041E", "Creative Technology",
            "0424", "Microchip (SMSC)", "0451", "Texas Instruments", "045E", "Microsoft",
            "046D", "Logitech", "0471", "Philips", "04A9", "Canon", "04B3", "IBM",
            "04B4", "Cypress", "04B8", "Seiko Epson", "04CA", "Lite-On",
            "04D8", "Microchip", "04E8", "Samsung", "04F2", "Chicony",
            "04F3", "Elan Microelectronics", "0502", "Acer", "050D", "Belkin",
            "054C", "Sony", "056A", "Wacom", "057E", "Nintendo", "058F", "Alcor Micro",
            "05AC", "Apple", "05C6", "Qualcomm", "05E3", "Genesys Logic",
            "0644", "TEAC", "067B", "Prolific", "06CB", "Synaptics", "0718", "Imation",
            "07CA", "AVerMedia", "0781", "SanDisk", "0836", "Sierra Wireless",
            "0846", "NetGear", "08E6", "Gemalto", "090C", "Silicon Motion",
            "0930", "Toshiba", "093A", "Pixart Imaging", "0951", "Kingston",
            "09DA", "A4Tech", "0A12", "Cambridge Silicon Radio", "0A5C", "Broadcom",
            "0B05", "ASUSTek", "0B0E", "GN Netcom (Jabra)", "0B95", "ASIX",
            "0BB4", "HTC", "0BC2", "Seagate", "0BDA", "Realtek", "0C45", "Microdia",
            "0C76", "JMTek", "0CF3", "Qualcomm Atheros", "0D8C", "C-Media",
            "0E8D", "MediaTek", "0F42", "Nuvoton", "1004", "LG Electronics",
            "1038", "SteelSeries ApS", "1050", "Yubico", "1058", "Western Digital",
            "10C4", "Silicon Labs", "1199", "Sierra Wireless", "12D1", "Huawei",
            "13D3", "IMC Networks", "1462", "MSI", "1532", "Razer", "15A9", "Gemtek",
            "174C", "ASMedia", "17EF", "Lenovo", "18D1", "Google",
            "1915", "Nordic Semiconductor", "1A40", "Terminus Technology",
            "1A86", "QinHeng Electronics", "1B1C", "Corsair", "1BCF", "Sunplus",
            "1D6B", "Linux Foundation", "1E7D", "ROCCAT", "2109", "VIA Labs",
            "2188", "Realtek", "22B8", "Motorola", "2341", "Arduino", "2357", "TP-Link",
            "2717", "Xiaomi", "27C6", "Goodix", "28DE", "Valve", "2C7C", "Quectel",
            "2E8A", "Raspberry Pi", "413C", "Dell", "5986", "Acer/Bison Electronics",
            "8086", "Intel", "8087", "Intel",
        };

        private static readonly string[] SeedPci = new string[]
        {
            "1002", "Advanced Micro Devices, Inc. [AMD/ATI]", "1013", "Cirrus Logic",
            "1022", "Advanced Micro Devices, Inc. [AMD]", "1028", "Dell",
            "103C", "Hewlett-Packard", "1043", "ASUSTeK", "104C", "Texas Instruments",
            "1102", "Creative Labs", "1106", "VIA Technologies", "1179", "Toshiba",
            "10DE", "NVIDIA Corporation", "10EC", "Realtek Semiconductor",
            "11AB", "Marvell", "126F", "Silicon Motion", "144D", "Samsung Electronics",
            "14E4", "Broadcom", "15AD", "VMware", "15B7", "Sandisk",
            "168C", "Qualcomm Atheros", "1969", "Qualcomm Atheros", "197B", "JMicron",
            "1AF4", "Red Hat (Virtio)", "1B21", "ASMedia", "1B4B", "Marvell",
            "1C5C", "SK hynix", "1CC1", "ADATA", "1D6A", "Aquantia", "1E0F", "KIOXIA",
            "2646", "Kingston Technology", "8086", "Intel Corporation",
            "8087", "Intel Corporation", "9005", "Adaptec",
        };
    }
}
