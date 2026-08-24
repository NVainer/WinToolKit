// Entry point: the local console, plus the same command line as the Python
// build.  Single self-contained executable -- the web UI is embedded.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Threading;

namespace DeviceControlConsole
{
    public static class Program
    {
        public const string Version = "1.0.0";
        private const string Host = "127.0.0.1";

        [STAThread]
        public static int Main(string[] args)
        {
            try { return Run(args); }
            catch (ActionException ex) { Console.Error.WriteLine("error: " + ex.Message); return 2; }
            catch (PnpUtilException ex) { Console.Error.WriteLine("error: " + ex.Message); return 2; }
        }

        private static int Run(string[] args)
        {
            string command = "serve";
            List<string> rest = new List<string>();
            for (int i = 0; i < args.Length; i++)
            {
                if (i == 0 && !args[i].StartsWith("-", StringComparison.Ordinal)) command = args[i].ToLowerInvariant();
                else rest.Add(args[i]);
            }
            if (command == "-h" || command == "--help" || command == "/?" || command == "help")
            {
                PrintHelp();
                return 0;
            }

            switch (command)
            {
                case "serve": return CmdServe(rest);
                case "devices": return CmdDevices(rest);
                case "drivers": return CmdDrivers(rest);
                case "resolve": return CmdResolve(rest);
                case "orphans": return CmdOrphans(rest);
                case "tree": return CmdTree(rest);
                case "status": return CmdStatus();
                case "update-hwids": return CmdUpdateHwids();
                case "delete-driver": return CmdDeleteDriver(rest);
                case "enable-device":
                case "disable-device":
                case "restart-device":
                case "remove-device": return CmdDeviceAction(command, rest);
                default:
                    Console.Error.WriteLine("unknown command '" + command + "'");
                    PrintHelp();
                    return 2;
            }
        }

        private static void PrintHelp()
        {
            Console.WriteLine("Device Control Console " + Version + " (native build)");
            Console.WriteLine();
            Console.WriteLine("  DeviceControlConsole.exe [command] [options]");
            Console.WriteLine();
            Console.WriteLine("Commands:");
            Console.WriteLine("  serve                     run the local web console (default)");
            Console.WriteLine("      --port <n>            listen on this port (default 8777)");
            Console.WriteLine("      --no-browser          do not open a browser");
            Console.WriteLine("      --token-file <path>   read the session token from a file, then delete it");
            Console.WriteLine("  devices [search]          list devices with resolved names");
            Console.WriteLine("      --status connected|disconnected|problem");
            Console.WriteLine("      --class <name>  --type <name>  --limit <n>  --csv <path>");
            Console.WriteLine("  drivers [search]          list driver-store packages");
            Console.WriteLine("      --state inuse|orphaned|superseded|extension");
            Console.WriteLine("  resolve <query>           resolve an instance ID to the real device");
            Console.WriteLine("      --relations           also print children and related hardware");
            Console.WriteLine("  orphans [--superseded]    packages no device is using");
            Console.WriteLine("  tree [--depth <n>]        device tree with resolved names");
            Console.WriteLine("  delete-driver <oem#.inf> [--uninstall] [--force] [--reboot] [-y]");
            Console.WriteLine("  enable-device | disable-device | restart-device | remove-device <id>");
            Console.WriteLine("  update-hwids              download usb.ids / pci.ids");
            Console.WriteLine("  status                    JSON summary of the machine");
        }

        // ------------------------------------------------------ option help
        private static string Opt(List<string> args, string name, string fallback)
        {
            for (int i = 0; i < args.Count - 1; i++)
                if (string.Equals(args[i], name, StringComparison.OrdinalIgnoreCase)) return args[i + 1];
            return fallback;
        }

        private static bool Has(List<string> args, string name)
        {
            foreach (string a in args)
                if (string.Equals(a, name, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static string Positional(List<string> args)
        {
            for (int i = 0; i < args.Count; i++)
            {
                if (args[i].StartsWith("-", StringComparison.Ordinal)) { i++; continue; }
                return args[i];
            }
            return "";
        }

        private static int IntOpt(List<string> args, string name, int fallback)
        {
            int value;
            if (int.TryParse(Opt(args, name, ""), NumberStyles.Integer,
                    CultureInfo.InvariantCulture, out value)) return value;
            return fallback;
        }

        // ---------------------------------------------------------- serve
        private static int CmdServe(List<string> args)
        {
            int port = IntOpt(args, "--port", 8777);
            bool openBrowser = !Has(args, "--no-browser");

            string tokenFile = Opt(args, "--token-file", "");
            string token = null;
            if (tokenFile.Length > 0)
            {
                // Written by the instance that asked for elevation; read once, then gone.
                try { token = File.ReadAllText(tokenFile).Trim(); }
                catch (IOException) { token = null; }
                try { if (File.Exists(tokenFile)) File.Delete(tokenFile); } catch (IOException) { }
                if (token != null && token.Length == 0) token = null;
            }
            Api.Token = token != null ? token : NewToken();

            string url = "http://" + Host + ":" + port + "/?token=" + Api.Token;
            Console.WriteLine("Device Control Console " + Version + " (native)");
            Console.WriteLine("  URL         : " + url);
            Console.WriteLine("  Elevated    : " + (Actions.IsElevated()
                ? "yes" : "no (write actions will prompt for UAC)"));
            Console.WriteLine("  Stop        : Ctrl+C");
            Console.Out.Flush();

            ThreadPool.QueueUserWorkItem(delegate (object unused)
            {
                try { Api.Cache.Get(true); } catch (Exception) { }
            });

            if (openBrowser)
            {
                string target = url;
                ThreadPool.QueueUserWorkItem(delegate (object unused)
                {
                    Thread.Sleep(400);
                    try
                    {
                        ProcessStartInfo psi = new ProcessStartInfo(target);
                        psi.UseShellExecute = true;
                        Process.Start(psi);
                    }
                    catch (Exception) { }
                });
            }

            while (true)
            {
                HttpServer server = new HttpServer(Host, port, Api.Route);
                try { server.Bind(40, 400); }
                catch (IOException ex) { Console.Error.WriteLine(ex.Message); return 1; }
                Api.Server = server;
                server.Serve();
                server.Stop();

                if (!Api.RestartElevatedRequested) return 0;
                Api.RestartElevatedRequested = false;

                Console.WriteLine("  handing over to an elevated instance...");
                Console.Out.Flush();
                if (SpawnElevated(port, Api.Token) && WaitForPort(port, 40000))
                {
                    Console.WriteLine("  elevated instance is serving; this one is done.");
                    return 0;
                }
                // UAC declined, or the child never came up: take the port back
                // so the page the user is looking at keeps working.
                Api.ElevationDeclined = true;
                Console.WriteLine("  elevation did not complete; continuing as standard user.");
                Console.Out.Flush();
            }
        }

        private static string NewToken()
        {
            byte[] raw = new byte[24];
            using (RNGCryptoServiceProvider rng = new RNGCryptoServiceProvider()) rng.GetBytes(raw);
            return Convert.ToBase64String(raw).Replace('+', '-').Replace('/', '_').TrimEnd('=');
        }

        /// <summary>
        /// Starts an elevated copy on the same port and token.  The token goes
        /// through a short-lived file, never the command line, so it cannot be
        /// read out of the process list.
        /// </summary>
        private static bool SpawnElevated(int port, string token)
        {
            string tokenFile = Path.Combine(Path.GetTempPath(),
                "dcc_tok_" + Guid.NewGuid().ToString("N") + ".txt");
            try
            {
                File.WriteAllText(tokenFile, token);
                string exe = Assembly.GetExecutingAssembly().Location;
                string arguments = "serve --port " + port + " --no-browser --token-file \"" + tokenFile + "\"";

                ProcessStartInfo psi = new ProcessStartInfo(exe, arguments);
                psi.UseShellExecute = true;      // required for the runas verb
                psi.Verb = "runas";
                psi.WorkingDirectory = Path.GetDirectoryName(exe);
                Process.Start(psi);
                return true;
            }
            catch (Exception)
            {
                try { if (File.Exists(tokenFile)) File.Delete(tokenFile); } catch (IOException) { }
                return false;
            }
        }

        private static bool WaitForPort(int port, int timeoutMs)
        {
            DateTime deadline = DateTime.UtcNow.AddMilliseconds(timeoutMs);
            while (DateTime.UtcNow < deadline)
            {
                try
                {
                    using (System.Net.Sockets.TcpClient probe = new System.Net.Sockets.TcpClient())
                    {
                        IAsyncResult ar = probe.BeginConnect(Host, port, null, null);
                        if (ar.AsyncWaitHandle.WaitOne(400) && probe.Connected)
                        {
                            probe.EndConnect(ar);
                            return true;
                        }
                    }
                }
                catch (Exception) { }
                Thread.Sleep(300);
            }
            return false;
        }

        // ------------------------------------------------------------ CLI
        private static bool Matches(string blob, string needle)
        {
            if (string.IsNullOrEmpty(needle)) return true;
            foreach (string term in needle.ToLowerInvariant().Split(' '))
            {
                if (term.Length == 0) continue;
                if (blob.IndexOf(term, StringComparison.Ordinal) < 0) return false;
            }
            return true;
        }

        private static void Table(List<string[]> rows, string[] headers, int limit)
        {
            if (rows.Count == 0) { Console.WriteLine("(no matching rows)"); return; }
            int shown = limit > 0 && limit < rows.Count ? limit : rows.Count;
            int[] widths = new int[headers.Length];
            for (int i = 0; i < headers.Length; i++) widths[i] = headers[i].Length;
            for (int r = 0; r < shown; r++)
                for (int i = 0; i < headers.Length && i < rows[r].Length; i++)
                    widths[i] = Math.Max(widths[i], (rows[r][i] ?? "").Length);
            for (int i = 0; i < widths.Length; i++) widths[i] = Math.Min(widths[i], 58);

            Console.WriteLine(Line(headers, widths));
            string[] rule = new string[headers.Length];
            for (int i = 0; i < headers.Length; i++) rule[i] = new string('-', widths[i]);
            Console.WriteLine(Line(rule, widths));
            for (int r = 0; r < shown; r++) Console.WriteLine(Line(rows[r], widths));
            if (shown < rows.Count)
                Console.WriteLine("... " + (rows.Count - shown) + " more (use --limit 0 to show all)");
        }

        private static string Line(string[] cells, int[] widths)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < widths.Length; i++)
            {
                if (i > 0) sb.Append("  ");
                string cell = i < cells.Length ? (cells[i] ?? "") : "";
                if (cell.Length > widths[i]) cell = cell.Substring(0, widths[i]);
                sb.Append(cell.PadRight(widths[i]));
            }
            return sb.ToString().TrimEnd();
        }

        private static int CmdDevices(List<string> args)
        {
            Snapshot snap = Model.Build();
            string search = Positional(args);
            string status = Opt(args, "--status", "all");
            string klass = Opt(args, "--class", "");
            string type = Opt(args, "--type", "");
            int limit = IntOpt(args, "--limit", 60);

            List<Device> rows = new List<Device>();
            foreach (Device d in snap.Devices)
            {
                if (!Matches(d.SearchBlob, search)) continue;
                if (status == "connected" && !d.Present) continue;
                if (status == "disconnected" && d.Present) continue;
                if (status == "problem" && d.ProblemCode == 0) continue;
                if (klass.Length > 0 && !string.Equals(d.ClassName, klass, StringComparison.OrdinalIgnoreCase)) continue;
                if (type.Length > 0 && d.DeviceType.ToLowerInvariant().IndexOf(type.ToLowerInvariant(), StringComparison.Ordinal) < 0) continue;
                rows.Add(d);
            }
            rows.Sort(delegate (Device a, Device b)
            { return string.Compare(a.ResolvedName, b.ResolvedName, StringComparison.OrdinalIgnoreCase); });

            string csv = Opt(args, "--csv", "");
            if (csv.Length > 0)
            {
                StringBuilder sb = new StringBuilder();
                sb.Append("Type,Resolved Device,Instance ID,Status,Driver,Class GUID\r\n");
                foreach (Device d in rows)
                    sb.Append(Csv(d.DeviceType)).Append(',').Append(Csv(d.ResolvedName)).Append(',')
                      .Append(Csv(d.InstanceId)).Append(',').Append(Csv(d.Status)).Append(',')
                      .Append(Csv(d.DriverName)).Append(',').Append(Csv(d.ClassGuid)).Append("\r\n");
                File.WriteAllText(csv, sb.ToString(), new UTF8Encoding(true));
                Console.WriteLine("wrote " + rows.Count + " rows to " + csv);
                return 0;
            }

            List<string[]> table = new List<string[]>();
            foreach (Device d in rows)
                table.Add(new string[] { d.DeviceType, d.ResolvedName, d.InstanceId, d.Status, d.DriverName });
            Table(table, new string[] { "TYPE", "RESOLVED DEVICE", "INSTANCE ID", "STATUS", "DRIVER" }, limit);
            Console.WriteLine();
            Console.WriteLine(rows.Count + " device(s) of " + snap.Devices.Count);
            return 0;
        }

        private static string Csv(string value)
        {
            if (value == null) value = "";
            if (value.IndexOf(',') >= 0 || value.IndexOf('"') >= 0)
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            return value;
        }

        private static int CmdDrivers(List<string> args)
        {
            Snapshot snap = Model.Build();
            string search = Positional(args);
            string state = Opt(args, "--state", "all");
            int limit = IntOpt(args, "--limit", 60);

            List<DriverEntry> rows = new List<DriverEntry>();
            foreach (DriverEntry e in snap.Drivers)
            {
                if (!Matches(e.SearchBlob, search)) continue;
                if (state == "orphaned" && !e.Orphaned) continue;
                if (state == "inuse" && e.Orphaned) continue;
                if (state == "superseded" && e.SupersededBy.Length == 0) continue;
                if (state == "extension" && !e.IsExtension) continue;
                rows.Add(e);
            }
            List<string[]> table = new List<string[]>();
            foreach (DriverEntry e in rows)
                table.Add(new string[] { e.Package.DriverName, e.Package.OriginalName,
                    e.Package.ProviderName, e.Package.ClassName, e.Package.DriverVersion,
                    e.DeviceIds.Count.ToString(CultureInfo.InvariantCulture), e.SupersededBy });
            Table(table, new string[] { "PUBLISHED", "ORIGINAL", "PROVIDER", "CLASS",
                "VERSION", "DEVICES", "SUPERSEDED BY" }, limit);
            Dictionary<string, object> meta = snap.Meta();
            Console.WriteLine();
            Console.WriteLine(rows.Count + " package(s) of " + meta["driver_count"]
                + " (" + meta["orphan_driver_count"] + " orphaned, "
                + meta["superseded_driver_count"] + " superseded)");
            return 0;
        }

        private static int CmdResolve(List<string> args)
        {
            string query = Positional(args);
            if (query.Length == 0) { Console.Error.WriteLine("resolve needs a query"); return 2; }
            Snapshot snap = Model.Build();
            bool relations = Has(args, "--relations");
            int limit = IntOpt(args, "--limit", 5);

            List<Device> hits = new List<Device>();
            foreach (Device d in snap.Devices)
                if (string.Equals(d.InstanceId, query, StringComparison.OrdinalIgnoreCase)) hits.Add(d);
            if (hits.Count == 0)
                foreach (Device d in snap.Devices)
                    if (Matches(d.SearchBlob, query.ToLowerInvariant())) hits.Add(d);
            if (hits.Count == 0) { Console.WriteLine("no device matches '" + query + "'"); return 1; }

            int shown = 0;
            foreach (Device d in hits)
            {
                if (limit > 0 && shown >= limit) break;
                shown++;
                Console.WriteLine();
                Console.WriteLine("Instance ID:                " + d.InstanceId);
                Console.WriteLine("  >> Resolved device:       " + d.ResolvedName
                    + "  [" + d.ResolvedConfidence + " confidence]");
                Console.WriteLine("  >> via:                   " + d.ResolvedFrom);
                Console.WriteLine("  >> Type:                  " + d.DeviceType + "  (" + d.TypeFrom + ")");
                Console.WriteLine("  >> Vendor:                " + d.Vendor);
                Console.WriteLine("Device Description:         " + d.Description);
                Console.WriteLine("Class Name:                 " + d.ClassName);
                Console.WriteLine("Class GUID:                 " + d.ClassGuid);
                Console.WriteLine("Manufacturer Name:          " + d.Manufacturer);
                Console.WriteLine("Status:                     " + d.Status
                    + (d.ProblemCode != 0 ? "  (problem " + d.ProblemCode + ": " + d.ProblemText + ")" : ""));
                if (d.DriverName.Length > 0)
                    Console.WriteLine("Driver Name:                " + d.DriverName);
                if (d.ExtensionDrivers.Count > 0)
                    Console.WriteLine("Extension Driver Names:     " + string.Join(", ", d.ExtensionDrivers.ToArray()));
                if (relations)
                {
                    if (d.Children.Count > 0)
                    {
                        Console.WriteLine("Children:");
                        foreach (string c in d.Children)
                        {
                            Device kid;
                            string name = snap.DeviceIndex.TryGetValue(c, out kid) ? kid.ResolvedName : "?";
                            Console.WriteLine("    " + name.PadRight(44) + " " + c);
                        }
                    }
                    if (d.Related.Count > 0)
                    {
                        Console.WriteLine("Related hardware:");
                        int n = 0;
                        foreach (string r in d.Related)
                        {
                            if (n++ >= 12) break;
                            Device rel;
                            string name = snap.DeviceIndex.TryGetValue(r, out rel) ? rel.ResolvedName : "?";
                            Console.WriteLine("    " + name.PadRight(44) + " " + r);
                        }
                    }
                }
            }
            Console.WriteLine();
            if (hits.Count > shown) Console.WriteLine("(" + hits.Count + " matches, showing " + shown + ")");
            return 0;
        }

        private static int CmdOrphans(List<string> args)
        {
            Snapshot snap = Model.Build();
            bool superseded = Has(args, "--superseded");
            int limit = IntOpt(args, "--limit", 0);
            List<string[]> table = new List<string[]>();
            int orphans = 0;
            foreach (DriverEntry e in snap.Drivers)
            {
                if (e.Orphaned) orphans++;
                if (!e.Orphaned && !(superseded && e.SupersededBy.Length > 0)) continue;
                table.Add(new string[] { e.Package.DriverName, e.Package.OriginalName,
                    e.Package.ProviderName, e.Package.ClassName, e.Package.DriverVersion,
                    e.DeviceIds.Count.ToString(CultureInfo.InvariantCulture), e.SupersededBy });
            }
            Table(table, new string[] { "PUBLISHED", "ORIGINAL", "PROVIDER", "CLASS",
                "VERSION", "DEVICES", "SUPERSEDED BY" }, limit);
            Console.WriteLine();
            Console.WriteLine(table.Count + " candidate(s); " + orphans + " package(s) have no device attached.");
            Console.WriteLine("Delete one with:  DeviceControlConsole.exe delete-driver oem42.inf");
            return 0;
        }

        private static int CmdTree(List<string> args)
        {
            Snapshot snap = Model.Build();
            int depth = IntOpt(args, "--depth", 4);
            List<Device> roots = new List<Device>();
            foreach (Device d in snap.Devices)
                if (d.Parent.Length == 0 || !snap.DeviceIndex.ContainsKey(d.Parent)) roots.Add(d);
            roots.Sort(delegate (Device a, Device b)
            { return string.Compare(a.ResolvedName, b.ResolvedName, StringComparison.OrdinalIgnoreCase); });
            foreach (Device root in roots) Walk(snap, root, 0, depth);
            return 0;
        }

        private static void Walk(Snapshot snap, Device dev, int level, int maxDepth)
        {
            if (level > maxDepth) return;
            string pad = new string(' ', level * 2);
            Console.WriteLine(pad + dev.ResolvedName + "  (" + dev.DeviceType + ")"
                + (dev.Present ? "" : "  [disconnected]"));
            Console.WriteLine(pad + "   " + dev.InstanceId);
            List<string> children = snap.Resolver.ChildrenOf(dev.InstanceId);
            children.Sort(StringComparer.OrdinalIgnoreCase);
            foreach (string c in children)
            {
                Device kid;
                if (snap.DeviceIndex.TryGetValue(c, out kid)) Walk(snap, kid, level + 1, maxDepth);
            }
        }

        private static int CmdStatus()
        {
            Snapshot snap = Model.Build();
            Dictionary<string, object> meta = snap.Meta();
            meta["elevated"] = Actions.IsElevated();
            meta["hwids"] = HwDb.Status();
            meta["backend"] = "native";
            Console.WriteLine(Json.Write(meta));
            return 0;
        }

        private static int CmdUpdateHwids()
        {
            Console.WriteLine("downloading usb.ids and pci.ids ...");
            Dictionary<string, object> results = HwDb.Update(null);
            foreach (KeyValuePair<string, object> kv in results)
            {
                Dictionary<string, object> r = (Dictionary<string, object>)kv.Value;
                if (Json.Flag(r, "ok"))
                    Console.WriteLine("  " + kv.Key + ": " + r["bytes"] + " bytes, " + r["vendors"] + " vendors");
                else
                    Console.WriteLine("  " + kv.Key + ": FAILED -- " + Json.Str(r, "error"));
            }
            Console.WriteLine("cache: " + HwDb.CacheDir);
            return 0;
        }

        private static int CmdDeleteDriver(List<string> args)
        {
            string name = Positional(args);
            if (name.Length == 0) { Console.Error.WriteLine("delete-driver needs an oem#.inf name"); return 2; }
            Snapshot snap = Model.Build();
            DriverEntry pkg;
            if (!snap.DriverIndex.TryGetValue(name, out pkg))
            {
                Console.WriteLine(name + " is not in the driver store");
                return 1;
            }
            Console.WriteLine(pkg.Package.DriverName + "  " + pkg.Package.OriginalName + "  ("
                + pkg.Package.ProviderName + ", " + pkg.Package.DriverVersion + ") -- used by "
                + pkg.DeviceIds.Count + " device(s)");
            if (!Has(args, "-y") && !Has(args, "--yes"))
            {
                Console.Write("Delete this package from the driver store? [y/N] ");
                string answer = (Console.ReadLine() ?? "").Trim().ToLowerInvariant();
                if (answer != "y" && answer != "yes") { Console.WriteLine("aborted"); return 1; }
            }
            ActionResult r = Actions.DeleteDriver(name, Has(args, "--uninstall"),
                Has(args, "--force"), Has(args, "--reboot"));
            Console.WriteLine(r.Output);
            Console.WriteLine("exit " + r.ReturnCode + (r.RebootRequired ? " (reboot required)" : ""));
            return r.Ok ? 0 : 2;
        }

        private static int CmdDeviceAction(string verb, List<string> args)
        {
            string id = Positional(args);
            if (id.Length == 0) { Console.Error.WriteLine(verb + " needs an instance ID"); return 2; }
            Snapshot snap = Model.Build();
            ActionResult r = Actions.DeviceAction(verb, id, snap.DeviceIndex.Keys, Has(args, "--subtree"));
            Console.WriteLine(r.Output);
            return r.Ok ? 0 : 2;
        }
    }
}
