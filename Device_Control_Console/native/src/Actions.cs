// Write operations, elevation, and the guard rails around them.
//
// Nothing here interpolates untrusted text into a command line: instance IDs
// must match a device in the current snapshot, INF names must match
// oem<n>.inf, and paths are resolved and existence-checked before use.
//
// Mirrors dcc/actions.py in the Python implementation.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Security.Principal;
using System.Text;
using System.Text.RegularExpressions;

namespace DeviceControlConsole
{
    public class ActionException : Exception
    {
        public ActionException(string message) : base(message) { }
    }

    public static class Actions
    {
        private static readonly Regex OemInfRe =
            new Regex(@"^oem\d+\.inf$", RegexOptions.IgnoreCase | RegexOptions.Compiled);
        private static readonly Regex InstanceIdRe =
            new Regex(@"^[A-Za-z0-9_\-.\\{}&#+ ]{3,400}$", RegexOptions.Compiled);

        public static readonly string[] SafeDeviceVerbs =
            { "enable-device", "disable-device", "restart-device", "remove-device" };

        private static bool? _elevated;

        public static bool IsElevated()
        {
            if (_elevated.HasValue) return _elevated.Value;
            try
            {
                using (WindowsIdentity identity = WindowsIdentity.GetCurrent())
                {
                    WindowsPrincipal principal = new WindowsPrincipal(identity);
                    _elevated = principal.IsInRole(WindowsBuiltInRole.Administrator);
                }
            }
            catch (Exception) { _elevated = false; }
            return _elevated.Value;
        }

        // -------------------------------------------------------- validation
        public static string ValidateOemInf(string name)
        {
            string trimmed = (name ?? "").Trim();
            if (!OemInfRe.IsMatch(trimmed))
                throw new ActionException("'" + trimmed +
                    "' is not a driver-store package name; expected e.g. oem42.inf");
            return trimmed.ToLowerInvariant();
        }

        public static string ValidateInstanceId(string instanceId, ICollection<string> known)
        {
            string trimmed = (instanceId ?? "").Trim();
            if (!InstanceIdRe.IsMatch(trimmed))
                throw new ActionException("'" + trimmed + "' is not a valid device instance ID");
            if (known != null && !known.Contains(trimmed))
                throw new ActionException("'" + trimmed +
                    "' is not in the current snapshot; refresh and retry");
            return trimmed;
        }

        public static string ValidateDirectory(string path)
        {
            string expanded = Environment.ExpandEnvironmentVariables((path ?? "").Trim());
            string full;
            try { full = Path.GetFullPath(expanded); }
            catch (Exception) { throw new ActionException("'" + path + "' is not a usable path"); }
            if (!Directory.Exists(full))
                throw new ActionException("'" + full + "' is not an existing directory");
            return full;
        }

        // --------------------------------------------------------- dispatch
        /// <summary>Runs a batch, elevating once for the whole thing when needed.</summary>
        public static List<ActionResult> DispatchMany(List<string[]> commands)
        {
            if (commands == null || commands.Count == 0) return new List<ActionResult>();
            if (IsElevated())
            {
                List<ActionResult> results = new List<ActionResult>();
                foreach (string[] args in commands)
                {
                    ActionResult direct = PnpUtil.Run(args, 300000);
                    direct.Elevated = true;
                    results.Add(direct);
                }
                return results;
            }
            return RunElevated(commands);
        }

        private static ActionResult Dispatch(string[] args)
        {
            List<string[]> one = new List<string[]>();
            one.Add(args);
            return DispatchMany(one)[0];
        }

        private const string ItemMark = "__DCC_ITEM__";

        /// <summary>
        /// A .cmd that runs each pnputil call and records its own exit code.
        ///
        /// Handing the whole pipeline to <c>cmd /c</c> as a single argument does
        /// not survive cmd's quote-stripping rule: a string beginning with a
        /// quote and containing several more comes back as "The filename,
        /// directory name, or volume label syntax is incorrect". A script file
        /// has no such rule, and it lets a batch run behind one UAC prompt
        /// rather than one prompt per package.
        /// </summary>
        private static string WriteBatchScript(List<string[]> commands, string outPath)
        {
            string script = Path.Combine(Path.GetTempPath(),
                "dcc_run_" + Guid.NewGuid().ToString("N") + ".cmd");
            StringBuilder sb = new StringBuilder();
            sb.Append("@echo off\r\n");
            for (int i = 0; i < commands.Count; i++)
            {
                sb.Append("echo.>> ").Append(Quote(outPath)).Append("\r\n");
                sb.Append(Quote(PnpUtil.ExePath));
                foreach (string a in commands[i]) sb.Append(' ').Append(Quote(a));
                sb.Append(" >> ").Append(Quote(outPath)).Append(" 2>&1\r\n");
                // %ERRORLEVEL% expands as each line is read, so this catches the
                // call immediately above it.
                sb.Append("echo ").Append(ItemMark).Append(i).Append(":%ERRORLEVEL%>> ")
                  .Append(Quote(outPath)).Append("\r\n");
            }
            File.WriteAllText(script, sb.ToString(), Encoding.ASCII);
            return script;
        }

        private static List<ActionResult> SplitBatchOutput(string text, List<string[]> commands)
        {
            List<ActionResult> results = new List<ActionResult>();
            Dictionary<int, int> codes = new Dictionary<int, int>();
            Dictionary<int, string> bodies = new Dictionary<int, string>();
            int cursor = 0;
            foreach (Match m in Regex.Matches(text, ItemMark + @"(\d+):(-?\d+)"))
            {
                int index = int.Parse(m.Groups[1].Value);
                codes[index] = int.Parse(m.Groups[2].Value);
                bodies[index] = text.Substring(cursor, m.Index - cursor);
                cursor = m.Index + m.Length;
            }
            for (int i = 0; i < commands.Count; i++)
            {
                ActionResult r = new ActionResult();
                r.Command = "pnputil " + PnpUtil.JoinArgs(commands[i]);
                r.Elevated = true;
                r.ReturnCode = codes.ContainsKey(i) ? codes[i] : -1;
                r.Ok = r.ReturnCode == 0 || r.ReturnCode == 3010;
                r.RebootRequired = r.ReturnCode == 3010;
                string body = bodies.ContainsKey(i) ? bodies[i].Trim() : "";
                if (body.Length == 0) body = r.ReturnCode == -1 ? "did not run" : "(no output)";
                r.Output = body;
                results.Add(r);
            }
            return results;
        }

        private static List<ActionResult> Cancelled(List<string[]> commands, string why)
        {
            List<ActionResult> results = new List<ActionResult>();
            foreach (string[] args in commands)
            {
                ActionResult r = new ActionResult();
                r.Command = "pnputil " + PnpUtil.JoinArgs(args);
                r.Elevated = true;
                r.ReturnCode = 1223;   // ERROR_CANCELLED
                r.Output = why;
                results.Add(r);
            }
            return results;
        }

        /// <summary>Runs one or more pnputil calls through a single UAC prompt.</summary>
        public static List<ActionResult> RunElevated(List<string[]> commands)
        {
            string outPath = Path.Combine(Path.GetTempPath(),
                "dcc_elev_" + Guid.NewGuid().ToString("N") + ".txt");
            string script = null;
            try
            {
                File.WriteAllText(outPath, "");
                script = WriteBatchScript(commands, outPath);

                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", "/c " + Quote(script));
                psi.UseShellExecute = true;      // required for the runas verb
                psi.Verb = "runas";
                psi.WindowStyle = ProcessWindowStyle.Hidden;

                using (Process p = Process.Start(psi))
                {
                    if (!p.WaitForExit(900000))
                        return Cancelled(commands, "the elevated command did not finish in time");
                }

                string text = "";
                try { if (File.Exists(outPath)) text = File.ReadAllText(outPath); }
                catch (IOException) { }

                if (text.IndexOf(ItemMark, StringComparison.Ordinal) < 0)
                    return Cancelled(commands, "Elevation was cancelled.");
                return SplitBatchOutput(text, commands);
            }
            catch (System.ComponentModel.Win32Exception)
            {
                return Cancelled(commands, "Elevation was cancelled.");
            }
            catch (Exception ex)
            {
                return Cancelled(commands, ex.GetType().Name + ": " + ex.Message);
            }
            finally
            {
                try { if (File.Exists(outPath)) File.Delete(outPath); } catch (IOException) { }
                try { if (script != null && File.Exists(script)) File.Delete(script); } catch (IOException) { }
            }
        }

        private static string Quote(string arg)
        {
            return "\"" + arg.Replace("\"", "\"\"") + "\"";
        }

        // ----------------------------------------------------------- verbs
        private static string[] DeleteArgs(string name, bool uninstall, bool force, bool reboot)
        {
            List<string> args = new List<string>();
            args.Add("/delete-driver"); args.Add(name);
            if (uninstall) args.Add("/uninstall");
            if (force) args.Add("/force");
            if (reboot) args.Add("/reboot");
            return args.ToArray();
        }

        public static ActionResult DeleteDriver(string oemInf, bool uninstall, bool force, bool reboot)
        {
            return Dispatch(DeleteArgs(ValidateOemInf(oemInf), uninstall, force, reboot));
        }

        /// <summary>
        /// Deletes several packages behind one UAC prompt. Every name is
        /// validated before anything runs, so one bad entry cannot leave half a
        /// batch deleted.
        /// </summary>
        public static List<ActionResult> DeleteDrivers(List<string> oemInfs, bool uninstall,
            bool force, bool reboot)
        {
            if (oemInfs == null || oemInfs.Count == 0)
                throw new ActionException("no driver packages given");
            List<string> names = new List<string>();
            foreach (string raw in oemInfs) names.Add(ValidateOemInf(raw));

            List<string[]> commands = new List<string[]>();
            foreach (string name in names) commands.Add(DeleteArgs(name, uninstall, force, reboot));

            List<ActionResult> results = DispatchMany(commands);
            for (int i = 0; i < results.Count && i < names.Count; i++) results[i].DriverName = names[i];
            return results;
        }

        public static ActionResult ExportDriver(string oemInf, string targetDir)
        {
            string name = ValidateOemInf(oemInf);
            string target = ValidateDirectory(targetDir);
            return Dispatch(new string[] { "/export-driver", name, target });
        }

        public static ActionResult AddDriver(string infPath, bool subdirs, bool install)
        {
            string expanded = Environment.ExpandEnvironmentVariables((infPath ?? "").Trim());
            string full;
            try { full = Path.GetFullPath(expanded); }
            catch (Exception) { throw new ActionException("'" + infPath + "' is not a usable path"); }
            if (!full.EndsWith(".inf", StringComparison.OrdinalIgnoreCase) || !File.Exists(full))
                throw new ActionException("'" + full + "' is not an existing .inf file");
            List<string> args = new List<string>();
            args.Add("/add-driver"); args.Add(full);
            if (subdirs) args.Add("/subdirs");
            if (install) args.Add("/install");
            return Dispatch(args.ToArray());
        }

        public static ActionResult DeviceAction(string verb, string instanceId,
            ICollection<string> known, bool subtree)
        {
            bool allowed = false;
            foreach (string v in SafeDeviceVerbs) if (v == verb) { allowed = true; break; }
            if (!allowed) throw new ActionException("unsupported device action '" + verb + "'");
            string id = ValidateInstanceId(instanceId, known);
            List<string> args = new List<string>();
            args.Add("/" + verb); args.Add(id);
            if (verb == "remove-device" && subtree) args.Add("/subtree");
            return Dispatch(args.ToArray());
        }

        public static ActionResult ScanDevices()
        {
            return Dispatch(new string[] { "/scan-devices" });
        }
    }
}
