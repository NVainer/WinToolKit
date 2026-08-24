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
        private static ActionResult Dispatch(string[] args)
        {
            if (IsElevated())
            {
                ActionResult direct = PnpUtil.Run(args, 300000);
                direct.Elevated = true;
                return direct;
            }
            return RunElevated(args);
        }

        /// <summary>
        /// Runs pnputil through UAC, capturing output and the exit code.
        /// ShellExecute (which "runas" requires) cannot redirect streams, so an
        /// elevated cmd.exe writes to a temp file that this process reads back.
        /// </summary>
        public static ActionResult RunElevated(string[] args)
        {
            string outPath = Path.Combine(Path.GetTempPath(),
                "dcc_elev_" + Guid.NewGuid().ToString("N") + ".txt");
            ActionResult result = new ActionResult();
            result.Command = "pnputil " + PnpUtil.JoinArgs(args);
            result.Elevated = true;
            try
            {
                StringBuilder inner = new StringBuilder();
                inner.Append("/c ");
                inner.Append(Quote(PnpUtil.ExePath));
                for (int i = 0; i < args.Length; i++) { inner.Append(' ').Append(Quote(args[i])); }
                inner.Append(" > ").Append(Quote(outPath)).Append(" 2>&1");
                inner.Append(" & echo __DCC_EXIT__%ERRORLEVEL% >> ").Append(Quote(outPath));

                ProcessStartInfo psi = new ProcessStartInfo("cmd.exe", inner.ToString());
                psi.UseShellExecute = true;      // required for the runas verb
                psi.Verb = "runas";
                psi.WindowStyle = ProcessWindowStyle.Hidden;
                psi.CreateNoWindow = true;

                using (Process p = Process.Start(psi))
                {
                    if (!p.WaitForExit(600000))
                    {
                        result.Output = "the elevated command did not finish in time";
                        return result;
                    }
                }

                string text = "";
                try { if (File.Exists(outPath)) text = File.ReadAllText(outPath); }
                catch (IOException) { }

                Match m = Regex.Match(text, @"__DCC_EXIT__(-?\d+)");
                if (m.Success)
                {
                    result.ReturnCode = int.Parse(m.Groups[1].Value);
                    text = text.Substring(0, m.Index).TrimEnd();
                }
                result.Output = text.Trim().Length > 0 ? text.Trim() : "(no output)";
                result.Ok = result.ReturnCode == 0 || result.ReturnCode == 3010;
                result.RebootRequired = result.ReturnCode == 3010;
                return result;
            }
            catch (System.ComponentModel.Win32Exception)
            {
                // 1223 == ERROR_CANCELLED, i.e. the UAC prompt was declined.
                result.Output = "Elevation was cancelled.";
                result.ReturnCode = 1223;
                return result;
            }
            catch (Exception ex)
            {
                result.Output = ex.GetType().Name + ": " + ex.Message;
                return result;
            }
            finally
            {
                try { if (File.Exists(outPath)) File.Delete(outPath); } catch (IOException) { }
            }
        }

        private static string Quote(string arg)
        {
            return "\"" + arg.Replace("\"", "\"\"") + "\"";
        }

        // ----------------------------------------------------------- verbs
        public static ActionResult DeleteDriver(string oemInf, bool uninstall, bool force, bool reboot)
        {
            string name = ValidateOemInf(oemInf);
            List<string> args = new List<string>();
            args.Add("/delete-driver"); args.Add(name);
            if (uninstall) args.Add("/uninstall");
            if (force) args.Add("/force");
            if (reboot) args.Add("/reboot");
            return Dispatch(args.ToArray());
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
