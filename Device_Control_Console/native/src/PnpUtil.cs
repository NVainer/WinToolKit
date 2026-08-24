// pnputil.exe driver: enumeration through its XML output, plus write actions.
//
// XML rather than the printed text blocks, so the tool is not tied to the
// display language of the machine it runs on.  Enumeration goes through
// /output-file so the console code page cannot mangle non-ASCII names.
//
// Mirrors dcc/pnputil.py in the Python implementation.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Text;
using System.Xml;

namespace DeviceControlConsole
{
    public class PnpUtilException : Exception
    {
        public PnpUtilException(string message) : base(message) { }
    }

    public sealed class DriverPackage
    {
        public string DriverName = "";
        public string OriginalName = "";
        public string ProviderName = "";
        public string ClassName = "";
        public string ClassGuid = "";
        public string DriverVersion = "";
        public string SignerName = "";
        public string WhcpVersion = "";
        public string DriverPackageId = "";
        public string FamilyId = "";
        public List<string> Attributes = new List<string>();
        public List<string> DeviceIds = new List<string>();
    }

    public sealed class PnpDeviceRow
    {
        public string InstanceId = "";
        public string Description = "";
        public string ClassName = "";
        public string ClassGuid = "";
        public string Manufacturer = "";
        public string Status = "";
        public string DriverName = "";
        public List<string> ExtensionDrivers = new List<string>();
    }

    public sealed class ActionResult
    {
        public string Command = "";
        public int ReturnCode = -1;
        public bool Ok;
        public bool RebootRequired;
        public bool Elevated;
        public string Output = "";
        /// <summary>Set for batch deletions so the UI can name each result.</summary>
        public string DriverName = "";

        public Dictionary<string, object> ToMap()
        {
            Dictionary<string, object> m = Json.Obj();
            m["command"] = Command;
            m["returncode"] = ReturnCode;
            m["ok"] = Ok;
            m["reboot_required"] = RebootRequired;
            m["elevated"] = Elevated;
            m["output"] = Output;
            m["reason"] = ReturnCode == -1 ? "did not run" : PnpUtil.DescribeExitCode(ReturnCode);
            if (DriverName.Length > 0) m["driver_name"] = DriverName;
            return m;
        }
    }

    public static class PnpUtil
    {
        // pnputil returns SetupAPI codes, which surface as large negative
        // numbers. Only entries confirmed on a real machine (or plain Win32)
        // are named; the rest fall back to hex plus pnputil's own message.
        private static readonly Dictionary<int, string> ExitCodes = BuildExitCodes();

        private static Dictionary<int, string> BuildExitCodes()
        {
            Dictionary<int, string> m = new Dictionary<int, string>();
            m[0] = "succeeded";
            m[3010] = "succeeded, reboot required";
            m[2] = "file not found";
            m[5] = "access denied -- needs administrator";
            m[87] = "invalid parameter";
            m[1223] = "the UAC prompt was declined";
            m[-536870340] = "not an installed OEM INF (already deleted?)";  // 0xE000023C
            m[-536870339] = "still in use by the system";                   // 0xE000023D
            return m;
        }

        public static string DescribeExitCode(int code)
        {
            string text;
            if (ExitCodes.TryGetValue(code, out text)) return text;
            if (code < 0)
            {
                uint u = unchecked((uint)code);
                if (u >= 0xE0000000u && u <= 0xE0000FFFu)
                    return "SetupAPI error 0x" + u.ToString("X8");
                return "error 0x" + u.ToString("X8");
            }
            return "exit " + code;
        }

        /// <summary>Drops pnputil's banner so the real message is line one.</summary>
        public static string CleanOutput(string text)
        {
            if (string.IsNullOrEmpty(text)) return "";
            return System.Text.RegularExpressions.Regex.Replace(
                text, @"\A\s*Microsoft PnP Utility\s*\r?\n\s*\r?\n?", "",
                System.Text.RegularExpressions.RegexOptions.IgnoreCase).Trim();
        }

        public static string ExePath
        {
            get
            {
                string root = Environment.GetEnvironmentVariable("SystemRoot");
                if (string.IsNullOrEmpty(root)) root = "C:\\Windows";
                return Path.Combine(Path.Combine(root, "System32"), "pnputil.exe");
            }
        }

        public static bool Available()
        {
            return File.Exists(ExePath);
        }

        // -------------------------------------------------------- running
        public static ActionResult Run(string[] args, int timeoutMs)
        {
            ProcessStartInfo psi = new ProcessStartInfo(ExePath, JoinArgs(args));
            psi.UseShellExecute = false;
            psi.CreateNoWindow = true;
            psi.RedirectStandardOutput = true;
            psi.RedirectStandardError = true;
            psi.StandardOutputEncoding = Encoding.UTF8;
            psi.StandardErrorEncoding = Encoding.UTF8;

            ActionResult result = new ActionResult();
            result.Command = "pnputil " + JoinArgs(args);
            try
            {
                using (Process p = Process.Start(psi))
                {
                    string stdout = p.StandardOutput.ReadToEnd();
                    string stderr = p.StandardError.ReadToEnd();
                    if (!p.WaitForExit(timeoutMs))
                    {
                        try { p.Kill(); } catch (InvalidOperationException) { }
                        result.Output = "pnputil timed out";
                        return result;
                    }
                    result.ReturnCode = p.ExitCode;
                    string text = (stdout ?? "").Trim();
                    if (text.Length == 0) text = (stderr ?? "").Trim();
                    result.Output = CleanOutput(text);
                }
            }
            catch (Exception ex)
            {
                result.Output = ex.GetType().Name + ": " + ex.Message;
                return result;
            }
            result.Ok = result.ReturnCode == 0 || result.ReturnCode == 3010;
            result.RebootRequired = result.ReturnCode == 3010;
            return result;
        }

        public static string JoinArgs(string[] args)
        {
            StringBuilder sb = new StringBuilder();
            for (int i = 0; i < args.Length; i++)
            {
                if (i > 0) sb.Append(' ');
                string a = args[i];
                if (a.IndexOf(' ') >= 0 || a.IndexOf('"') >= 0)
                    sb.Append('"').Append(a.Replace("\"", "\\\"")).Append('"');
                else
                    sb.Append(a);
            }
            return sb.ToString();
        }

        private static XmlDocument RunXml(string[] args, int timeoutMs)
        {
            string path = Path.Combine(Path.GetTempPath(), "dcc_pnp_" + Guid.NewGuid().ToString("N") + ".xml");
            try
            {
                List<string> full = new List<string>(args);
                full.Add("/format"); full.Add("xml");
                full.Add("/output-file"); full.Add(path);
                ActionResult r = Run(full.ToArray(), timeoutMs);

                string text = "";
                try { if (File.Exists(path)) text = File.ReadAllText(path, Encoding.UTF8); }
                catch (IOException) { }
                // Older builds ignore /output-file for some verbs.
                if (text.Trim().Length == 0) text = r.Output;
                if (text.Trim().Length == 0)
                    throw new PnpUtilException("pnputil produced no output for " + JoinArgs(args));

                XmlDocument doc = new XmlDocument();
                doc.XmlResolver = null;
                try { doc.LoadXml(text); }
                catch (XmlException ex)
                {
                    throw new PnpUtilException("could not parse pnputil XML: " + ex.Message);
                }
                return doc;
            }
            finally
            {
                try { if (File.Exists(path)) File.Delete(path); } catch (IOException) { }
            }
        }

        private static string Text(XmlNode parent, string name)
        {
            if (parent == null) return "";
            XmlNode n = parent.SelectSingleNode(name);
            if (n == null || n.InnerText == null) return "";
            return n.InnerText.Trim();
        }

        private static string Attr(XmlNode node, string name)
        {
            if (node == null || node.Attributes == null) return "";
            XmlAttribute a = node.Attributes[name];
            return a == null ? "" : a.Value;
        }

        // ---------------------------------------------------- enumeration
        public static List<DriverPackage> EnumDrivers()
        {
            XmlDocument doc = RunXml(new string[] { "/enum-drivers", "/devices", "/ids" }, 300000);
            List<DriverPackage> list = new List<DriverPackage>();
            XmlNodeList nodes = doc.SelectNodes("/PnpUtil/Driver");
            if (nodes == null) return list;
            foreach (XmlNode node in nodes)
            {
                DriverPackage d = new DriverPackage();
                d.DriverName = Attr(node, "DriverName");
                d.OriginalName = Text(node, "OriginalName");
                d.ProviderName = Text(node, "ProviderName");
                d.ClassName = Text(node, "ClassName");
                d.ClassGuid = Text(node, "ClassGuid");
                d.DriverVersion = Text(node, "DriverVersion");
                d.SignerName = Text(node, "SignerName");
                d.WhcpVersion = Text(node, "WhcpVersion");
                d.DriverPackageId = Text(node, "DriverPackageId");
                d.FamilyId = Text(node, "FamilyId");

                XmlNodeList attrs = node.SelectNodes("CatalogAttributes/Attribute");
                if (attrs != null)
                    foreach (XmlNode a in attrs)
                        if (a.InnerText.Trim().Length > 0) d.Attributes.Add(a.InnerText.Trim());

                XmlNodeList devs = node.SelectNodes("Devices/Device");
                if (devs != null)
                    foreach (XmlNode dev in devs)
                    {
                        string id = Attr(dev, "InstanceId");
                        if (id.Length > 0) d.DeviceIds.Add(id);
                    }
                list.Add(d);
            }
            return list;
        }

        public static List<PnpDeviceRow> EnumDevices()
        {
            XmlDocument doc = RunXml(new string[] { "/enum-devices" }, 300000);
            List<PnpDeviceRow> list = new List<PnpDeviceRow>();
            XmlNodeList nodes = doc.SelectNodes("/PnpUtil/Device");
            if (nodes == null) return list;
            foreach (XmlNode node in nodes)
            {
                PnpDeviceRow d = new PnpDeviceRow();
                d.InstanceId = Attr(node, "InstanceId");
                d.Description = Text(node, "DeviceDescription");
                d.ClassName = Text(node, "ClassName");
                d.ClassGuid = Text(node, "ClassGuid");
                d.Manufacturer = Text(node, "ManufacturerName");
                d.Status = Text(node, "Status");
                d.DriverName = Text(node, "DriverName");
                XmlNodeList ext = node.SelectNodes("ExtensionDriverNames/DriverName");
                if (ext != null)
                    foreach (XmlNode e in ext)
                        if (e.InnerText.Trim().Length > 0) d.ExtensionDrivers.Add(e.InnerText.Trim());
                list.Add(d);
            }
            return list;
        }
    }
}
