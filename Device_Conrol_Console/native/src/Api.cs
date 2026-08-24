// Request routing and the JSON API.  Same endpoints and shapes as the Python
// server, so dcc/web/* is shared verbatim between the two implementations.
using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

namespace DeviceControlConsole
{
    public sealed class ApiException : Exception
    {
        public readonly int Status;
        public ApiException(string message, int status) : base(message) { Status = status; }
    }

    public static class Api
    {
        public static readonly SnapshotCache Cache = new SnapshotCache();
        public static string Token = "";
        public static bool RestartElevatedRequested;
        public static bool ElevationDeclined;
        public static HttpServer Server;

        /// <summary>Set by the host so progress shows in the console window.</summary>
        public static Action<string> Log = delegate (string message) { };
        private static int _pageLoads;

        private static readonly string[] AllowedHosts = { "127.0.0.1", "localhost", "[::1]" };

        // ------------------------------------------------------- routing
        public static Response Route(Request req)
        {
            if (!HostOk(req)) return Response.Error("bad host", 403);

            try
            {
                if (req.Path == "/" || req.Path == "/index.html") return ServeIndex();
                if (req.Path.StartsWith("/static/", StringComparison.Ordinal))
                    return ServeStatic(req.Path.Substring("/static/".Length));

                if (!req.Path.StartsWith("/api/", StringComparison.Ordinal))
                    return Response.Error("not found", 404);

                if (!TokenOk(req)) return Response.Error("bad or missing token", 403);

                if (req.Method == "GET" || req.Method == "HEAD")
                {
                    switch (req.Path)
                    {
                        case "/api/snapshot": return SnapshotResponse(req.Q("refresh") == "1");
                        case "/api/device": return DeviceResponse(req.Q("id"));
                        case "/api/driver": return DriverResponse(req.Q("name"));
                        case "/api/hwids": return Response.Json(HwDb.Status(), 200);
                        case "/api/ping": return PingResponse();
                        case "/api/export": return ExportResponse(req.Q("what"), req.Q("format"));
                    }
                    return Response.Error("unknown endpoint", 404);
                }

                if (req.Method == "POST")
                {
                    Dictionary<string, object> payload = Json.ReadObject(req.Body);
                    switch (req.Path)
                    {
                        case "/api/action": return ActionResponse(payload);
                        case "/api/hwids/update": return HwidsUpdateResponse(payload);
                        case "/api/refresh": Cache.Invalidate(); return Ok();
                        case "/api/relaunch-admin": return RelaunchResponse();
                        case "/api/shutdown": return ShutdownResponse();
                    }
                    return Response.Error("unknown endpoint", 404);
                }
                return Response.Error("method not allowed", 405);
            }
            catch (ApiException ex) { return Response.Error(ex.Message, ex.Status); }
            catch (ActionException ex) { return Response.Error(ex.Message, 400); }
            catch (PnpUtilException ex) { return Response.Error(ex.Message, 500); }
        }

        private static bool HostOk(Request req)
        {
            string host = req.Header("Host");
            int colon = host.LastIndexOf(':');
            if (colon > 0 && host.IndexOf(']') < colon) host = host.Substring(0, colon);
            foreach (string allowed in AllowedHosts)
                if (string.Equals(host, allowed, StringComparison.OrdinalIgnoreCase)) return true;
            return false;
        }

        private static bool TokenOk(Request req)
        {
            string given = req.Header("X-DCC-Token");
            if (given.Length == 0) given = req.Q("token");
            return given.Length > 0 && FixedTimeEquals(given, Token);
        }

        private static bool FixedTimeEquals(string a, string b)
        {
            if (a.Length != b.Length) return false;
            int diff = 0;
            for (int i = 0; i < a.Length; i++) diff |= a[i] ^ b[i];
            return diff == 0;
        }

        private static Response Ok()
        {
            Dictionary<string, object> m = Json.Obj();
            m["ok"] = true;
            return Response.Json(m, 200);
        }

        // -------------------------------------------------- static assets
        private static byte[] Resource(string name)
        {
            Assembly asm = Assembly.GetExecutingAssembly();
            using (Stream s = asm.GetManifestResourceStream(name))
            {
                if (s == null) return null;
                using (MemoryStream ms = new MemoryStream())
                {
                    byte[] buffer = new byte[8192];
                    int read;
                    while ((read = s.Read(buffer, 0, buffer.Length)) > 0) ms.Write(buffer, 0, read);
                    return ms.ToArray();
                }
            }
        }

        private static Response ServeIndex()
        {
            byte[] raw = Resource("index.html");
            if (raw == null) return Response.Error("index.html is missing from the build", 500);
            int loads = System.Threading.Interlocked.Increment(ref _pageLoads);
            Log(loads == 1 ? "Browser connected. The console is running." : "Page reloaded (" + loads + ").");
            string html = Encoding.UTF8.GetString(raw).Replace("__DCC_TOKEN__", Token);
            return Response.Text(html, "text/html; charset=utf-8");
        }

        private static Response ServeStatic(string name)
        {
            // Resource names are flat, so a path separator can never escape.
            if (name.IndexOf('/') >= 0 || name.IndexOf('\\') >= 0 || name.IndexOf("..", StringComparison.Ordinal) >= 0)
                return Response.Error("forbidden", 403);
            byte[] raw = Resource(name);
            if (raw == null) return Response.Error("not found", 404);
            string type = "application/octet-stream";
            if (name.EndsWith(".js", StringComparison.OrdinalIgnoreCase)) type = "text/javascript; charset=utf-8";
            else if (name.EndsWith(".css", StringComparison.OrdinalIgnoreCase)) type = "text/css; charset=utf-8";
            else if (name.EndsWith(".html", StringComparison.OrdinalIgnoreCase)) type = "text/html; charset=utf-8";
            return Response.Bytes(raw, type);
        }

        // ------------------------------------------------------ endpoints
        private static Response SnapshotResponse(bool refresh)
        {
            Snapshot snap = Cache.Get(refresh);
            List<object> devices = new List<object>(snap.Devices.Count);
            foreach (Device d in snap.Devices) devices.Add(d.ToMap());
            List<object> drivers = new List<object>(snap.Drivers.Count);
            foreach (DriverEntry e in snap.Drivers) drivers.Add(e.ToMap());

            Dictionary<string, object> meta = snap.Meta();
            meta["elevated"] = Actions.IsElevated();
            meta["hwids"] = HwDb.Status();
            meta["backend"] = "native";

            Dictionary<string, object> body = Json.Obj();
            body["meta"] = meta;
            body["devices"] = devices;
            body["drivers"] = drivers;
            return Response.Json(body, 200);
        }

        private static Response PingResponse()
        {
            Dictionary<string, object> m = Json.Obj();
            m["ok"] = true;
            m["elevated"] = Actions.IsElevated();
            m["pid"] = System.Diagnostics.Process.GetCurrentProcess().Id;
            m["elevation_declined"] = ElevationDeclined;
            return Response.Json(m, 200);
        }

        private static Dictionary<string, object> Brief(Snapshot snap, string id)
        {
            Dictionary<string, object> m = Json.Obj();
            Device d;
            m["instance_id"] = id;
            if (snap.DeviceIndex.TryGetValue(id, out d))
            {
                m["resolved_name"] = d.ResolvedName;
                m["description"] = d.Description;
                m["status"] = d.Status;
                m["device_type"] = d.DeviceType;
            }
            else
            {
                m["resolved_name"] = "";
                m["description"] = "";
                m["status"] = "Unknown";
                m["device_type"] = "";
            }
            return m;
        }

        private static Response DeviceResponse(string instanceId)
        {
            if (string.IsNullOrEmpty(instanceId)) throw new ApiException("missing id", 400);
            Snapshot snap = Cache.Get(false);
            Device dev;
            if (!snap.DeviceIndex.TryGetValue(instanceId, out dev))
                throw new ApiException("unknown device '" + instanceId + "'", 404);

            List<object> children = new List<object>();
            foreach (string c in dev.Children) children.Add(Brief(snap, c));
            List<object> related = new List<object>();
            foreach (string r in dev.Related) related.Add(Brief(snap, r));

            object parent = null;
            if (dev.Parent.Length > 0 && snap.DeviceIndex.ContainsKey(dev.Parent))
                parent = Brief(snap, dev.Parent);

            List<object> drivers = new List<object>();
            List<string> names = new List<string>();
            if (dev.DriverName.Length > 0) names.Add(dev.DriverName);
            names.AddRange(dev.ExtensionDrivers);
            foreach (string name in names)
            {
                DriverEntry pkg;
                bool inStore = snap.DriverIndex.TryGetValue(name, out pkg);
                Dictionary<string, object> m = Json.Obj();
                m["driver_name"] = name;
                m["in_store"] = inStore;
                m["original_name"] = inStore ? pkg.Package.OriginalName : "";
                m["provider_name"] = inStore ? pkg.Package.ProviderName : "";
                m["driver_version"] = inStore ? pkg.Package.DriverVersion : "";
                m["signer_name"] = inStore ? pkg.Package.SignerName : "";
                m["device_count"] = inStore ? pkg.DeviceIds.Count : 0;
                m["is_extension"] = name != dev.DriverName;
                drivers.Add(m);
            }

            Dictionary<string, object> props = Model.DeviceDetail(instanceId);
            Dictionary<string, object> body = Json.Obj();
            body["summary"] = dev.ToMap();
            body["properties"] = props;
            body["parent"] = parent;
            body["children"] = children;
            body["related"] = related;
            body["drivers"] = drivers;
            return Response.Json(body, 200);
        }

        private static Response DriverResponse(string name)
        {
            if (string.IsNullOrEmpty(name)) throw new ApiException("missing name", 400);
            Snapshot snap = Cache.Get(false);
            DriverEntry pkg;
            if (!snap.DriverIndex.TryGetValue(name, out pkg))
                throw new ApiException("unknown driver package '" + name + "'", 404);

            List<object> devices = new List<object>();
            foreach (string id in pkg.DeviceIds)
            {
                Device d;
                Dictionary<string, object> m = Json.Obj();
                m["instance_id"] = id;
                if (snap.DeviceIndex.TryGetValue(id, out d))
                {
                    m["resolved_name"] = d.ResolvedName;
                    m["description"] = d.Description;
                    m["device_type"] = d.DeviceType;
                    m["status"] = d.Status;
                    m["class_name"] = d.ClassName;
                    m["is_extension_use"] = d.ExtensionDrivers.Contains(pkg.Package.DriverName);
                }
                else
                {
                    m["resolved_name"] = ""; m["description"] = ""; m["device_type"] = "";
                    m["status"] = "Unknown"; m["class_name"] = ""; m["is_extension_use"] = false;
                }
                devices.Add(m);
            }
            Dictionary<string, object> body = Json.Obj();
            body["driver"] = pkg.ToMap();
            body["devices"] = devices;
            return Response.Json(body, 200);
        }

        private static Response ActionResponse(Dictionary<string, object> payload)
        {
            string verb = Json.Str(payload, "verb").Trim();
            Snapshot snap = Cache.Get(false);
            ActionResult result;

            if (verb == "delete-driver")
                result = Actions.DeleteDriver(Json.Str(payload, "driver_name"),
                    Json.Flag(payload, "uninstall"), Json.Flag(payload, "force"),
                    Json.Flag(payload, "reboot"));
            else if (verb == "export-driver")
                result = Actions.ExportDriver(Json.Str(payload, "driver_name"),
                    Json.Str(payload, "target_dir"));
            else if (verb == "add-driver")
                result = Actions.AddDriver(Json.Str(payload, "inf_path"),
                    Json.Flag(payload, "subdirs"), Json.Flag(payload, "install"));
            else if (verb == "scan-devices")
                result = Actions.ScanDevices();
            else if (Array.IndexOf(Actions.SafeDeviceVerbs, verb) >= 0)
                result = Actions.DeviceAction(verb, Json.Str(payload, "instance_id"),
                    snap.DeviceIndex.Keys, Json.Flag(payload, "subtree"));
            else
                throw new ApiException("unsupported action '" + verb + "'", 400);

            Cache.Invalidate();
            return Response.Json(result.ToMap(), 200);
        }

        private static Response HwidsUpdateResponse(Dictionary<string, object> payload)
        {
            List<string> tables = null;
            object raw;
            if (payload.TryGetValue("tables", out raw))
            {
                List<object> list = raw as List<object>;
                if (list != null)
                {
                    tables = new List<string>();
                    foreach (object o in list) if (o != null) tables.Add(o.ToString());
                }
            }
            Dictionary<string, object> results = HwDb.Update(tables);
            Cache.Invalidate();
            Dictionary<string, object> body = Json.Obj();
            body["results"] = results;
            body["status"] = HwDb.Status();
            return Response.Json(body, 200);
        }

        private static Response RelaunchResponse()
        {
            Dictionary<string, object> m = Json.Obj();
            m["ok"] = true;
            if (Actions.IsElevated())
            {
                m["already"] = true;
                return Response.Json(m, 200);
            }
            m["already"] = false;
            ElevationDeclined = false;
            RestartElevatedRequested = true;
            StopSoon();
            return Response.Json(m, 200);
        }

        private static Response ShutdownResponse()
        {
            StopSoon();
            return Ok();
        }

        private static void StopSoon()
        {
            System.Threading.ThreadPool.QueueUserWorkItem(delegate (object unused)
            {
                System.Threading.Thread.Sleep(200);
                if (Server != null) Server.Stop();
            });
        }

        // --------------------------------------------------------- export
        private static readonly string[][] DeviceColumns = {
            new string[] { "instance_id", "Instance ID" },
            new string[] { "resolved_name", "Resolved Device" },
            new string[] { "device_type", "Type" },
            new string[] { "description", "Device Description" },
            new string[] { "class_name", "Class Name" },
            new string[] { "class_guid", "Class GUID" },
            new string[] { "manufacturer", "Manufacturer Name" },
            new string[] { "vendor", "Resolved Vendor" },
            new string[] { "status", "Status" },
            new string[] { "problem_text", "Problem" },
            new string[] { "driver_name", "Driver Name" },
            new string[] { "extension_drivers", "Extension Driver Names" },
            new string[] { "service", "Service" },
            new string[] { "driver_version", "Driver Version" },
            new string[] { "location", "Location" },
            new string[] { "last_arrival", "Last Arrival" },
            new string[] { "last_removal", "Last Removal" },
            new string[] { "resolved_from", "Name Resolved From" },
        };

        private static readonly string[][] DriverColumns = {
            new string[] { "driver_name", "Published Name" },
            new string[] { "original_name", "Original Name" },
            new string[] { "provider_name", "Provider Name" },
            new string[] { "class_name", "Class Name" },
            new string[] { "class_guid", "Class GUID" },
            new string[] { "driver_version", "Driver Version" },
            new string[] { "signer_name", "Signer Name" },
            new string[] { "attributes", "Attributes" },
            new string[] { "driver_package_id", "Driver Package ID" },
            new string[] { "family_id", "Family ID" },
            new string[] { "device_count", "Devices Using" },
            new string[] { "present_device_count", "Connected Devices" },
            new string[] { "orphaned", "Orphaned" },
            new string[] { "superseded_by", "Superseded By" },
            new string[] { "device_names", "Device Names" },
        };

        private static Response ExportResponse(string what, string format)
        {
            if (string.IsNullOrEmpty(what)) what = "devices";
            if (string.IsNullOrEmpty(format)) format = "csv";
            Snapshot snap = Cache.Get(false);

            List<object> rows = new List<object>();
            if (what == "devices") foreach (Device d in snap.Devices) rows.Add(d.ToMap());
            else foreach (DriverEntry e in snap.Drivers) rows.Add(e.ToMap());
            string[][] columns = what == "devices" ? DeviceColumns : DriverColumns;

            Response response;
            if (format == "json")
            {
                response = Response.Json(rows, 200);
                response.Extra["Content-Disposition"] = "attachment; filename=\"" + what + ".json\"";
                return response;
            }

            StringBuilder sb = new StringBuilder(1 << 18);
            for (int i = 0; i < columns.Length; i++)
            {
                if (i > 0) sb.Append(',');
                sb.Append(CsvCell(columns[i][1]));
            }
            sb.Append("\r\n");
            foreach (object row in rows)
            {
                Dictionary<string, object> map = (Dictionary<string, object>)row;
                for (int i = 0; i < columns.Length; i++)
                {
                    if (i > 0) sb.Append(',');
                    object value;
                    map.TryGetValue(columns[i][0], out value);
                    sb.Append(CsvCell(Flatten(value)));
                }
                sb.Append("\r\n");
            }
            // UTF-8 BOM so Excel opens non-ASCII device names correctly.
            byte[] bom = Encoding.UTF8.GetPreamble();
            byte[] text = Encoding.UTF8.GetBytes(sb.ToString());
            byte[] body = new byte[bom.Length + text.Length];
            Buffer.BlockCopy(bom, 0, body, 0, bom.Length);
            Buffer.BlockCopy(text, 0, body, bom.Length, text.Length);

            response = Response.Bytes(body, "text/csv");
            response.Extra["Content-Disposition"] = "attachment; filename=\"" + what + ".csv\"";
            return response;
        }

        private static string Flatten(object value)
        {
            if (value == null) return "";
            if (value is bool) return ((bool)value) ? "yes" : "no";
            List<string> list = value as List<string>;
            if (list != null) return string.Join("; ", list.ToArray());
            System.Collections.IEnumerable seq = value as System.Collections.IEnumerable;
            if (seq != null && !(value is string))
            {
                List<string> parts = new List<string>();
                foreach (object o in seq) parts.Add(o == null ? "" : o.ToString());
                return string.Join("; ", parts.ToArray());
            }
            return value.ToString();
        }

        private static string CsvCell(string value)
        {
            if (value == null) value = "";
            if (value.IndexOf(',') >= 0 || value.IndexOf('"') >= 0
                || value.IndexOf('\n') >= 0 || value.IndexOf('\r') >= 0)
                return "\"" + value.Replace("\"", "\"\"") + "\"";
            return value;
        }
    }
}
