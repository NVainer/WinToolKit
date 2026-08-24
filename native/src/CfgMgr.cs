// P/Invoke over cfgmgr32.dll -- the Windows Configuration Manager.
//
// pnputil prints six fields per device.  This API is what sits behind it and
// exposes the whole device node: friendly names, the string the bus reported,
// parent/child relations, arrival and removal timestamps.  A full scan of a
// typical machine takes well under two seconds and needs no elevation.
//
// Mirrors dcc/cfgmgr.py in the Python implementation.
using System;
using System.Collections.Generic;
using System.Globalization;
using System.Runtime.InteropServices;
using System.Text;

namespace DeviceControlConsole
{
    public sealed class DevNode
    {
        public uint DevInst;
        public string InstanceId;
        public bool Present;
    }

    public static class CfgMgr
    {
        public const int CrSuccess = 0;
        private const uint LocateNormal = 0x00000000;
        private const uint LocatePhantom = 0x00000001;
        private const uint FilterNone = 0x00000000;
        private const uint FilterPresent = 0x00000100;

        [StructLayout(LayoutKind.Sequential)]
        private struct DEVPROPKEY
        {
            public Guid fmtid;
            public uint pid;
        }

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Get_Device_ID_List_SizeW(
            out uint pulLen, string pszFilter, uint ulFlags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Get_Device_ID_ListW(
            string pszFilter, char[] buffer, uint bufferLen, uint ulFlags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Locate_DevNodeW(
            out uint pdnDevInst, string pDeviceID, uint ulFlags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Get_DevNode_PropertyW(
            uint dnDevInst, ref DEVPROPKEY propertyKey, out uint propertyType,
            byte[] propertyBuffer, ref uint propertyBufferSize, uint ulFlags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Get_Class_PropertyW(
            ref Guid classGuid, ref DEVPROPKEY propertyKey, out uint propertyType,
            byte[] propertyBuffer, ref uint propertyBufferSize, uint ulFlags);

        [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)]
        private static extern int CM_Get_Device_IDW(
            uint dnDevInst, char[] buffer, uint bufferLen, uint ulFlags);

        [DllImport("cfgmgr32.dll")]
        private static extern int CM_Get_Parent(out uint pdnDevInst, uint dnDevInst, uint ulFlags);

        [DllImport("cfgmgr32.dll")]
        private static extern int CM_Get_Child(out uint pdnDevInst, uint dnDevInst, uint ulFlags);

        [DllImport("cfgmgr32.dll")]
        private static extern int CM_Get_Sibling(out uint pdnDevInst, uint dnDevInst, uint ulFlags);

        private static DEVPROPKEY MakeKey(DevProps.PropKey key)
        {
            DEVPROPKEY k = new DEVPROPKEY();
            k.fmtid = new Guid(key.Fmtid);
            k.pid = key.Pid;
            return k;
        }

        /// <summary>Every device instance id the system knows, phantoms included.</summary>
        public static List<string> ListInstanceIds(bool presentOnly)
        {
            uint flags = presentOnly ? FilterPresent : FilterNone;
            List<string> ids = new List<string>();
            uint size;
            if (CM_Get_Device_ID_List_SizeW(out size, null, flags) != CrSuccess || size == 0)
                return ids;
            char[] buffer = new char[size];
            if (CM_Get_Device_ID_ListW(null, buffer, size, flags) != CrSuccess) return ids;

            StringBuilder current = new StringBuilder();
            for (int i = 0; i < buffer.Length; i++)
            {
                if (buffer[i] == '\0')
                {
                    if (current.Length > 0) { ids.Add(current.ToString()); current.Length = 0; }
                }
                else current.Append(buffer[i]);
            }
            if (current.Length > 0) ids.Add(current.ToString());
            return ids;
        }

        /// <summary>Locates a devnode, falling back to a phantom (absent) lookup.</summary>
        public static DevNode Locate(string instanceId)
        {
            uint devinst;
            if (CM_Locate_DevNodeW(out devinst, instanceId, LocateNormal) == CrSuccess)
            {
                DevNode n = new DevNode();
                n.DevInst = devinst; n.InstanceId = instanceId; n.Present = true;
                return n;
            }
            if (CM_Locate_DevNodeW(out devinst, instanceId, LocatePhantom) == CrSuccess)
            {
                DevNode n = new DevNode();
                n.DevInst = devinst; n.InstanceId = instanceId; n.Present = false;
                return n;
            }
            return null;
        }

        /// <summary>Reads one DEVPKEY.  Returns null when the node does not carry it.</summary>
        public static object GetProperty(uint devinst, string name)
        {
            DevProps.PropKey spec;
            if (!DevProps.Keys.TryGetValue(name, out spec)) return null;
            DEVPROPKEY key = MakeKey(spec);
            uint type;
            uint size = 0;
            CM_Get_DevNode_PropertyW(devinst, ref key, out type, null, ref size, 0);
            if (size == 0) return null;
            byte[] buffer = new byte[size];
            if (CM_Get_DevNode_PropertyW(devinst, ref key, out type, buffer, ref size, 0) != CrSuccess)
                return null;
            return Decode(type, buffer, (int)size);
        }

        public static Dictionary<string, object> GetProperties(uint devinst, string[] names)
        {
            Dictionary<string, object> map = new Dictionary<string, object>(StringComparer.Ordinal);
            for (int i = 0; i < names.Length; i++)
            {
                object value = GetProperty(devinst, names[i]);
                if (value == null) continue;
                string s = value as string;
                if (s != null && s.Length == 0) continue;
                List<string> list = value as List<string>;
                if (list != null && list.Count == 0) continue;
                map[names[i]] = value;
            }
            return map;
        }

        public static string DeviceId(uint devinst)
        {
            char[] buffer = new char[512];
            if (CM_Get_Device_IDW(devinst, buffer, (uint)buffer.Length, 0) != CrSuccess) return null;
            int end = Array.IndexOf(buffer, '\0');
            if (end < 0) end = buffer.Length;
            return new string(buffer, 0, end);
        }

        public static string ParentOf(uint devinst)
        {
            uint parent;
            if (CM_Get_Parent(out parent, devinst, 0) != CrSuccess) return null;
            return DeviceId(parent);
        }

        /// <summary>Walks child + sibling links, for nodes with no Children property.</summary>
        public static List<string> ChildrenOf(uint devinst)
        {
            List<string> ids = new List<string>();
            uint child;
            if (CM_Get_Child(out child, devinst, 0) != CrSuccess) return ids;
            uint current = child;
            while (true)
            {
                string id = DeviceId(current);
                if (id != null) ids.Add(id);
                uint next;
                if (CM_Get_Sibling(out next, current, 0) != CrSuccess) break;
                current = next;
                if (ids.Count > 4096) break;  // never loop forever on a corrupt tree
            }
            return ids;
        }

        // ------------------------------------------------------- class names
        private static readonly Dictionary<string, string> ClassNameCache =
            new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);

        public static string ClassDisplayName(string classGuid)
        {
            if (string.IsNullOrEmpty(classGuid)) return null;
            lock (ClassNameCache)
            {
                string cached;
                if (ClassNameCache.TryGetValue(classGuid, out cached))
                    return cached.Length == 0 ? null : cached;
            }
            string name = "";
            try
            {
                Guid guid = new Guid(classGuid);
                DEVPROPKEY key = MakeKey(DevProps.ClassName);
                uint type;
                uint size = 0;
                CM_Get_Class_PropertyW(ref guid, ref key, out type, null, ref size, 0);
                if (size > 0)
                {
                    byte[] buffer = new byte[size];
                    if (CM_Get_Class_PropertyW(ref guid, ref key, out type, buffer, ref size, 0) == CrSuccess)
                    {
                        string decoded = Decode(type, buffer, (int)size) as string;
                        if (decoded != null) name = decoded;
                    }
                }
            }
            catch (FormatException) { name = ""; }
            catch (OverflowException) { name = ""; }

            lock (ClassNameCache) { ClassNameCache[classGuid] = name; }
            return name.Length == 0 ? null : name;
        }

        // ---------------------------------------------------------- decoding
        private const long EpochDelta = 116444736000000000L; // 1601 -> 1970, 100ns ticks

        private static object Decode(uint type, byte[] raw, int length)
        {
            if (length <= 0) return null;
            switch (type)
            {
                case DevProps.TypeString:
                    return TrimNulls(Encoding.Unicode.GetString(raw, 0, length));

                case DevProps.TypeStringList:
                    {
                        string all = Encoding.Unicode.GetString(raw, 0, length);
                        string[] parts = all.Split('\0');
                        List<string> list = new List<string>();
                        for (int i = 0; i < parts.Length; i++)
                            if (parts[i].Length > 0) list.Add(parts[i]);
                        return list;
                    }

                case DevProps.TypeUInt32:
                    return length >= 4 ? (object)BitConverter.ToUInt32(raw, 0) : null;

                case DevProps.TypeInt32:
                    return length >= 4 ? (object)BitConverter.ToInt32(raw, 0) : null;

                case DevProps.TypeUInt64:
                    return length >= 8 ? (object)BitConverter.ToUInt64(raw, 0) : null;

                case DevProps.TypeBoolean:
                    return raw[0] != 0;

                case DevProps.TypeByte:
                    return (int)raw[0];

                case DevProps.TypeFileTime:
                    return FileTimeToIso(raw, length);

                case DevProps.TypeGuid:
                    if (length < 16) return null;
                    byte[] g = new byte[16];
                    Array.Copy(raw, g, 16);
                    return new Guid(g).ToString("B");

                case DevProps.TypeSecurityDescriptor:
                    return null;

                case DevProps.TypeBinary:
                    return BitConverter.ToString(raw, 0, Math.Min(length, 64)).Replace("-", "").ToLowerInvariant();

                default:
                    return null;
            }
        }

        private static string TrimNulls(string s)
        {
            int end = s.IndexOf('\0');
            return end >= 0 ? s.Substring(0, end) : s;
        }

        private static string FileTimeToIso(byte[] raw, int length)
        {
            if (length < 8) return null;
            long ticks = BitConverter.ToInt64(raw, 0);
            if (ticks == 0) return null;
            try
            {
                DateTime utc = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc)
                    .AddTicks(ticks - EpochDelta);
                return utc.ToString("yyyy-MM-dd'T'HH:mm:ss'+00:00'", CultureInfo.InvariantCulture);
            }
            catch (ArgumentOutOfRangeException) { return null; }
        }
    }
}
