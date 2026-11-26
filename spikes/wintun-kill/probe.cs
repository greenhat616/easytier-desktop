// Native, read-only enumeration (IP Helper + Configuration Manager). It is fast
// enough to hold a 250 ms cadence, which Get-NetAdapter and pnputil are not;
// run.ps1 uses those as a cross-check outside the timed window.
using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Threading;

// OperStatus is IF_OPER_STATUS: 1 up, 2 down, 6 not present. GetIfTable2 keeps
// a "down" row for a removed adapter, so a row alone does not mean it exists.
public class Iface { public ulong Luid; public uint Index; public Guid Guid; public string Alias; public string Description; public int OperStatus; }
public class Node { public string Id; public bool Live; public bool Phantom; public uint Status; public uint Problem; }
public class Sample
{
    public int TargetMs; public long AtMs; public long TookMs;
    public Iface[] Interfaces; public int IpInterfaces; public string[] Routes; public string[] Addresses; public Node[] Nodes;
}

public static class Probe
{
    [DllImport("iphlpapi.dll")] static extern uint GetIfTable2(out IntPtr table);
    [DllImport("iphlpapi.dll")] static extern uint GetIpForwardTable2(ushort family, out IntPtr table);
    [DllImport("iphlpapi.dll")] static extern uint GetUnicastIpAddressTable(ushort family, out IntPtr table);
    [DllImport("iphlpapi.dll")] static extern uint GetIpInterfaceTable(ushort family, out IntPtr table);
    [DllImport("iphlpapi.dll")] static extern void FreeMibTable(IntPtr table);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)] static extern uint CM_Locate_DevNodeW(out uint devInst, string id, uint flags);
    [DllImport("cfgmgr32.dll")] static extern uint CM_Get_DevNode_Status(out uint status, out uint problem, uint devInst, uint flags);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)] static extern uint CM_Get_Device_ID_List_SizeW(out uint len, string filter, uint flags);
    [DllImport("cfgmgr32.dll", CharSet = CharSet.Unicode)] static extern uint CM_Get_Device_ID_ListW(string filter, [Out] char[] buffer, uint len, uint flags);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool TerminateProcess(IntPtr process, uint exitCode);
    [DllImport("kernel32.dll", SetLastError = true)] static extern bool SetConsoleCtrlHandler(IntPtr handler, bool add);

    // A process inherits its parent's "ignore Ctrl+C" attribute; clear it so the
    // graceful-exit contrast can reach the core.
    public static void AllowCtrlC() { SetConsoleCtrlHandler(IntPtr.Zero, false); }

    // MIB_IF_ROW2: 1352 bytes; the table's rows start at offset 8.
    public static Iface[] Interfaces()
    {
        IntPtr t; uint rc = GetIfTable2(out t);
        if (rc != 0) throw new Exception("GetIfTable2 " + rc);
        try
        {
            var list = new List<Iface>();
            int n = Marshal.ReadInt32(t);
            for (int i = 0; i < n; i++)
            {
                IntPtr r = IntPtr.Add(t, 8 + i * 1352);
                var g = new byte[16]; Marshal.Copy(IntPtr.Add(r, 12), g, 0, 16);
                list.Add(new Iface {
                    Luid = (ulong)Marshal.ReadInt64(r), Index = (uint)Marshal.ReadInt32(r, 8), Guid = new Guid(g),
                    Alias = Marshal.PtrToStringUni(IntPtr.Add(r, 28)), Description = Marshal.PtrToStringUni(IntPtr.Add(r, 542)), OperStatus = Marshal.ReadInt32(r, 1156) });
            }
            return list.ToArray();
        }
        finally { FreeMibTable(t); }
    }

    static string Address(IntPtr sockaddr)
    {
        short family = Marshal.ReadInt16(sockaddr);
        var b = new byte[family == 2 ? 4 : 16];
        Marshal.Copy(IntPtr.Add(sockaddr, family == 2 ? 4 : 8), b, 0, b.Length);
        return new IPAddress(b).ToString();
    }

    // MIB_IPFORWARD_ROW2: 104 bytes; destination at 12, prefix length at 40.
    public static string[] Routes(ulong luid)
    {
        IntPtr t; uint rc = GetIpForwardTable2(0, out t);
        if (rc != 0) throw new Exception("GetIpForwardTable2 " + rc);
        try
        {
            var list = new List<string>();
            int n = Marshal.ReadInt32(t);
            for (int i = 0; i < n; i++)
            {
                IntPtr r = IntPtr.Add(t, 8 + i * 104);
                if ((ulong)Marshal.ReadInt64(r) != luid) continue;
                list.Add(Address(IntPtr.Add(r, 12)) + "/" + Marshal.ReadByte(r, 40));
            }
            return list.ToArray();
        }
        finally { FreeMibTable(t); }
    }

    // MIB_UNICASTIPADDRESS_ROW: 80 bytes; interface LUID at 32.
    public static string[] Addresses(ulong luid)
    {
        IntPtr t; uint rc = GetUnicastIpAddressTable(0, out t);
        if (rc != 0) throw new Exception("GetUnicastIpAddressTable " + rc);
        try
        {
            var list = new List<string>();
            int n = Marshal.ReadInt32(t);
            for (int i = 0; i < n; i++)
            {
                IntPtr r = IntPtr.Add(t, 8 + i * 80);
                if ((ulong)Marshal.ReadInt64(r, 32) != luid) continue;
                list.Add(Address(r));
            }
            return list.ToArray();
        }
        finally { FreeMibTable(t); }
    }

    // MIB_IPINTERFACE_ROW: 168 bytes; interface LUID at 8. One row per address family.
    public static int IpInterfaces(ulong luid)
    {
        IntPtr t; uint rc = GetIpInterfaceTable(0, out t);
        if (rc != 0) throw new Exception("GetIpInterfaceTable " + rc);
        try
        {
            int count = 0, n = Marshal.ReadInt32(t);
            for (int i = 0; i < n; i++)
                if ((ulong)Marshal.ReadInt64(IntPtr.Add(t, 8 + i * 168), 8) == luid) count++;
            return count;
        }
        finally { FreeMibTable(t); }
    }

    [StructLayout(LayoutKind.Sequential)]
    struct DevInfoData { public uint Size; public Guid Class; public uint DevInst; public IntPtr Reserved; }
    [DllImport("setupapi.dll", SetLastError = true)] static extern IntPtr SetupDiCreateDeviceInfoList(IntPtr classGuid, IntPtr parent);
    [DllImport("setupapi.dll", CharSet = CharSet.Unicode, SetLastError = true)] static extern bool SetupDiOpenDeviceInfoW(IntPtr set, string id, IntPtr parent, uint flags, ref DevInfoData data);
    [DllImport("setupapi.dll")] static extern bool SetupDiDestroyDeviceInfoList(IntPtr set);
    [DllImport("newdev.dll", SetLastError = true)] static extern bool DiUninstallDevice(IntPtr parent, IntPtr set, ref DevInfoData data, uint flags, out bool needReboot);

    // Removes a device node, present or not. Returns whether Windows asks for a reboot.
    public static bool Uninstall(string id)
    {
        IntPtr set = SetupDiCreateDeviceInfoList(IntPtr.Zero, IntPtr.Zero);
        if (set == new IntPtr(-1)) throw new Exception("SetupDiCreateDeviceInfoList " + Marshal.GetLastWin32Error());
        try
        {
            var data = new DevInfoData();
            data.Size = (uint)Marshal.SizeOf(typeof(DevInfoData));
            if (!SetupDiOpenDeviceInfoW(set, id, IntPtr.Zero, 0, ref data))
                throw new Exception("SetupDiOpenDeviceInfoW 0x" + Marshal.GetLastWin32Error().ToString("X8"));
            bool reboot;
            if (!DiUninstallDevice(IntPtr.Zero, set, ref data, 0, out reboot))
                throw new Exception("DiUninstallDevice 0x" + Marshal.GetLastWin32Error().ToString("X8"));
            return reboot;
        }
        finally { SetupDiDestroyDeviceInfoList(set); }
    }

    // Every SWD\Wintun device node, present or not (no CM_GETIDLIST_FILTER_PRESENT).
    public static Node[] WintunNodes()
    {
        const uint ENUMERATOR = 1;
        uint len; char[] buffer; uint rc;
        do
        {
            rc = CM_Get_Device_ID_List_SizeW(out len, "SWD", ENUMERATOR);
            if (rc != 0) throw new Exception("CM_Get_Device_ID_List_SizeW " + rc);
            buffer = new char[len];
            rc = CM_Get_Device_ID_ListW("SWD", buffer, len, ENUMERATOR);
        } while (rc == 0x1A); // CR_BUFFER_SMALL
        if (rc != 0) throw new Exception("CM_Get_Device_ID_ListW " + rc);
        var list = new List<Node>();
        foreach (var id in new string(buffer).Split(new[] { '\0' }, StringSplitOptions.RemoveEmptyEntries))
        {
            if (!id.StartsWith("SWD\\Wintun\\", StringComparison.OrdinalIgnoreCase)) continue;
            list.Add(Locate(id));
        }
        return list.ToArray();
    }

    public static Node Locate(string id)
    {
        var node = new Node { Id = id };
        uint inst;
        if (CM_Locate_DevNodeW(out inst, id, 0) == 0)
        {
            node.Live = true;
            uint s, p;
            if (CM_Get_DevNode_Status(out s, out p, inst, 0) == 0) { node.Status = s; node.Problem = p; }
        }
        node.Phantom = !node.Live && CM_Locate_DevNodeW(out inst, id, 1) == 0; // CM_LOCATE_DEVNODE_PHANTOM
        return node;
    }

    // Interfaces matching the adapter by LUID, GUID or alias prefix (the prefix
    // also catches the NDIS filter interfaces stacked on it).
    public static Sample Take(string name, ulong luid, Guid guid)
    {
        var s = new Sample();
        var matched = new List<Iface>();
        foreach (var i in Interfaces())
            if (i.Luid == luid || i.Guid == guid || (i.Alias ?? "").StartsWith(name, StringComparison.OrdinalIgnoreCase))
                matched.Add(i);
        s.Interfaces = matched.ToArray();
        s.IpInterfaces = IpInterfaces(luid);
        s.Routes = Routes(luid);
        s.Addresses = Addresses(luid);
        s.Nodes = WintunNodes();
        return s;
    }

    public static void HardKill(IntPtr process)
    {
        if (!TerminateProcess(process, 1)) throw new Exception("TerminateProcess " + Marshal.GetLastWin32Error());
    }

    // Samples at 0, step, 2*step ... window, measured from the call.
    public static Sample[] Timeline(string name, ulong luid, Guid guid, int stepMs, int windowMs)
    {
        var clock = Stopwatch.StartNew();
        var list = new List<Sample>();
        for (int target = 0; target <= windowMs; target += stepMs)
        {
            int wait = target - (int)clock.ElapsedMilliseconds;
            if (wait > 0) Thread.Sleep(wait);
            long at = clock.ElapsedMilliseconds;
            var s = Take(name, luid, guid);
            s.TargetMs = target; s.AtMs = at; s.TookMs = clock.ElapsedMilliseconds - at;
            list.Add(s);
        }
        return list.ToArray();
    }
}
