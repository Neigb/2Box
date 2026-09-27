param(
    [Parameter(Mandatory = $true)][string]$Output,
    [Parameter(Mandatory = $true)][string]$NativeAssembly
)

$ErrorActionPreference = 'Stop'

$nativeDefinition = @'
using System;
using System.Collections.Generic;
using System.Management;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class DeviceProbeNative
{
    private const uint IOCTL_STORAGE_QUERY_PROPERTY = 0x002D1400;
    private const uint FILE_SHARE_READ = 1;
    private const uint FILE_SHARE_WRITE = 2;
    private const uint OPEN_EXISTING = 3;
    private const uint FILE_FLAG_OVERLAPPED = 0x40000000;
    private const int ERROR_IO_PENDING = 997;
    private const uint ERROR_BUFFER_OVERFLOW = 111;

    [StructLayout(LayoutKind.Sequential)]
    private struct StorageQuery
    {
        public uint PropertyId;
        public uint QueryType;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct Overlapped
    {
        public IntPtr Internal;
        public IntPtr InternalHigh;
        public uint Offset;
        public uint OffsetHigh;
        public IntPtr Event;
    }

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern IntPtr CreateFileW(string name, uint access, uint share, IntPtr security,
        uint creation, uint flags, IntPtr templateFile);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(IntPtr device, uint code, ref StorageQuery query,
        uint inputSize, [Out] byte[] output, uint outputSize, out uint returned, IntPtr overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool DeviceIoControl(IntPtr device, uint code, ref StorageQuery query,
        uint inputSize, [Out] byte[] output, uint outputSize, out uint returned, ref Overlapped overlapped);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool GetOverlappedResult(IntPtr device, ref Overlapped overlapped,
        out uint returned, bool wait);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern IntPtr CreateEventW(IntPtr security, bool manualReset, bool initialState, string name);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern uint WaitForSingleObject(IntPtr handle, uint milliseconds);

    [DllImport("kernel32.dll", SetLastError = true)]
    private static extern bool CloseHandle(IntPtr handle);

    [DllImport("iphlpapi.dll")]
    private static extern uint GetAdaptersInfo(IntPtr adapters, ref uint size);

    public static string AsyncWmiSerial()
    {
        using (ManualResetEvent done = new ManualResetEvent(false))
        using (ManagementObjectSearcher searcher = new ManagementObjectSearcher(
            @"root\cimv2", "SELECT SerialNumber FROM Win32_DiskDrive"))
        {
            string serial = "";
            ManagementOperationObserver observer = new ManagementOperationObserver();
            observer.ObjectReady += (sender, args) =>
            {
                if (serial.Length == 0)
                {
                    object value = args.NewObject["SerialNumber"];
                    serial = value == null ? "" : value.ToString();
                }
            };
            observer.Completed += (sender, args) => done.Set();
            searcher.Get(observer);
            return done.WaitOne(10000) ? serial : "TIMEOUT";
        }
    }

    private static string[] AdapterFields(bool names)
    {
        uint size = 0;
        if (GetAdaptersInfo(IntPtr.Zero, ref size) != ERROR_BUFFER_OVERFLOW || size == 0)
            return new string[0];
        IntPtr buffer = Marshal.AllocHGlobal((int)size);
        try
        {
            if (GetAdaptersInfo(buffer, ref size) != 0) return new string[0];
            List<string> result = new List<string>();
            int addressLengthOffset = IntPtr.Size == 8 ? 404 : 400;
            int nameOffset = IntPtr.Size + 4;
            IntPtr current = buffer;
            for (int i = 0; i < 128 && current != IntPtr.Zero; ++i)
            {
                if (names)
                {
                    byte[] bytes = new byte[260];
                    Marshal.Copy(IntPtr.Add(current, nameOffset), bytes, 0, bytes.Length);
                    int end = Array.IndexOf(bytes, (byte)0);
                    if (end > 0) result.Add(Encoding.ASCII.GetString(bytes, 0, end));
                }
                else
                {
                    int addressLength = Marshal.ReadInt32(current, addressLengthOffset);
                    if (addressLength == 6)
                    {
                        byte[] bytes = new byte[6];
                        Marshal.Copy(IntPtr.Add(current, addressLengthOffset + 4), bytes, 0, bytes.Length);
                        result.Add(BitConverter.ToString(bytes).Replace('-', ':'));
                    }
                }
                current = Marshal.ReadIntPtr(current);
            }
            return result.ToArray();
        }
        finally { Marshal.FreeHGlobal(buffer); }
    }

    public static string[] AdapterMacs() { return AdapterFields(false); }
    public static string[] AdapterGuids() { return AdapterFields(true); }

    private static string Serial(byte[] data, uint returned)
    {
        if (returned < 36) return "NO_DESCRIPTOR";
        uint offset = BitConverter.ToUInt32(data, 24);
        if (offset == 0 || offset >= returned) return "NO_SERIAL";
        int end = Array.IndexOf(data, (byte)0, (int)offset, (int)(returned - offset));
        if (end < 0) return "NO_TERMINATOR";
        return Encoding.ASCII.GetString(data, (int)offset, end - (int)offset).Trim();
    }

    public static string Read(bool asynchronous, bool shortBuffer)
    {
        IntPtr device = CreateFileW(@"\\.\PhysicalDrive0", 0, FILE_SHARE_READ | FILE_SHARE_WRITE,
            IntPtr.Zero, OPEN_EXISTING, asynchronous ? FILE_FLAG_OVERLAPPED : 0, IntPtr.Zero);
        if (device == new IntPtr(-1)) return "OPEN_ERROR:" + Marshal.GetLastWin32Error();
        IntPtr evt = IntPtr.Zero;
        try
        {
            StorageQuery query = new StorageQuery();
            byte[] data = new byte[shortBuffer ? 8 : 4096];
            uint returned;
            bool ok;
            if (asynchronous)
            {
                evt = CreateEventW(IntPtr.Zero, true, false, null);
                if (evt == IntPtr.Zero) return "EVENT_ERROR:" + Marshal.GetLastWin32Error();
                Overlapped overlapped = new Overlapped { Event = evt };
                ok = DeviceIoControl(device, IOCTL_STORAGE_QUERY_PROPERTY, ref query, 8,
                    data, (uint)data.Length, out returned, ref overlapped);
                int error = Marshal.GetLastWin32Error();
                if (!ok && error == ERROR_IO_PENDING)
                {
                    uint wait = WaitForSingleObject(evt, 10000);
                    if (wait != 0) return "WAIT_ERROR:" + wait;
                    ok = GetOverlappedResult(device, ref overlapped, out returned, false);
                }
            }
            else
            {
                ok = DeviceIoControl(device, IOCTL_STORAGE_QUERY_PROPERTY, ref query, 8,
                    data, (uint)data.Length, out returned, IntPtr.Zero);
            }
            if (!ok) return "QUERY_ERROR:" + Marshal.GetLastWin32Error();
            if (shortBuffer) return "SHORT_OK:" + returned + ":" + BitConverter.ToUInt32(data, 4);
            return Serial(data, returned);
        }
        finally
        {
            if (evt != IntPtr.Zero) CloseHandle(evt);
            CloseHandle(device);
        }
    }
}
'@

try {
if (Test-Path -LiteralPath $NativeAssembly) {
    Add-Type -LiteralPath $NativeAssembly
} else {
    Add-Type -ReferencedAssemblies 'System.Management' -TypeDefinition $nativeDefinition `
        -OutputAssembly $NativeAssembly -PassThru | Out-Null
}

$disk = Get-WmiObject -Namespace 'root\cimv2' -Class Win32_DiskDrive | Select-Object -First 1
$bios = Get-WmiObject -Namespace 'root\cimv2' -Class Win32_BIOS | Select-Object -First 1
$systemProduct = Get-WmiObject -Namespace 'root\cimv2' -Class Win32_ComputerSystemProduct | Select-Object -First 1
$adapter = Get-WmiObject -Namespace 'root\cimv2' -Class Win32_NetworkAdapter |
    Where-Object { $_.MACAddress -and $_.PhysicalAdapter } | Select-Object -First 1
$invalidClassStatus = ''
try {
    $null = Get-WmiObject -Namespace 'root\cimv2' -Class '__DeviceProbeMissingClass' -ErrorAction Stop
    $invalidClassStatus = 'UNEXPECTED_SUCCESS'
} catch {
    $invalidClassStatus = [string]$_.Exception.HResult
}

$result = [ordered]@{
    ProcessId = $PID
    WmiSerial = if ($disk) { [string]$disk.SerialNumber } else { '' }
    AsyncWmiSerial = [DeviceProbeNative]::AsyncWmiSerial()
    WmiModel = if ($disk) { [string]$disk.Model } else { '' }
    WmiBiosSerial = if ($bios) { [string]$bios.SerialNumber } else { '' }
    WmiProductUuid = if ($systemProduct) { [string]$systemProduct.UUID } else { '' }
    WmiMac = if ($adapter) { [string]$adapter.MACAddress } else { '' }
    WmiAdapterGuid = if ($adapter) { [string]$adapter.GUID } else { '' }
    IpHelperMacs = @([DeviceProbeNative]::AdapterMacs())
    IpHelperGuids = @([DeviceProbeNative]::AdapterGuids())
    StorageSerial = [DeviceProbeNative]::Read($false, $false)
    AsyncStorageSerial = [DeviceProbeNative]::Read($true, $false)
    ShortQuery = [DeviceProbeNative]::Read($false, $true)
    InvalidWmiClassStatus = $invalidClassStatus
}

$result | ConvertTo-Json | Set-Content -LiteralPath $Output -Encoding UTF8
} catch {
    [ordered]@{
        ProcessId = $PID
        FatalError = $_.Exception.ToString()
    } | ConvertTo-Json | Set-Content -LiteralPath $Output -Encoding UTF8
    exit 1
}
