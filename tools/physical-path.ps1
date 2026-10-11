function Resolve-PhysicalPath([string]$Path) {
    # Resolve reparse points using the actual filesystem handle, including existing
    # ancestors of a destination that has not been created yet.
    if (-not ('AcePhysicalPath' -as [type])) {
        Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;
using Microsoft.Win32.SafeHandles;
public static class AcePhysicalPath {
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string name, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern uint GetFinalPathNameByHandle(SafeFileHandle handle,
        StringBuilder buffer, uint size, uint flags);
    public static string Resolve(string path) {
        using (var handle = CreateFile(path, 0, 7, IntPtr.Zero, 3, 0x02000000, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new Win32Exception(Marshal.GetLastWin32Error());
            var buffer = new StringBuilder(32768);
            var length = GetFinalPathNameByHandle(handle, buffer, (uint)buffer.Capacity, 0);
            if (length == 0 || length >= buffer.Capacity)
                throw new Win32Exception(Marshal.GetLastWin32Error());
            var result = buffer.ToString();
            if (result.StartsWith(@"\\?\UNC\")) return @"\\" + result.Substring(8);
            return result.StartsWith(@"\\?\") ? result.Substring(4) : result;
        }
    }
}
'@
    }
    $absolute = [IO.Path]::GetFullPath($Path)
    $suffix = @()
    while (-not (Test-Path -LiteralPath $absolute)) {
        $suffix = @([IO.Path]::GetFileName($absolute)) + $suffix
        $parent = [IO.Path]::GetDirectoryName($absolute)
        if (-not $parent -or $parent -eq $absolute) { throw 'PHYSICAL_PATH_UNAVAILABLE' }
        $absolute = $parent
    }
    $resolved = [AcePhysicalPath]::Resolve($absolute)
    foreach ($part in $suffix) { $resolved = Join-Path $resolved $part }
    return $resolved
}

function Assert-SeparateBackupKey([string]$ArchivePath, [string]$KeyPath) {
    $archive = (Resolve-PhysicalPath $ArchivePath).TrimEnd('\')
    $key = (Resolve-PhysicalPath $KeyPath).TrimEnd('\')
    if ($key.Equals($archive, [StringComparison]::OrdinalIgnoreCase) -or
        $key.StartsWith($archive+'\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'BACKUP_KEY_STORAGE_NOT_SEPARATE'
    }
}
