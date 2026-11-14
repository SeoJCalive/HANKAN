[CmdletBinding()]
param(
    [string]$RepoPath = 'C:\Users\BILAB\LinuxWorkspace\HANKAN',
    [string]$DataDir = 'D:\HANKAN\data',
    [ValidateRange(1024, 65535)][int]$Port = 5180,
    [ValidateRange(1024, 65535)][int]$MetricsPort = 5196,
    [string]$UrlFile = 'D:\HANKAN\tunnel-url.txt',
    [string]$TaskName = 'HANKAN-AutoStart'
)

$ErrorActionPreference = 'Stop'
$serverLog = if ($DataDir -eq 'D:\HANKAN\data') {
    'D:\HANKAN\server.log'
} else {
    Join-Path $DataDir 'server.log'
}
$runLog = Join-Path $DataDir 'autostart.log'

try {
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    Remove-Item -LiteralPath $UrlFile -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $UrlFile) { throw "Cannot remove old URL: $UrlFile" }
    if ([Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1] -ine 'BILAB') {
        throw 'Run this script as the logged-on BILAB user.'
    }
    if ($Port -eq $MetricsPort) { throw 'Server and metrics ports must differ.' }
    foreach ($number in @($Port, $MetricsPort)) {
        if (Get-NetTCPConnection -State Listen -LocalPort $number -ErrorAction SilentlyContinue) {
            throw "Port $number is already listening; no server or tunnel was started."
        }
    }

    $project = Join-Path $RepoPath 'src\HANKAN.Web\HANKAN.Web.csproj'
    $dotnet = (Get-Command dotnet -CommandType Application).Source
    $cloudflared = 'C:\Program Files (x86)\cloudflared\cloudflared.exe'
    $tunnelHome = Join-Path $env:LOCALAPPDATA 'HANKAN-Tunnel'
    $config = Join-Path $tunnelHome 'cloudflared-empty.yml'
    foreach ($file in @($project, $cloudflared, $config)) {
        if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw "Missing file: $file" }
    }

    # A non-inheritable handle lives until this PowerShell process exits.
    # Job membership is inherited by children, including dotnet run's app.
    # Even Stop-ScheduledTask/TerminateProcess closes the handle and kills
    # only this invocation's process tree; finally alone cannot guarantee it.
    Add-Type -TypeDefinition @'
using System;
using System.ComponentModel;
using System.Diagnostics;
using System.Runtime.InteropServices;

public static class HankanProcessJob
{
    [StructLayout(LayoutKind.Sequential)]
    struct BasicLimits
    {
        public long ProcessTime, JobTime;
        public uint Flags;
        public UIntPtr MinWorkingSet, MaxWorkingSet;
        public uint ActiveProcesses;
        public UIntPtr Affinity;
        public uint Priority, Scheduling;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct IoCounters
    {
        public ulong ReadOps, WriteOps, OtherOps, ReadBytes, WriteBytes, OtherBytes;
    }
    [StructLayout(LayoutKind.Sequential)]
    struct ExtendedLimits
    {
        public BasicLimits Basic;
        public IoCounters Io;
        public UIntPtr ProcessMemory, JobMemory, PeakProcessMemory, PeakJobMemory;
    }
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    static extern IntPtr CreateJobObject(IntPtr attributes, string name);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool SetInformationJobObject(IntPtr job, int kind,
        ref ExtendedLimits limits, uint size);
    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool AssignProcessToJobObject(IntPtr job, IntPtr process);
    [DllImport("kernel32.dll")]
    static extern bool CloseHandle(IntPtr handle);
    static IntPtr job;

    public static void Attach()
    {
        job = CreateJobObject(IntPtr.Zero, null);
        if (job == IntPtr.Zero) throw new Win32Exception();
        var limits = new ExtendedLimits();
        limits.Basic.Flags = 0x2000; // JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE
        if (!SetInformationJobObject(job, 9, ref limits,
                (uint)Marshal.SizeOf(typeof(ExtendedLimits))) ||
            !AssignProcessToJobObject(job, Process.GetCurrentProcess().Handle))
        {
            int error = Marshal.GetLastWin32Error();
            CloseHandle(job);
            throw new Win32Exception(error);
        }
    }
}
'@
    $watchCommand = "Wait-Process -Id $PID -ErrorAction SilentlyContinue; Remove-Item -LiteralPath '" +
        $UrlFile.Replace("'", "''") + "' -Force -ErrorAction SilentlyContinue"
    $watcher = Start-Process -FilePath "$PSHOME\powershell.exe" -WindowStyle Hidden `
        -ArgumentList '-NoProfile', '-Command', $watchCommand -PassThru
    Add-Content -LiteralPath $runLog -Value "$(Get-Date -Format o) url-watcher=$($watcher.Id) host=$PID"
    [HankanProcessJob]::Attach()

    $env:HANKAN_DATA_DIR = $DataDir
    $env:HANKAN_PORT = $Port.ToString()
    $serverCommand = '"{0}" run --no-build --project "{1}" > "{2}" 2>&1' -f $dotnet, $project, $serverLog
    $server = Start-Process -FilePath $env:ComSpec -ArgumentList ('/d /s /c "' + $serverCommand + '"') `
        -WorkingDirectory $RepoPath -WindowStyle Hidden -PassThru
    Add-Content -LiteralPath $runLog -Value "$(Get-Date -Format o) $TaskName host=$PID server-wrapper=$($server.Id) port=$Port"

    $deadline = (Get-Date).AddSeconds(60)
    $ready = $false
    while ((Get-Date) -lt $deadline) {
        if ($server.HasExited) { throw "Server exited before readiness; see $serverLog" }
        try {
            $request = [Net.HttpWebRequest]::Create("http://127.0.0.1:$Port/Login")
            $request.AllowAutoRedirect = $false
            $request.Timeout = 2000
            $response = $request.GetResponse()
            $ready = [int]$response.StatusCode -in @(200, 302)
            $response.Close()
        } catch [Net.WebException] {
            $ready = $false
        }
        if ($ready) { break }
        Start-Sleep -Seconds 1
    }
    if (-not $ready) { throw "Server readiness timed out; see $serverLog" }

    # Change only this dedicated host and future tunnel child environment.
    # The already-started server retains its original forwarding guard.
    Get-ChildItem Env: |
        Where-Object { $_.Name -like 'TUNNEL_*' -or $_.Name -in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY') } |
        ForEach-Object { Remove-Item ('Env:' + $_.Name) }
    $tunnelLog = Join-Path $DataDir 'tunnel.log'
    $tunnelCommand = '"{0}" tunnel --config "{1}" --url http://127.0.0.1:{2} --protocol http2 --no-autoupdate --metrics 127.0.0.1:{3} > "{4}" 2>&1' -f `
        $cloudflared, $config, $Port, $MetricsPort, $tunnelLog
    $tunnel = Start-Process -FilePath $env:ComSpec -ArgumentList ('/d /s /c "' + $tunnelCommand + '"') `
        -WorkingDirectory $tunnelHome -WindowStyle Hidden -PassThru
    Add-Content -LiteralPath $runLog -Value "$(Get-Date -Format o) tunnel-wrapper=$($tunnel.Id) metrics=$MetricsPort"

    $deadline = (Get-Date).AddSeconds(120)
    $url = $null
    while ((Get-Date) -lt $deadline) {
        if ($server.HasExited -or $tunnel.HasExited) { throw "Server or tunnel exited; see $DataDir logs." }
        $text = Get-Content -LiteralPath $tunnelLog -Raw -ErrorAction SilentlyContinue
        if ($text) {
            $match = [regex]::Match($text, 'https://[a-z0-9-]+\.trycloudflare\.com')
            if ($match.Success -and $text -match 'Registered tunnel connection.*protocol=http2') {
                $url = $match.Value
                break
            }
        }
        Start-Sleep -Seconds 1
    }
    if (-not $url) { throw "Quick Tunnel URL/connection timed out; see $tunnelLog" }
    New-Item -ItemType Directory -Path (Split-Path -Parent $UrlFile) -Force | Out-Null
    Set-Content -LiteralPath $UrlFile -Value $url -Encoding ASCII
    Add-Content -LiteralPath $runLog -Value "$(Get-Date -Format o) ready $url"
    while (-not $server.HasExited -and -not $tunnel.HasExited) { Start-Sleep -Seconds 1 }
    throw "Server or tunnel stopped; see $DataDir logs."
} catch {
    Add-Content -LiteralPath $runLog -Value "$(Get-Date -Format o) ERROR $($_.Exception.Message)"
    Write-Error -Message $_.Exception.Message -ErrorAction Continue
    exit 1
} finally {
    Remove-Item -LiteralPath $UrlFile -Force -ErrorAction SilentlyContinue
    # Exiting this dedicated host closes its job handle and stops its children.
}
