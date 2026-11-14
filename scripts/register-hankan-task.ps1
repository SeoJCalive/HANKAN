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
$user = [Security.Principal.WindowsIdentity]::GetCurrent().Name
if ($user.Split('\')[-1] -ine 'BILAB') { throw 'Register this task as the logged-on BILAB user.' }
$RepoPath = [IO.Path]::GetFullPath($RepoPath)
$DataDir = [IO.Path]::GetFullPath($DataDir)
$UrlFile = [IO.Path]::GetFullPath($UrlFile)
$script = Join-Path $RepoPath 'scripts\start-hankan-tunnel.ps1'
if (-not (Test-Path -LiteralPath $script -PathType Leaf)) { throw "Missing script: $script" }
if ($Port -eq $MetricsPort) { throw 'Server and metrics ports must differ.' }

# Encode the command to preserve spaces and apostrophes in every path.
$command = "& '" + $script.Replace("'", "''") + "'"
foreach ($entry in @{
    RepoPath = $RepoPath; DataDir = $DataDir; Port = $Port
    MetricsPort = $MetricsPort; UrlFile = $UrlFile; TaskName = $TaskName
}.GetEnumerator()) {
    $command += " -$($entry.Key) '" + ([string]$entry.Value).Replace("'", "''") + "'"
}
$encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($command))
$action = New-ScheduledTaskAction -Execute "$PSHOME\powershell.exe" `
    -Argument "-NoProfile -ExecutionPolicy Bypass -EncodedCommand $encoded" -WorkingDirectory $RepoPath
$principal = New-ScheduledTaskPrincipal -UserId $user -LogonType Interactive -RunLevel Limited
$trigger = New-ScheduledTaskTrigger -AtLogOn -User $user
$settings = New-ScheduledTaskSettingsSet -Disable -MultipleInstances IgnoreNew `
    -ExecutionTimeLimit ([TimeSpan]::Zero) -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries
Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal `
    -Trigger $trigger -Settings $settings -Description 'HANKAN server and Quick Tunnel at BILAB logon (opt-in).'
