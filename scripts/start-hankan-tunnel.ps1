[CmdletBinding()]
param(
    [string]$RepoPath = 'C:\Users\BILAB\LinuxWorkspace\HANKAN',
    [string]$DataDir = 'D:\HANKAN\data',
    [ValidateRange(1024, 65535)][int]$Port = 5180,
    [ValidateRange(1024, 65535)][int]$MetricsPort = 5196,
    [string]$UrlFile = 'D:\HANKAN\tunnel-url.txt',
    [string]$TaskName = 'HANKAN-AutoStart',
    [switch]$UseAccessModeFile,
    [string]$CloudflaredPath = 'C:\Program Files (x86)\cloudflared\cloudflared.exe',
    [string]$TunnelHome = (Join-Path $env:LOCALAPPDATA 'HANKAN-Tunnel')
)

$ErrorActionPreference = 'Stop'
$RepoPath = [IO.Path]::GetFullPath($RepoPath)
$DataDir = [IO.Path]::GetFullPath($DataDir)
$UrlFile = [IO.Path]::GetFullPath($UrlFile)
$serverLog = if ($DataDir -eq 'D:\HANKAN\data') { 'D:\HANKAN\server.log' } else { Join-Path $DataDir 'server.log' }
$runLog = Join-Path $DataDir 'autostart.log'
$ownerFile = $UrlFile + '.owner'
$owner = [Guid]::NewGuid().ToString('N')
$server = $null
$tunnel = $null
$invocationLock = $null
$ownsUrl = $false

function Write-RunLog([string]$Message) {
    Add-Content -LiteralPath $runLog -Value "$(Get-Date -Format o) $Message"
}

function Test-LegacyRegistration {
    if ($UseAccessModeFile) { return $false }
    $task = Get-ScheduledTask -TaskName $TaskName -ErrorAction SilentlyContinue
    foreach ($action in $task.Actions) {
        if ($action.Arguments -notmatch '(?i)-EncodedCommand\s+([A-Za-z0-9+/=]+)') { continue }
        $command = [Text.Encoding]::Unicode.GetString([Convert]::FromBase64String($Matches[1]))
        $scriptPath = Join-Path $RepoPath 'scripts\start-hankan-tunnel.ps1'
        if (-not $command.StartsWith("& '" + $scriptPath.Replace("'", "''") + "'") -or
            $command -match '(?i)-UseAccessModeFile') { continue }
        $same = $true
        foreach ($entry in @{
            RepoPath = $RepoPath; DataDir = $DataDir; Port = $Port
            MetricsPort = $MetricsPort; UrlFile = $UrlFile; TaskName = $TaskName
        }.GetEnumerator()) {
            $argument = " -$($entry.Key) '" + ([string]$entry.Value).Replace("'", "''") + "'"
            if (-not $command.Contains($argument)) { $same = $false }
        }
        if ($same) { return $true }
    }
    return $false
}

function New-ChildInfo([string]$File, [string]$Arguments, [string]$Directory) {
    $info = New-Object Diagnostics.ProcessStartInfo
    $info.FileName = $File
    $info.Arguments = $Arguments
    $info.WorkingDirectory = $Directory
    # Only the child's environment is changed; never mutate user/machine/host env.
    foreach ($key in @($info.EnvironmentVariables.Keys)) {
        if ($key -like 'TUNNEL_*' -or $key -in @('HTTP_PROXY', 'HTTPS_PROXY', 'ALL_PROXY', 'NO_PROXY')) {
            $info.EnvironmentVariables.Remove($key)
        }
    }
    return $info
}

function Start-App([bool]$ForceLocal) {
    $script:startupId = [Guid]::NewGuid().ToString('N')
    $info = New-ChildInfo $dotnet ('"' + $assembly + '"') $projectDirectory
    $info.EnvironmentVariables['HANKAN_DATA_DIR'] = $DataDir
    $info.EnvironmentVariables['HANKAN_PORT'] = $Port.ToString()
    $info.EnvironmentVariables['HANKAN_STARTUP_ID'] = $script:startupId
    $info.EnvironmentVariables['HANKAN_FORCE_LOCAL'] = if ($ForceLocal) { '1' } else { '0' }
    $child = New-Object HankanChild($info, $serverLog, 'server', '')
    Write-RunLog "host=$PID server=$($child.Process.Id) port=$Port"
    return $child
}

function Get-AppStatus {
    $deadline = (Get-Date).AddSeconds(60)
    while ((Get-Date) -lt $deadline) {
        if ($server.Process.HasExited -or $server.OutputFailed) { throw 'App startup failed.' }
        $response = $null
        try {
            $request = [Net.HttpWebRequest]::Create("http://127.0.0.1:$Port/_local/startup")
            $request.Proxy = $null
            $request.AllowAutoRedirect = $false
            $request.Timeout = 2000
            $request.Headers.Add('X-Hankan-Startup-Id', $startupId)
            try { $response = $request.GetResponse() }
            catch [Net.WebException] { $response = $_.Exception.Response }
            if ($response -and [int]$response.StatusCode -in @(200, 503)) {
                $reader = New-Object IO.StreamReader($response.GetResponseStream())
                try { $status = $reader.ReadToEnd() | ConvertFrom-Json }
                finally { $reader.Dispose() }
                if ($status.processId -eq $server.Process.Id -and
                    (([int]$response.StatusCode -eq 200) -eq ($status.setupReady -eq $true))) {
                    return $status
                }
            }
        } finally { if ($response) { $response.Close() } }
        Start-Sleep -Seconds 1
    }
    throw 'App startup timed out.'
}

function Read-TunnelToken([string]$Reference) {
    $secretDirectory = Join-Path $DataDir 'access-secrets'
    $path = [IO.Path]::GetFullPath((Join-Path $DataDir $Reference))
    if (-not $path.StartsWith($secretDirectory + '\', [StringComparison]::OrdinalIgnoreCase)) {
        throw 'Invalid secret path.'
    }
    $current = $path
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
    while ($current) {
        if ((Get-Item -LiteralPath $current -Force).Attributes -band [IO.FileAttributes]::ReparsePoint) {
            throw 'Reparse point is not allowed.'
        }
        if ($current -eq $path -or $current -eq $secretDirectory) {
            foreach ($rule in (Get-Acl -LiteralPath $current).Access) {
                if ($rule.AccessControlType -eq 'Allow' -and
                    $rule.IdentityReference.Translate([Security.Principal.SecurityIdentifier]).Value -notin @($sid, 'S-1-5-18')) {
                    throw 'Secret ACL is too broad.'
                }
            }
        }
        $current = Split-Path -Parent $current
    }
    $blob = [IO.File]::ReadAllBytes($path)
    $plain = $null
    try {
        $plain = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null,
            [Security.Cryptography.DataProtectionScope]::CurrentUser)
        $value = [Text.Encoding]::UTF8.GetString($plain)
        if ([string]::IsNullOrWhiteSpace($value)) { throw 'Empty token.' }
        return $value
    } finally {
        [Array]::Clear($blob, 0, $blob.Length)
        if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
    }
}

try {
    if ([Security.Principal.WindowsIdentity]::GetCurrent().Name.Split('\')[-1] -ine 'BILAB') {
        throw 'Run as the logged-on BILAB user.'
    }
    New-Item -ItemType Directory -Path $DataDir -Force | Out-Null
    $invocationLock = [IO.File]::Open((Join-Path $DataDir 'autostart.lock'), 'OpenOrCreate', 'ReadWrite', 'None')
    if (Get-NetTCPConnection -State Listen -LocalPort $Port -ErrorAction SilentlyContinue) {
        throw 'Internal port is already listening.'
    }
    $projectDirectory = Join-Path $RepoPath 'src\HANKAN.Web'
    $assembly = Join-Path $projectDirectory 'bin\Debug\net10.0\HANKAN.Web.dll'
    if (-not (Test-Path -LiteralPath $assembly -PathType Leaf)) { throw 'Build the app first.' }
    $dotnet = (Get-Command dotnet -CommandType Application).Source
    $settingsPath = Join-Path $DataDir 'access-mode.json'
    $migrationMarker = Join-Path $DataDir 'access-mode.initialized'
    if (-not (Test-Path -LiteralPath $settingsPath) -and -not (Test-Path -LiteralPath $migrationMarker) -and
        (Test-LegacyRegistration)) {
        $temporary = $settingsPath + '.new'
        [IO.File]::WriteAllText($temporary, '{"version":1,"mode":"tunnel","trustedProxyIps":["127.0.0.1"]}')
        $acl = New-Object Security.AccessControl.FileSecurity
        $acl.SetAccessRuleProtection($true, $false)
        foreach ($identity in @([Security.Principal.WindowsIdentity]::GetCurrent().User,
            (New-Object Security.Principal.SecurityIdentifier('S-1-5-18')))) {
            $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($identity, 'FullControl', 'Allow')))
        }
        Set-Acl -LiteralPath $temporary -AclObject $acl
        Move-Item -LiteralPath $temporary -Destination $settingsPath
        Write-RunLog 'Inherited legacy Quick registration as explicit tunnel settings.'
    }
    if ((Test-Path -LiteralPath $settingsPath) -or $UseAccessModeFile) {
        [IO.File]::WriteAllText($migrationMarker, 'v1')
    }
    New-Item -ItemType Directory -Path (Split-Path -Parent $UrlFile) -Force | Out-Null
    Remove-Item -LiteralPath $UrlFile -Force -ErrorAction SilentlyContinue
    if (Test-Path -LiteralPath $UrlFile) { throw 'Cannot remove old URL.' }
    [IO.File]::WriteAllText($ownerFile, $owner)
    $ownsUrl = $true
    Add-Type -Path (Join-Path $PSScriptRoot 'HankanProcessHost.cs')
    Add-Type -AssemblyName System.Security
    # The watcher is outside our job; it only removes this invocation's URL.
    $watchCommand = "Wait-Process -Id $PID -ErrorAction SilentlyContinue; if ((Get-Content -LiteralPath '" +
        $ownerFile.Replace("'", "''") + "' -Raw -ErrorAction SilentlyContinue) -eq '$owner') { Remove-Item -LiteralPath '" +
        $UrlFile.Replace("'", "''") + "','" + $ownerFile.Replace("'", "''") + "' -Force -ErrorAction SilentlyContinue }"
    $encoded = [Convert]::ToBase64String([Text.Encoding]::Unicode.GetBytes($watchCommand))
    $watcher = Start-Process -FilePath "$PSHOME\powershell.exe" -WindowStyle Hidden `
        -ArgumentList '-NoProfile', '-EncodedCommand', $encoded -PassThru
    Write-RunLog "url-watcher=$($watcher.Id) host=$PID"
    [HankanProcessJob]::Attach()
    $server = Start-App $false
    $status = Get-AppStatus
    if ($status.setupReady -eq $true -and $status.requestedMode -eq 'tunnel' -and
        $status.effectiveMode -eq 'tunnel' -and $status.applied -eq $true -and -not $status.restartRequired) {
        try {
            if ($Port -eq $MetricsPort -or
                (Get-NetTCPConnection -State Listen -LocalPort $MetricsPort -ErrorAction SilentlyContinue)) {
                throw 'Metrics port unavailable.'
            }
            $config = Join-Path $TunnelHome 'cloudflared-empty.yml'
            foreach ($file in @($CloudflaredPath, $config)) {
                if (-not (Test-Path -LiteralPath $file -PathType Leaf)) { throw 'Missing tunnel file.' }
            }
            if ([IO.File]::ReadAllText($config).Trim() -notin @('', '{}')) { throw 'Tunnel config must be empty.' }
            $version = [HankanChild]::Probe((New-ChildInfo $CloudflaredPath 'version' $TunnelHome))
            $versionMatch = [regex]::Match($version, 'cloudflared version [0-9.]+')
            if (-not $versionMatch.Success) { throw 'Unknown cloudflared version.' }
            Write-RunLog $versionMatch.Value
            $arguments = 'tunnel --config "{0}" --protocol http2 --no-autoupdate --metrics 127.0.0.1:{1}' -f $config, $MetricsPort
            $token = ''
            if ($status.tunnelKind -eq 'fixed') {
                $help = [HankanChild]::Probe((New-ChildInfo $CloudflaredPath 'tunnel run --help' $TunnelHome))
                if ($help -notmatch '\bTUNNEL_TOKEN\b') { throw 'Child token environment is unsupported.' }
                $token = Read-TunnelToken $status.tokenFile
                $arguments += " run --url http://127.0.0.1:$Port"
            } elseif ($status.tunnelKind -eq 'quick') {
                $arguments += " --url http://127.0.0.1:$Port"
            } else { throw 'Invalid tunnel selection.' }
            $info = New-ChildInfo $CloudflaredPath $arguments $TunnelHome
            if ($status.tunnelKind -eq 'fixed') { $info.EnvironmentVariables['TUNNEL_TOKEN'] = $token }
            try {
                $tunnel = New-Object HankanChild($info, (Join-Path $DataDir 'tunnel.log'), $status.tunnelKind, $token)
            } finally {
                $info.EnvironmentVariables.Remove('TUNNEL_TOKEN')
                $token = $null
            }
            Write-RunLog "tunnel=$($tunnel.Process.Id) metrics=$MetricsPort"
            $deadline = (Get-Date).AddSeconds(120)
            $connected = $false
            while ((Get-Date) -lt $deadline) {
                if ($server.Process.HasExited -or $tunnel.Process.HasExited -or $tunnel.OutputFailed) {
                    throw 'Tunnel startup failed.'
                }
                if ($tunnel.Connected -and ($status.tunnelKind -eq 'fixed' -or $tunnel.QuickUrl)) {
                    $request = [Net.HttpWebRequest]::Create("http://127.0.0.1:$MetricsPort/ready")
                    $request.Proxy = $null
                    $request.Timeout = 2000
                    $request.AllowAutoRedirect = $false
                    try {
                        $response = $request.GetResponse()
                        try { $connected = [int]$response.StatusCode -eq 200 } finally { $response.Close() }
                    } catch [Net.WebException] {
                        if ($_.Exception.Response) { $_.Exception.Response.Close() }
                    }
                    if ($connected) { break }
                }
                Start-Sleep -Seconds 1
            }
            if (-not $connected) { throw 'Tunnel readiness timed out.' }
            if ($status.tunnelKind -eq 'quick') {
                Set-Content -LiteralPath $UrlFile -Value $tunnel.QuickUrl -Encoding ASCII
                Write-RunLog "Quick ready $($tunnel.QuickUrl)"
            } else {
                Write-RunLog "Fixed connector ready; configured origin=$($status.publicOrigin); ingress unverified."
            }
            while (-not $server.Process.HasExited -and -not $tunnel.Process.HasExited -and
                -not $tunnel.OutputFailed -and -not $server.OutputFailed) { Start-Sleep -Seconds 1 }
            throw 'App or tunnel stopped.'
        } catch {
            # Never log exception details, command lines, token, or child environment.
            if ($tunnel) { $tunnel.Dispose(); $tunnel = $null }
            if ($server) { $server.Dispose(); $server = $null }
            Remove-Item -LiteralPath $UrlFile -Force -ErrorAction SilentlyContinue
            Write-RunLog 'Tunnel failed. Restarting only this app in local mode.'
            $server = Start-App $true
            $status = Get-AppStatus
            if ($status.effectiveMode -ne 'local') { throw 'Local fallback failed.' }
        }
    }
    Write-RunLog "Supervising app; effectiveMode=$($status.effectiveMode)."
    while (-not $server.Process.HasExited -and -not $server.OutputFailed) { Start-Sleep -Seconds 1 }
    throw 'App stopped.'
} catch {
    if (Test-Path -LiteralPath $DataDir) { Write-RunLog 'Startup or app failed. This invocation is stopping.' }
    Write-Error -Message 'HANKAN startup failed. Check local status and sanitized logs.' -ErrorAction Continue
    exit 1
} finally {
    if ($tunnel) { $tunnel.Dispose() }
    if ($server) { $server.Dispose() }
    if ($ownsUrl -and (Get-Content -LiteralPath $ownerFile -Raw -ErrorAction SilentlyContinue) -eq $owner) {
        Remove-Item -LiteralPath $UrlFile, $ownerFile -Force -ErrorAction SilentlyContinue
    }
    if ($invocationLock) { $invocationLock.Dispose() }
    # Forced host termination also closes the Job Object and kills its children.
}
