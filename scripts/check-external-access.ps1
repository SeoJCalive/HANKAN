# 임시 인스턴스 전용 읽기 검사. 서버/터널/예약 작업은 생성하지 않는다.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateRange(1024, 65535)][int]$Port,
    [Parameter(Mandatory)][string]$StartupId,
    [switch]$ExpectReady,
    [ValidateSet('local', 'direct', 'tunnel')][string]$ExpectedMode = 'local',
    [int]$ExpectedProcessId = 0,
    [switch]$CheckHttpPasswordBoundary
)
$ErrorActionPreference = 'Stop'
function Get-Startup([string]$Id, [bool]$Forwarded = $false) {
    $request = [Net.HttpWebRequest]::Create("http://127.0.0.1:$Port/_local/startup")
    $request.Proxy = $null
    $request.AllowAutoRedirect = $false
    $request.Timeout = 5000
    $request.Headers.Add('X-Hankan-Startup-Id', $Id)
    if ($Forwarded) { $request.Headers.Add('CF-Connecting-IP', '192.0.2.1') }
    try { $response = $request.GetResponse() }
    catch [Net.WebException] {
        if (-not $_.Exception.Response) { throw }
        $response = $_.Exception.Response
    }
    try {
        $reader = New-Object IO.StreamReader($response.GetResponseStream())
        try { $body = $reader.ReadToEnd() } finally { $reader.Dispose() }
        return @{ Code = [int]$response.StatusCode; Body = $body; Cache = $response.Headers['Cache-Control'] }
    } finally { $response.Close() }
}
$status = Get-Startup $StartupId
$expected = if ($ExpectReady) { 200 } else { 503 }
if ($status.Code -ne $expected -or $status.Cache -ne 'no-store') { throw 'Startup status/cache mismatch.' }
$body = $status.Body | ConvertFrom-Json
if ($body.setupReady -ne [bool]$ExpectReady -or $body.processId -le 0) { throw 'Startup response mismatch.' }
if ($body.effectiveMode -ne $ExpectedMode) { throw 'Effective mode mismatch.' }
if ($ExpectedProcessId -gt 0 -and $body.processId -ne $ExpectedProcessId) { throw 'Child PID mismatch.' }
if ((Get-Startup ([Guid]::NewGuid().ToString('N'))).Code -ne 403) { throw 'Wrong invocation accepted.' }
if ((Get-Startup $StartupId $true).Code -ne 403) { throw 'Forwarded readiness accepted.' }
Write-Output 'PASS: startup state, effective mode, invocation binding, forwarding rejection, no-store'
if ($CheckHttpPasswordBoundary) {
    foreach ($path in @('/lOgIn', '/Register', '/sHaReS?handler=cReAtE', '/Shares?handler=Other&handler=Create')) {
        $request = [Net.HttpWebRequest]::Create("http://127.0.0.1:$Port$path")
        $request.Proxy = $null
        $request.AllowAutoRedirect = $false
        $request.Timeout = 5000
        $request.Method = 'POST'
        $request.ContentLength = 0
        try { $response = $request.GetResponse() }
        catch [Net.WebException] {
            if (-not $_.Exception.Response) { throw }
            $response = $_.Exception.Response
        }
        try {
            if ([int]$response.StatusCode -ne 403) { throw 'HTTP password endpoint did not reject before authentication.' }
        } finally { $response.Close() }
    }
    Write-Output 'PASS: HTTP login, registration, share creation reject before authentication/body binding'
}
