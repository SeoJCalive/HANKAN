# 실행 계정의 CurrentUser DPAPI 비밀 등록/교체. 원문 인자는 받지 않는다.
[CmdletBinding()]
param(
    [Parameter(Mandatory)][ValidateSet('PfxPassword', 'TunnelToken')][string]$Kind,
    [Parameter(Mandatory)][string]$DataDir
)
$ErrorActionPreference = 'Stop'
Add-Type -AssemblyName System.Security
$temporary = $null
$plain = $null
$restored = $null
$bstr = [IntPtr]::Zero
try {
    $DataDir = [IO.Path]::GetFullPath($DataDir)
    $directory = Join-Path $DataDir 'access-secrets'
    $webRoot = [IO.Path]::GetFullPath((Join-Path $PSScriptRoot '..\src\HANKAN.Web\wwwroot'))
    if ($directory.StartsWith($webRoot + '\', [StringComparison]::OrdinalIgnoreCase) -or
        $directory.Equals($webRoot, [StringComparison]::OrdinalIgnoreCase)) { throw 'Static path.' }
    for ($item = $directory; $item; $item = Split-Path -Parent $item) {
        if ((Test-Path -LiteralPath $item) -and
            ((Get-Item -LiteralPath $item -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
            throw 'Linked path.'
        }
    }
    New-Item -ItemType Directory -Path $directory -Force | Out-Null
    $sid = [Security.Principal.WindowsIdentity]::GetCurrent().User
    $system = New-Object Security.Principal.SecurityIdentifier('S-1-5-18')
    $acl = New-Object Security.AccessControl.DirectorySecurity
    $acl.SetOwner($sid)
    $acl.SetAccessRuleProtection($true, $false)
    foreach ($principal in @($sid, $system)) {
        $acl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule(
            $principal, 'FullControl', 'ContainerInherit,ObjectInherit', 'None', 'Allow')))
    }
    Set-Acl -LiteralPath $directory -AclObject $acl
    $name = if ($Kind -eq 'PfxPassword') { 'pfx-password.dpapi' } else { 'tunnel-token.dpapi' }
    $destination = Join-Path $directory $name
    if ((Test-Path -LiteralPath $destination) -and
        ((Get-Item -LiteralPath $destination -Force).Attributes -band [IO.FileAttributes]::ReparsePoint)) {
        throw 'Linked secret.'
    }
    $secure = Read-Host -Prompt $Kind -AsSecureString
    $bstr = [Runtime.InteropServices.Marshal]::SecureStringToBSTR($secure)
    $value = [Runtime.InteropServices.Marshal]::PtrToStringBSTR($bstr)
    if ($Kind -eq 'TunnelToken' -and [string]::IsNullOrWhiteSpace($value)) { throw 'Empty token.' }
    $plain = [Text.Encoding]::UTF8.GetBytes($value)
    $value = $null
    $blob = [Security.Cryptography.ProtectedData]::Protect($plain, $null, 'CurrentUser')
    $restored = [Security.Cryptography.ProtectedData]::Unprotect($blob, $null, 'CurrentUser')
    if ($plain.Length -ne $restored.Length) { throw 'Round trip failed.' }
    $difference = 0
    for ($i = 0; $i -lt $plain.Length; $i++) { $difference = $difference -bor ($plain[$i] -bxor $restored[$i]) }
    if ($difference -ne 0) { throw 'Round trip failed.' }
    $temporary = Join-Path $directory ([Guid]::NewGuid().ToString('N') + '.dpapi')
    [IO.File]::WriteAllBytes($temporary, $blob)
    $fileAcl = New-Object Security.AccessControl.FileSecurity
    $fileAcl.SetOwner($sid)
    $fileAcl.SetAccessRuleProtection($true, $false)
    foreach ($principal in @($sid, $system)) {
        $fileAcl.AddAccessRule((New-Object Security.AccessControl.FileSystemAccessRule($principal, 'FullControl', 'Allow')))
    }
    Set-Acl -LiteralPath $temporary -AclObject $fileAcl
    if (Test-Path -LiteralPath $destination) {
        Set-Acl -LiteralPath $destination -AclObject $fileAcl
        [IO.File]::Replace($temporary, $destination, $null)
    } else { [IO.File]::Move($temporary, $destination) }
    Write-Output 'DPAPI 비밀을 등록했습니다. 같은 Windows 계정에서 앱을 재시작하세요.'
} catch {
    # Provider exceptions and input values must not enter transcripts or logs.
    Write-Error '비밀 등록에 실패했습니다. 경로, 연결 폴더, 실행 계정과 권한을 확인하세요.' -ErrorAction Continue
    exit 1
} finally {
    if ($plain) { [Array]::Clear($plain, 0, $plain.Length) }
    if ($restored) { [Array]::Clear($restored, 0, $restored.Length) }
    if ($bstr -ne [IntPtr]::Zero) { [Runtime.InteropServices.Marshal]::ZeroFreeBSTR($bstr) }
    if ($secure) { $secure.Dispose() }
    if ($temporary -and (Test-Path -LiteralPath $temporary)) { Remove-Item -LiteralPath $temporary -Force }
}
