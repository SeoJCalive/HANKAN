# 한칸 (HANKAN)

**HAN:KAN**은 Windows PC의 폴더를 웹 기반 파일 저장·공유 공간으로 사용하는 학교 프로젝트다. 관리자는 저장 위치와 용량을 정하고, 승인된 사용자는 VIEWER 또는 OWNER 권한으로 파일을 이용한다. 파일은 링크로 공유하거나 관리자가 공개 목록에 게시할 수 있다.

계정·권한 검사, 파일 저장 암호화(AES-256-GCM), Windows DPAPI 키 보호, 공유 만료·취소와 변조 감지를 구현했다. 계정과 링크·공개 공유 비밀번호는 Argon2id(메모리 19 MiB·반복 2회·병렬도 1)로 저장하며, 기존 PBKDF2 비밀번호는 계속 검증하고 정답 확인 시 자동 전환한다. 서버를 운영하는 관리자에게도 파일 내용을 숨기는 종단간 암호화 서비스는 아니다.

로그인과 공유 비밀번호는 계정 또는 공유 항목과 접속 IP의 실패를 각각 독립 집계한다. 어느 한쪽이 두 번 틀리면 외부 서비스 없는 PoW 추가 확인이 표시되고, 다음 비밀번호 검사부터 유효한 증명이 필요하다. 추가 확인 버튼은 JavaScript·Web Worker·Web Crypto를 사용해 계산한 뒤 폼을 제출한다. JavaScript가 꺼져 있으면 초기 두 번까지 일반 폼을 쓸 수 있으며 추가 확인이 필요한 상태에서는 통과할 수 없다.

실패 집계는 첫 실패부터 고정 15분이며 정답 비밀번호 인증 성공 시 해당 계정/공유 항목과 IP 집계를 함께 초기화한다. 확인 문제는 2분 동안 유효하고 한 번만 사용할 수 있다. PoW를 푸는 것만으로 실패 집계가 지워지지 않는다. 단일 운영 프로세스의 메모리에 보관하므로 재시작하면 집계·사용 목록·서명키가 초기화되고 이전 문제는 무효가 된다. 기존 계정 5회/1분 잠금, 공유 5회/15분 차단 및 HTTP 요청 제한은 별도로 유지된다. 비밀번호 없는 공유에는 추가 확인을 요구하지 않는다.

## Windows에서 실행

1. [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)을 설치한다.
2. 저장소를 내려받은 뒤 PowerShell에서 다음 명령을 실행한다.

   ```powershell
   dotnet run --project .\src\HANKAN.Web\HANKAN.Web.csproj
   ```

3. 서버 PC에서 기본 주소 `http://127.0.0.1:5180/`을 연다. `HANKAN_PORT`를 지정했다면 해당 포트를 사용한다. 콘솔에 표시된 일회용 설정 코드를 입력하고 관리자 이메일·비밀번호, 비어 있는 전용 저장 폴더의 **Windows 절대 경로**, 전체 용량 한도를 지정한다.
4. 최초 설정 후 일반 사용자는 비로그인 상태에서 계정을 만들고 VIEWER 또는 OWNER 권한을 신청한다. 관리자는 로그인하여 신청을 승인한다. 승인된 사용자는 공용 저장소의 폴더를 탐색하고 파일을 내려받을 수 있다. 파일과 폴더를 다중 선택해 하위 항목까지 ZIP으로 받을 수 있다. 관리자와 OWNER는 폴더 생성, 파일 업로드, 이름 변경, 드래그 또는 목적지 창으로 이동, 삭제 영향 확인 후 하위 항목까지 영구 삭제할 수 있다.

앱은 Windows 루프백 주소에서만 수신한다. 다른 기기에서 접속하려면 최초 설정을 완료한 뒤 별도의 HTTPS 연결 경로를 구성해야 한다. 브라우저에서 복사한 공유 주소는 현재 접속한 주소를 사용한다.

계정·설정·SQLite 데이터베이스 `hankan.db`의 기본 데이터 폴더는 실행한 Windows 계정의 `%LOCALAPPDATA%\HANKAN`이며 `HANKAN_DATA_DIR`로 바꿀 수 있다. 업로드 파일은 최초 설정에서 지정한 폴더에 암호화되어 저장된다. 기존 데이터를 유지하려면 **같은 Windows 계정에서 실제 사용하는 앱 데이터 폴더와 파일 저장 폴더를 함께 보관**해야 한다. 둘 중 하나를 잃거나 다른 PC로 옮기면 파일에 접근하지 못할 수 있다.

기존 설치를 새 버전으로 실행하면 이전 순차 갱신에 이어 데이터베이스가 v6→v7(감사 체인)→v8(파일 KEK)로 자동 변경된다. 감사 체인 필드·상태·재시작 목록과 최초 키 생성은 하나의 트랜잭션으로 반영된다. 파일 KEK 전환도 별도의 한 트랜잭션에서 컬럼·KEK·모든 파일 키·스키마 버전을 함께 확정하며, 한 행이라도 실패하면 전체 전환을 취소하고 복구 필요 상태로 멈춘다. 업데이트 전 자동 재시작을 막고 앱을 종료하여 실제 데이터 폴더(기본 `%LOCALAPPDATA%\HANKAN`, 지정 시 `HANKAN_DATA_DIR`) 전체(`hankan.db`·`instance.marker`·존재하는 SQLite 부속 파일 포함)와 설정의 암호문 저장 폴더를 **같은 시점에 함께 백업**한다. 구버전은 새 스키마와 Argon2id 해시를 읽을 수 있다고 가정하지 않는다. 복구할 때는 앱을 종료한 뒤 **코드와 DB·데이터·암호문 저장 폴더를 배포 전의 같은 시점으로 함께 복원**한다. 실패 상태의 SQLite 부속 파일은 복원한 DB와 섞이지 않게 분리한다.

파일마다 무작위 32바이트 DEK로 내용을 AES-256-GCM 암호화한다. 단일 32바이트 KEK는 Windows CurrentUser DPAPI로 보호하여 DB의 설정 행에만 저장하고, 각 DEK를 AES-GCM으로 감싼다. 기존 형식 1(DPAPI 직접 보호)은 시작 시 요청 처리 전에 모두 형식 2로 전환한다. 형식 2의 키 BLOB은 표지 1바이트·별도 wrap nonce 12바이트·DEK 암호문 32바이트·tag 16바이트이며, 소문자 N 형식 파일 ID를 AAD에 결합하여 다른 파일의 키로 교체하면 인증에 실패한다. 암호문 파일과 내용용 nonce/tag, 파일 ID·이름·크기·공유 연결은 변경하지 않는다. 재시작 때 기존 KEK를 복원하며 누락·손상 시 새 키를 만들지 않는다. 같은 Windows 실행 계정의 DPAPI 보호 상태가 필요하며 다른 PC로 이동하거나 Windows를 재설치한 뒤의 복구는 보장하지 않는다. 공유 토큰 키와 감사 HMAC 키는 기존의 별도 DPAPI 보호를 유지한다.

## 감사 기록 검증과 복구

배포 이후 사건은 1부터 증가하는 순번과 이전 MAC을 포함한 HMAC-SHA256 체인으로 저장한다. 무작위 32바이트 HMAC 키는 Windows CurrentUser DPAPI로 보호한 BLOB으로 DB에 보관하며 재시작 후에도 같은 키를 사용한다. 별도 평문 키 파일은 없다. 같은 Windows 실행 계정의 DPAPI 복원 권한을 유지해야 한다. 완료된 설치의 키·상태 누락이나 키 복원 실패는 복구 필요 상태이며 키를 자동 재생성하지 않는다.

관리자의 `/Admin/Audit`는 조회와 같은 DB 스냅샷에서 전체 보존 체인을 읽기 전용으로 검증하고 실행·시작 UTC, 순번 범위·건수, 배포 전 제외 건수, OK 또는 최초 실패 위치·이유와 정상 보존 삭제 재시작점을 표시한다. 배포 전 행은 다시 서명하거나 본문을 바꾸지 않으며 배포 경계 이하의 체인 필드가 모두 없는 행만 검증에서 제외한다.

30일·논리적 100 MiB 보존 정책은 그대로다. 논리적 크기는 기존 사건 7개 필드의 UTF-8 값 합계이며 키·MAC·삭제 구간과 물리 DB 크기를 포함하지 않는다. 시각·Id 순서의 정상 삭제는 인증된 삭제 순번 구간과 끝 MAC을 남기므로 중간·끝 사건 또는 전체 사건이 정리되어도 다음 순번으로 검증을 이어간다. 정상 삭제된 본문과 배포 전 기록의 진실성은 검증 범위 밖이다. 외부에서 일어난 모든 행위의 완전성, 부인 방지, 외부 시각 증명도 보장하지 않는다.

서버 실행 계정으로 DPAPI 복원과 DB 쓰기를 모두 할 수 있는 접근자는 키로 체인을 다시 계산할 수 있다. 키·상태·삭제 구간을 포함한 DB 전체를 과거의 일관된 스냅샷으로 되돌리는 공격도 외부 체크포인트 없이 탐지하지 못한다.

시작 시 무결성 실패가 발견되면 정상 삭제와 파일 복구 쓰기를 중단하고 명시적으로 앱 로그에 남긴다. 이미 인증된 관리자는 검증 화면에서 실패를 확인할 수 있다. 새 감사 기록이 필요한 로그인 등은 복구 전 실패할 수 있다. 체인 재생성으로 OK를 만들지 않는다. 먼저 실행 계정과 데이터 경로를 확인하고, 앱과 자동 재시작을 중지한 뒤 실패 데이터·로그를 별도 보존한다. 배포 전 같은 시점의 코드·데이터 폴더·암호문 폴더를 함께 복원하고 같은 계정으로 빌드·재시작하여 로그인과 작은 파일 다운로드를 확인한다. 백업 이후의 변경은 복원 시점으로 돌아간다.

## BILAB 로그온 시 서버와 Quick Tunnel 시작

운영 PC에서 BILAB으로 대화형 로그인한 상태로 등록·실행한다. 예약 작업은 해당 계정의 `Interactive` 로그온과 사용자 로그온 트리거를 사용한다. 기존 파일의 CurrentUser DPAPI 키를 사용하므로 같은 Windows 계정을 유지한다. Windows 서비스나 암호 저장은 사용하지 않으며, 로그온 전에는 실행되지 않는다.

등록 전 PowerShell에서 저장소를 빌드하고 cloudflared 설치 및 전용 빈 설정을 준비한다. 이미 있는 전용 빈 설정은 재사용하며 사용자 `.cloudflared` 설정은 수정하지 않는다.

```powershell
Set-Location C:\Users\BILAB\LinuxWorkspace\HANKAN
dotnet build .\src\HANKAN.Web\HANKAN.Web.csproj
winget install --id Cloudflare.cloudflared --exact
$TunnelHome = Join-Path $env:LOCALAPPDATA 'HANKAN-Tunnel'
New-Item -ItemType Directory -Path $TunnelHome -Force | Out-Null
if (-not (Test-Path "$TunnelHome\cloudflared-empty.yml")) {
    Set-Content "$TunnelHome\cloudflared-empty.yml" '{}' -Encoding ASCII
}
powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\register-hankan-task.ps1
```

`HANKAN-AutoStart`는 **비활성 상태로 등록**된다. 일회 확인 전 기존 수동 서버·터널의 PID를 확인하고 각각의 실행 콘솔에서 중지하여 5180·5196을 비운다. 시작 스크립트는 어느 포트든 점유돼 있으면 기존 listener를 종료하거나 재사용하지 않고 오류로 끝낸다.

```powershell
Get-NetTCPConnection -State Listen -LocalPort 5180,5196 -ErrorAction SilentlyContinue
Enable-ScheduledTask -TaskName 'HANKAN-AutoStart'
Start-ScheduledTask -TaskName 'HANKAN-AutoStart'
Get-ScheduledTask -TaskName 'HANKAN-AutoStart' | Format-List Principal,Triggers,State
Get-ScheduledTaskInfo -TaskName 'HANKAN-AutoStart'
Get-Content D:\HANKAN\data\autostart.log -Tail 10
```

`autostart.log`에 `ready`가 기록된 뒤 다음 명령으로 서버와 이번 URL을 확인한다. 시작 스크립트는 서버 준비 후 같은 PC에서 HTTP/2 Quick Tunnel을 실행하며 metrics는 `127.0.0.1:5196`을 사용한다. 서버 로그는 `D:\HANKAN\server.log`, 터널 로그는 `D:\HANKAN\data\tunnel.log`다. 실패는 `autostart.log`와 작업 결과에 남고 실행 시작 시 이전 URL을 지운다.

```powershell
Invoke-WebRequest -UseBasicParsing http://127.0.0.1:5180/Login
$Url = (Get-Content D:\HANKAN\tunnel-url.txt -Raw).Trim()
Invoke-WebRequest -UseBasicParsing ($Url + '/Login')
Disable-ScheduledTask -TaskName 'HANKAN-AutoStart'
Get-ScheduledTask -TaskName 'HANKAN-AutoStart' | Select-Object TaskName,State
```

등록·일회 확인 후에는 위와 같이 비활성화해 둔다. 비활성화는 다음 로그온 실행을 막으며 **현재 실행 중인 서버·터널은 계속 실행된다**. 이후 자동 시작을 선택할 때 활성화 한 줄은 `Enable-ScheduledTask -TaskName 'HANKAN-AutoStart'`다. 즉시 실행하려면 활성화 후 `Start-ScheduledTask`도 실행한다.

URL 파일에는 이번 실행의 `https://...trycloudflare.com` 임시 주소가 들어간다. 터널 재시작 때 주소가 바뀌므로 새 주소에서 공유 URL을 다시 복사한다. 주소 발급과 외부 HTTPS 도달은 별도로 확인한다. URL은 해당 실행이 살아 있는 동안만 유효하며, 강제 종료를 포함해 실행이 끝나면 URL 파일을 삭제한다.

두 스크립트는 같은 매개변수를 받으며 등록 스크립트는 모두 시작 스크립트에 전달한다.

| 매개변수 | 기본값 |
| --- | --- |
| `-RepoPath` | `C:\Users\BILAB\LinuxWorkspace\HANKAN` |
| `-DataDir` | `D:\HANKAN\data` |
| `-Port` | `5180` (`HANKAN_PORT` 환경값 대신 지정값 사용) |
| `-MetricsPort` | `5196` |
| `-UrlFile` | `D:\HANKAN\tunnel-url.txt` |
| `-TaskName` | `HANKAN-AutoStart` |

별도 데이터 폴더를 지정하면 서버 로그도 그 폴더의 `server.log`에 쓴다. 시험 시에는 여섯 값을 모두 운영용과 분리한다. 시작 스크립트를 직접 실행할 때도 전용 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-hankan-tunnel.ps1 ...` 프로세스를 사용한다.

실행 중지와 수동 운영 복귀는 아래 순서로 한다. `Stop-ScheduledTask`는 이 실행이 시작한 서버·터널을 Windows Job Object로 함께 정리한다. 수동 실행한 기존 프로세스에는 적용하지 않는다. 재등록이 필요하면 중지 후 `Unregister-ScheduledTask -TaskName 'HANKAN-AutoStart' -Confirm:$false`로 해제하고 등록한다.

```powershell
Disable-ScheduledTask -TaskName 'HANKAN-AutoStart'
Stop-ScheduledTask -TaskName 'HANKAN-AutoStart'
Get-NetTCPConnection -State Listen -LocalPort 5180,5196 -ErrorAction SilentlyContinue
cmd /c 'set HANKAN_DATA_DIR=D:\HANKAN\data&& set HANKAN_PORT=5180&& cd /d C:\Users\BILAB\LinuxWorkspace\HANKAN && dotnet run --no-build --project src\HANKAN.Web\HANKAN.Web.csproj > D:\HANKAN\server.log 2>&1'
```

수동 서버 응답을 확인한 뒤 별도 `powershell.exe -NoProfile` 콘솔에서 기존 Quick Tunnel을 수동 실행한다. 이 콘솔은 사용하는 동안 유지하고 종료할 때 Ctrl+C를 누른다.

```powershell
$TunnelHome = Join-Path $env:LOCALAPPDATA 'HANKAN-Tunnel'
Set-Location $TunnelHome
Get-ChildItem Env: |
    Where-Object { $_.Name -like 'TUNNEL_*' -or $_.Name -in @('HTTP_PROXY','HTTPS_PROXY','ALL_PROXY','NO_PROXY') } |
    ForEach-Object { Remove-Item ('Env:' + $_.Name) }
& 'C:\Program Files (x86)\cloudflared\cloudflared.exe' tunnel `
    --config "$TunnelHome\cloudflared-empty.yml" --url http://127.0.0.1:5180 `
    --protocol http2 --no-autoupdate --metrics 127.0.0.1:5196
```

2026-10-04 당시 격리 시험에서 28개 시나리오 중 21개가 통과했고 7개는 일부 조건만 확인했다. 이후 개별 시험에서 잘못된 전송 길이·디스크 부족·삭제 중 사용량 정산, 격리 인스턴스의 별도 휴대폰 전송과 요청 제한 회귀를 확인했다. 현재 남은 일은 완성본 전체 통합 시험과 운영 실계정·휴대폰 확인이다. DB와 표식 동시 소실의 기록·판정, 작업 종료 후 앱 저장 폴더와 앱 임시 경로에 평문 파일이 남지 않음, 모든 역할·상태의 작은 화면·키보드 조작 등은 통합 시험에서 함께 확인한다.

이 저장소는 수업 시연용 버전이며, 후속 단계에서 상시 운영을 위한 배포·백업 운영·보안 점검 체계를 확장한다.
