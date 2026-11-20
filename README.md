# 한칸 (HANKAN)

**HAN:KAN**은 Windows PC의 폴더를 웹 기반 파일 저장·공유 공간으로 사용하는 학교 프로젝트다. 관리자는 저장 위치와 용량을 정하고, 승인된 사용자는 VIEWER 또는 OWNER 권한으로 파일을 이용한다. 파일은 링크로 공유하거나 관리자가 공개 목록에 게시할 수 있다.

계정·권한 검사, 파일 저장 암호화(AES-256-GCM), Windows DPAPI 키 보호, 공유 만료·취소와 변조 감지를 구현했다. 계정과 링크·공개 공유 비밀번호는 Argon2id(메모리 19 MiB·반복 2회·병렬도 1)로 저장하며, 기존 PBKDF2 비밀번호는 계속 검증하고 정답 확인 시 자동 전환한다. 서버를 운영하는 관리자에게도 파일 내용을 숨기는 종단간 암호화 서비스는 아니다.

로그인과 공유 비밀번호는 계정 또는 공유 항목과 접속 IP의 실패를 각각 독립 집계한다. 어느 한쪽이 두 번 틀리면 외부 서비스 없는 PoW 추가 확인이 표시되고, 다음 비밀번호 검사부터 유효한 증명이 필요하다. 추가 확인 버튼은 JavaScript·Web Worker·Web Crypto를 사용해 계산한 뒤 폼을 제출한다. JavaScript가 꺼져 있으면 초기 두 번까지 일반 폼을 쓸 수 있으며 추가 확인이 필요한 상태에서는 통과할 수 없다.

실패 집계는 첫 실패부터 고정 15분이며 정답 비밀번호 인증 성공 시 해당 계정/공유 항목과 IP 집계를 함께 초기화한다. 확인 문제는 2분 동안 유효하고 한 번만 사용할 수 있다. PoW를 푸는 것만으로 실패 집계가 지워지지 않는다. 단일 운영 프로세스의 메모리에 보관하므로 재시작하면 집계·사용 목록·서명키가 초기화되고 이전 문제는 무효가 된다. 기존 계정 5회/1분 잠금, 공유 5회/15분 차단 및 HTTP 요청 제한은 별도로 유지된다. 비밀번호 없는 공유에는 추가 확인을 요구하지 않는다.

## Windows에서 실행

1. [.NET 10 SDK](https://dotnet.microsoft.com/download/dotnet/10.0)을 설치한다.
2. 저장소를 내려받은 뒤 PowerShell에서 다음 명령을 실행한다.

   ```powershell
   dotnet run --no-launch-profile --project .\src\HANKAN.Web\HANKAN.Web.csproj
   ```

3. 서버 PC에서 기본 주소 `http://127.0.0.1:5180/`을 연다. `HANKAN_PORT`를 지정했다면 해당 포트를 사용한다. 콘솔에 표시된 일회용 설정 코드를 입력하고 관리자 이메일·비밀번호, 비어 있는 전용 저장 폴더의 **Windows 절대 경로**, 전체 용량 한도를 지정한다.
4. 최초 설정을 완료하면 앱을 중지하고 아래 접속 모드 안내에 따라 HTTPS를 준비한 뒤 재시작한다. 기본 로컬 HTTP에서는 일반 로그인·가입·비밀번호 공유를 사용할 수 없다. HTTPS에서 일반 사용자는 계정을 만들고 VIEWER 또는 OWNER 권한을 신청하며 관리자는 로그인하여 승인한다. 승인된 사용자는 공용 폴더 탐색과 파일·ZIP 다운로드를 사용할 수 있고, 관리자·OWNER는 폴더 생성·업로드·이름 변경·이동·삭제를 수행할 수 있다.

새 실행은 기본적으로 루프백만 수신한다. 미설정·복구 상태에서도 루프백만 열며 같은 실행 중 설정을 마쳐도 외부 수신을 추가하지 않는다. 모드는 파일로 정하고 재시작 때 적용한다. 브라우저에서 복사한 공유 주소는 현재 접속한 origin을 사용한다.

계정·설정·SQLite 데이터베이스 `hankan.db`의 기본 데이터 폴더는 실행한 Windows 계정의 `%LOCALAPPDATA%\HANKAN`이며 `HANKAN_DATA_DIR`로 바꿀 수 있다. 업로드 파일은 최초 설정에서 지정한 폴더에 암호화되어 저장된다. 기존 데이터를 유지하려면 **같은 Windows 계정에서 실제 사용하는 앱 데이터 폴더와 파일 저장 폴더를 함께 보관**해야 한다. 둘 중 하나를 잃거나 다른 PC로 옮기면 파일에 접근하지 못할 수 있다.

기존 설치를 새 버전으로 실행하면 이전 순차 갱신에 이어 데이터베이스가 v6→v7(감사 체인)→v8(파일 KEK)로 자동 변경된다. 감사 체인 필드·상태·재시작 목록과 최초 키 생성은 하나의 트랜잭션으로 반영된다. 파일 KEK 전환도 별도의 한 트랜잭션에서 컬럼·KEK·모든 파일 키·스키마 버전을 함께 확정하며, 한 행이라도 실패하면 전체 전환을 취소하고 복구 필요 상태로 멈춘다. 업데이트 전 자동 재시작을 막고 앱을 종료하여 실제 데이터 폴더(기본 `%LOCALAPPDATA%\HANKAN`, 지정 시 `HANKAN_DATA_DIR`) 전체(`hankan.db`·`instance.marker`·존재하는 SQLite 부속 파일 포함)와 설정의 암호문 저장 폴더를 **같은 시점에 함께 백업**한다. 구버전은 새 스키마와 Argon2id 해시를 읽을 수 있다고 가정하지 않는다. 복구할 때는 앱을 종료한 뒤 **코드와 DB·데이터·암호문 저장 폴더를 배포 전의 같은 시점으로 함께 복원**한다. 실패 상태의 SQLite 부속 파일은 복원한 DB와 섞이지 않게 분리한다.

파일마다 무작위 32바이트 DEK로 내용을 AES-256-GCM 암호화한다. 단일 32바이트 KEK는 Windows CurrentUser DPAPI로 보호하여 DB의 설정 행에만 저장하고, 각 DEK를 AES-GCM으로 감싼다. 기존 형식 1(DPAPI 직접 보호)은 시작 시 요청 처리 전에 모두 형식 2로 전환한다. 형식 2의 키 BLOB은 표지 1바이트·별도 wrap nonce 12바이트·DEK 암호문 32바이트·tag 16바이트이며, 소문자 N 형식 파일 ID를 AAD에 결합하여 다른 파일의 키로 교체하면 인증에 실패한다. 암호문 파일과 내용용 nonce/tag, 파일 ID·이름·크기·공유 연결은 변경하지 않는다. 재시작 때 기존 KEK를 복원하며 누락·손상 시 새 키를 만들지 않는다. 같은 Windows 실행 계정의 DPAPI 보호 상태가 필요하며 다른 PC로 이동하거나 Windows를 재설치한 뒤의 복구는 보장하지 않는다. 공유 토큰 키와 감사 HMAC 키는 기존의 별도 DPAPI 보호를 유지한다.

## 감사 기록 검증과 복구

배포 이후 사건은 1부터 증가하는 순번과 이전 MAC을 포함한 HMAC-SHA256 체인으로 저장한다. 무작위 32바이트 HMAC 키는 Windows CurrentUser DPAPI로 보호한 BLOB으로 DB에 보관하며 재시작 후에도 같은 키를 사용한다. 별도 평문 키 파일은 없다. 같은 Windows 실행 계정의 DPAPI 복원 권한을 유지해야 한다. 완료된 설치의 키·상태 누락이나 키 복원 실패는 복구 필요 상태이며 키를 자동 재생성하지 않는다.

관리자의 `/Admin/Audit`는 조회와 같은 DB 스냅샷에서 전체 보존 체인을 읽기 전용으로 검증하고 실행·시작 UTC, 순번 범위·건수, 배포 전 제외 건수, OK 또는 최초 실패 위치·이유와 정상 보존 삭제 재시작점을 표시한다. 배포 전 행은 다시 서명하거나 본문을 바꾸지 않으며 배포 경계 이하의 체인 필드가 모두 없는 행만 검증에서 제외한다.

30일·논리적 100 MiB 보존 정책은 그대로다. 논리적 크기는 기존 사건 7개 필드의 UTF-8 값 합계이며 키·MAC·삭제 구간과 물리 DB 크기를 포함하지 않는다. 시각·Id 순서의 정상 삭제는 인증된 삭제 순번 구간과 끝 MAC을 남기므로 중간·끝 사건 또는 전체 사건이 정리되어도 다음 순번으로 검증을 이어간다. 정상 삭제된 본문과 배포 전 기록의 진실성은 검증 범위 밖이다. 외부에서 일어난 모든 행위의 완전성, 부인 방지, 외부 시각 증명도 보장하지 않는다.

서버 실행 계정으로 DPAPI 복원과 DB 쓰기를 모두 할 수 있는 접근자는 키로 체인을 다시 계산할 수 있다. 키·상태·삭제 구간을 포함한 DB 전체를 과거의 일관된 스냅샷으로 되돌리는 공격도 외부 체크포인트 없이 탐지하지 못한다.

시작 시 무결성 실패가 발견되면 정상 삭제와 파일 복구 쓰기를 중단하고 명시적으로 앱 로그에 남긴다. 이미 인증된 관리자는 검증 화면에서 실패를 확인할 수 있다. 새 감사 기록이 필요한 로그인 등은 복구 전 실패할 수 있다. 체인 재생성으로 OK를 만들지 않는다. 먼저 실행 계정과 데이터 경로를 확인하고, 앱과 자동 재시작을 중지한 뒤 실패 데이터·로그를 별도 보존한다. 배포 전 같은 시점의 코드·데이터 폴더·암호문 폴더를 함께 복원하고 같은 계정으로 빌드·재시작하여 로그인과 작은 파일 다운로드를 확인한다. 백업 이후의 변경은 복원 시점으로 돌아간다.

## 접속 모드 설정

설정 파일은 실제 앱 데이터 폴더의 `access-mode.json`이다. UTF-8 JSON `version: 1`만 받으며 알 수 없는 속성·중복 속성·잘못된 버전·값은 적용 오류다. 실행 중 편집은 다음 재시작에 반영한다. 관리자 구성 화면은 요청 모드·실제 모드·현재 origin·재시작 필요·적용 실패를 읽기 전용으로 표시한다.

| 모드 | 수신과 기능 |
| --- | --- |
| `local` | `127.0.0.1:<HANKAN_PORT>` HTTP만. 최초 설정·복구·공개 확인에 사용한다. |
| `direct` + `https` | 내부 루프백과 명시 IP·포트의 PFX HTTPS. 로그인·가입·비밀번호 공유·PoW를 사용한다. |
| `direct` + `http` | 명시 IP·포트와 `allowHttp: true`가 모두 필요하다. 평문 경고가 표시되고 비밀번호 기능·공유 생성 POST는 403이다. |
| `tunnel` | 앱은 루프백만. AutoStart가 Ready 확인 후 Quick 또는 고정 커넥터 하나를 실행한다. |

HTTP는 파일·링크·입력 내용의 전송 기밀성과 무결성을 보장하지 않는다. 비밀번호 없는 공개·공유는 기존 유효성·만료·취소·무결성 검사를 유지한다. Secure·HttpOnly·SameSite=Lax 쿠키, CSRF, PoW를 HTTP용으로 완화하지 않으므로 브라우저나 antiforgery 제약으로 사용할 수 없는 HTTP 요청은 HTTPS에서 수행한다. 최초 설정의 로컬·일회용 코드 계약은 일반 HTTP 비밀번호 기능의 예외가 아니다.

| 필드 | 값과 제약 |
| --- | --- |
| `version`, `mode` | 정수 `1`; `local`, `direct`, `tunnel`. |
| `trustedProxyIps` | IP 리터럴 배열. 생략은 `[]`. CIDR·hostname·자동 탐색 없음. IPv4-mapped 주소는 정규화한다. |
| `direct.address`, `direct.port` | 필수 IP 리터럴과 1024~65535 정수. 기본값 없음. 내부 포트와 달라야 한다. `0.0.0.0`·`::`도 명시한 경우에만 사용한다. |
| `direct.transport`, `direct.allowHttp` | `https` 또는 `http`. HTTP는 명시적 `true`, HTTPS는 생략 또는 `false`. |
| `direct.pfxPath`, `direct.pfxPasswordFile` | HTTPS 필수 Windows 절대 PFX 경로와 데이터 폴더 기준 DPAPI 파일 참조. |
| `direct.redirectHttpPort` | HTTPS에서만 선택하는 별도 포트. 기본값 없음. 같은 IP에서 GET/HEAD를 지정 HTTPS 포트로 307, POST는 403. 내부·HTTPS 포트와 중복 금지. |
| `tunnel.tokenFile` | 생략/null은 Quick. 파일 참조가 있으면 고정 터널이며 누락·손상·빈 토큰은 오류다. |
| `tunnel.publicOrigin` | 고정 터널의 필수 `https://hostname` origin. 경로·query·fragment·userinfo 금지. Quick에는 지정하지 않는다. |

신규 기본값의 전체 예:

```json
{"version":1,"mode":"local","trustedProxyIps":[]}
```

설정·PFX·비밀은 `wwwroot` 밖에 둔다. symlink/reparse point와 넓은 읽기 ACL은 거부한다. 설정·PFX의 허용 주체는 실행 계정·SYSTEM·필요한 Administrators이고, `access-secrets` 디렉터리와 BLOB은 상속을 끈 실행 계정·SYSTEM만 허용한다. 데이터 폴더를 바꾸면 기존 설정·파일 키와 별개인 새 인스턴스를 선택하므로 운영 데이터와 시험 데이터를 혼용하지 않는다.

### 프록시와 HTTPS

local과 빈 신뢰 목록의 direct는 CF·XFF·Proto 헤더를 무시한다. direct의 지정 프록시와 tunnel의 명시 `127.0.0.1`만 단일 `CF-Connecting-IP` + 단일 `X-Forwarded-Proto: http|https`를 한 홉 반영한다. 지정 프록시는 브라우저가 보낸 두 헤더를 제거하고 검증한 값으로 덮어써야 한다. 누락·다중 값·comma 목록·손상 값은 400이다. 일반 X-Forwarded-For·Forwarded Host·Prefix를 선택하는 기능은 없다.

확정 IP는 요청 제한·로그인/공유 실패 집계·PoW에 공통 사용한다. 감사 행에 실제 IP나 모드 변경 사건을 추가하지 않는다. direct HTTP에서 Proto만 `https`로 전달해도 비밀번호 기능은 열리지 않는다. 비밀번호 허용 근거는 실제 TLS 또는 tunnel 모드의 검증된 HTTPS 전달이다.

직접 HTTPS 응답에만 앱이 `Strict-Transport-Security: max-age=3600`을 붙이며 includeSubDomains·preload는 없다. 명시한 리디렉션 포트만 연다. local·direct HTTP·tunnel에는 앱 HSTS·강제 리디렉션이 없다. IP·localhost의 HSTS 처리에는 브라우저 제약이 있다. Cloudflare의 HTTPS 리디렉션·HSTS는 공개 재승인 후 실제 설정과 응답을 따로 확인한다.

### 임시 Windows 인스턴스와 PFX HTTPS

아래는 운영 대상과 분리한 예다. 새 PowerShell 콘솔에서 저장소 루트로 이동한 뒤 시작한다. 파일 저장 폴더는 최초 설정에서 `$Files`를 입력한다.

```powershell
$Repo = (Get-Location).Path
$Data = Join-Path $env:TEMP 'hankan-eam-qa\data'
$Files = Join-Path $env:TEMP 'hankan-eam-qa\files'
New-Item -ItemType Directory -Path $Data, $Files -Force | Out-Null
$sid = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
icacls $Data /inheritance:r /grant:r ("*" + $sid + ":(OI)(CI)F") '*S-1-5-18:(OI)(CI)F'
$env:HANKAN_DATA_DIR = $Data
$env:HANKAN_PORT = '55180'
dotnet build .\src\HANKAN.Web\HANKAN.Web.csproj --tl:off
dotnet run --no-build --no-launch-profile --project .\src\HANKAN.Web\HANKAN.Web.csproj
```

`http://127.0.0.1:55180/Setup`에서 최초 설정을 끝내고 Ctrl+C로 중지한다. 자동 시작에서는 설정 코드를 로그에 남기지 않으므로 최초 설정은 이 수동 콘솔에서 진행한다.

아래는 시험용 자체 서명 인증서를 생성·내보내는 명령이다. 비밀번호는 두 보안 입력 창에 같은 값을 직접 입력한다. 인자·JSON·환경 변수에 원문을 넣지 않는다.

```powershell
$certificate = New-SelfSignedCertificate -Subject 'CN=localhost' `
    -TextExtension @('2.5.29.17={text}DNS=localhost&IPAddress=127.0.0.1') `
    -CertStoreLocation 'Cert:\CurrentUser\My' -KeyExportPolicy Exportable `
    -NotAfter (Get-Date).AddDays(7)
$password = Read-Host '시험 PFX 비밀번호' -AsSecureString
Export-PfxCertificate -Cert $certificate -FilePath (Join-Path $Data 'test.pfx') -Password $password | Out-Null
$password.Dispose()
.\scripts\set-hankan-access-secret.ps1 -Kind PfxPassword -DataDir $Data
@{
    version = 1
    mode = 'direct'
    trustedProxyIps = @()
    direct = @{
        address = '127.0.0.1'
        port = 55443
        transport = 'https'
        pfxPath = (Join-Path $Data 'test.pfx')
        pfxPasswordFile = 'access-secrets/pfx-password.dpapi'
    }
} | ConvertTo-Json -Depth 4 | Set-Content (Join-Path $Data 'access-mode.json') -Encoding UTF8
dotnet run --no-build --no-launch-profile --project .\src\HANKAN.Web\HANKAN.Web.csproj
```

`https://127.0.0.1:55443/`에서 로그인한다. 앱은 PFX 개인키·유효기간·복원 가능 여부를 검사하고 임시 키로 로드한다. 인증서 발급·도메인 이름·신뢰 체인·만료 전 교체는 운영자의 책임이다. 자체 서명 경고를 무시한 연결은 정상 신뢰 검증 통과가 아니다. 다른 LAN 기기 시험에는 실제 시험 LAN IP를 `direct.address`와 인증서 SAN에 넣고 해당 기기의 신뢰·이름·날짜·경고 결과를 기록한다. 별도 LAN 시간 합격값은 추가하지 않는다.

DPAPI 등록 결과는 `access-secrets/pfx-password.dpapi` 또는 `access-secrets/tunnel-token.dpapi`다. 같은 계정에서 재등록하면 복원 확인을 거친 뒤 기존 BLOB을 교체한다. 다른 계정·손상 BLOB은 복원하지 못한다. PFX·비밀번호 BLOB을 교체한 뒤 재시작해야 새 인증서를 사용한다. DPAPI는 디스크 저장 보호이며 실행 계정이나 관리자 진단 권한으로 프로세스 메모리·자식 환경을 읽는 공격까지 막지 않는다.

### 명시 HTTP와 터널 설정 예

시험 HTTP는 HTTPS 설정 대신 다음 파일을 사용하고 재시작한다. 비밀번호 폼이 사라지고 직접 POST도 거부된다.

```json
{
  "version": 1,
  "mode": "direct",
  "trustedProxyIps": [],
  "direct": {"address": "127.0.0.1", "port": 55181, "transport": "http", "allowHttp": true}
}
```

Quick 설정에는 루프백 신뢰를 명시하고 토큰을 두지 않는다.

```json
{"version":1,"mode":"tunnel","trustedProxyIps":["127.0.0.1"]}
```

고정 터널은 같은 계정에서 `.\scripts\set-hankan-access-secret.ps1 -Kind TunnelToken -DataDir $Data`를 실행하여 보안 입력으로 등록한다. 아래 hostname은 문서용이며 실제 공개 시험에서는 소유자가 관리하는 origin으로 바꾼다.

```json
{
  "version": 1,
  "mode": "tunnel",
  "trustedProxyIps": ["127.0.0.1"],
  "tunnel": {
    "tokenFile": "access-secrets/tunnel-token.dpapi",
    "publicOrigin": "https://files.example.test"
  }
}
```

고정 커넥터는 `cloudflared tunnel run`의 자식 `TUNNEL_TOKEN` 환경만 사용한다. 원문 argv·평문 토큰 파일·사용자/머신 환경으로 우회하지 않는다. 시작 전 설치본 `version`과 `tunnel run --help`에서 환경 전달 지원을 확인하고 지원하지 않으면 local로 남는다. stdout/stderr는 토큰 제거 후 연결 완료·Quick 주소만 허용하여 기록하며 원문 출력·명령 전체·예외 덤프를 남기지 않는다.

고정 연결 준비는 HTTP/2 등록 신호와 loopback metrics `/ready`로 판정한다. `publicOrigin`은 구성된 접속 주소이며 token의 hostname·원격 ingress·`http://127.0.0.1:<내부 포트>` 연결의 일치를 증명하지 않는다. 고정 모드는 Quick URL을 성공 조건으로 쓰거나 URL 파일에 기록하지 않는다.

## BILAB 로그온 시 설정 모드 자동 시작

운영 PC에서 BILAB으로 대화형 로그인한 상태로 등록·실행한다. 예약 작업은 해당 계정의 `Interactive` 로그온과 사용자 로그온 트리거를 사용한다. 기존 파일의 CurrentUser DPAPI 키를 사용하므로 같은 Windows 계정을 유지한다. Windows 서비스나 암호 저장은 사용하지 않으며, 로그온 전에는 실행되지 않는다.

등록 전 수동 최초 설정과 빌드를 끝낸다. local/direct에는 cloudflared·빈 설정·metrics 포트가 필요 없다. tunnel만 설치본과 전용 빈 `cloudflared-empty.yml`(`{}` 또는 빈 파일), HTTP/2, no-autoupdate, 루프백 metrics를 사용한다. 사용자 `.cloudflared` 설정은 수정하지 않는다.

```powershell
.\scripts\register-hankan-task.ps1 -RepoPath $Repo -DataDir $Data `
    -Port 55180 -MetricsPort 55196 -UrlFile (Join-Path $Data 'quick-url.txt') -TaskName 'HANKAN-EAM-QA'
```

새 작업은 **Disabled·동일 계정 Interactive·Limited·IgnoreNew**로 등록되며 `-UseAccessModeFile`을 전달한다. 새 일반 실행의 파일 없음은 local이다. 같은 여섯 인자를 사용하는 기존 예약 작업의 옛 호출에만, 파일과 `access-mode.initialized`가 모두 없을 때 토큰 없는 tunnel 설정을 한 번 저장한다. 명시 파일이 항상 우선하며 명시 파일을 읽거나 계승한 표식이 남으면 파일을 삭제해도 Quick을 다시 만들지 않는다. 기존 작업의 활성 상태는 이 계승에서 바꾸지 않는다.

```powershell
Get-ScheduledTask -TaskName 'HANKAN-EAM-QA' | Format-List Principal,Triggers,Settings,State
# local/direct 임시 시험에서만 선택적으로 실행한다. tunnel은 공개 재승인 또는 시험 대역이 필요하다.
Enable-ScheduledTask -TaskName 'HANKAN-EAM-QA'
Start-ScheduledTask -TaskName 'HANKAN-EAM-QA'
Get-Content (Join-Path $Data 'autostart.log') -Tail 10
Disable-ScheduledTask -TaskName 'HANKAN-EAM-QA'
```

비활성화는 다음 로그온 실행을 막으며 **현재 실행은 계속된다**. 즉시 중지는 `Stop-ScheduledTask`다. 서버 준비는 `/Login`의 200/302가 아니라 내부 `/_local/startup` 응답의 Ready·이번 자식 PID·비밀 없는 실행 정책과 실행별 식별자로 확인한다. 미설정·복구·재시작 필요·적용 실패는 터널을 호출하지 않는다.

URL 파일에는 이번 실행의 `https://...trycloudflare.com` 임시 주소가 들어간다. 터널 재시작 때 주소가 바뀌므로 새 주소에서 공유 URL을 다시 복사한다. 주소 발급과 외부 HTTPS 도달은 별도로 확인한다. URL은 해당 실행이 살아 있는 동안만 유효하며, 강제 종료를 포함해 실행이 끝나면 URL 파일을 삭제한다.

두 스크립트는 기존 여섯 매개변수를 보존한다. 아래 기본값은 기존 등록 호환용이며 시험에서는 위 예처럼 모두 분리한다.

| 매개변수 | 기본값 |
| --- | --- |
| `-RepoPath` | `C:\Users\BILAB\LinuxWorkspace\HANKAN` |
| `-DataDir` | `D:\HANKAN\data` |
| `-Port` | `5180` (`HANKAN_PORT` 환경값 대신 지정값 사용) |
| `-MetricsPort` | `5196` |
| `-UrlFile` | `D:\HANKAN\tunnel-url.txt` |
| `-TaskName` | `HANKAN-AutoStart` |

별도 데이터 폴더를 지정하면 서버 로그도 그 폴더의 `server.log`에 쓴다. 시험 시에는 여섯 값을 모두 운영용과 분리한다. 시작 스크립트를 직접 실행할 때도 전용 `powershell.exe -NoProfile -ExecutionPolicy Bypass -File .\scripts\start-hankan-tunnel.ps1 ...` 프로세스를 사용한다.

시작 스크립트에는 `-UseAccessModeFile`, 시험 대역용 `-CloudflaredPath`, 전용 설정 폴더용 `-TunnelHome`도 있다. 직접 실행은 전용 `powershell.exe` 프로세스에서 한다. `Stop-ScheduledTask`·강제 종료 시 Job Object는 이번 실행의 자식만 정리한다. 이전 실행의 URL을 재사용하지 않으며 종료 watcher도 이번 URL의 소유 표식을 확인한다.

```powershell
Disable-ScheduledTask -TaskName 'HANKAN-EAM-QA'
Stop-ScheduledTask -TaskName 'HANKAN-EAM-QA'
# 수동 local 복귀: 기존 데이터·키는 보존하고 선택 파일만 바꾼다.
'{"version":1,"mode":"local","trustedProxyIps":[]}' |
    Set-Content (Join-Path $Data 'access-mode.json') -Encoding UTF8
dotnet run --no-build --no-launch-profile --project .\src\HANKAN.Web\HANKAN.Web.csproj
```

설정·PFX·DPAPI·직접 바인딩 실패는 부분 리스너를 닫고 새 local 호스트만 시작한다. tunnel 실행·연결 실패는 이번 터널과 앱을 중지한 뒤 새 식별자의 local 앱을 다시 시작하여 계속 감독한다. 토큰 실패를 Quick으로 대체하지 않는다. 내부 포트도 점유되면 다른 포트 선택이나 기존 PID 종료 없이 이번 실행만 끝낸다. 설정 파일은 보존하므로 수정 후 재시작한다.

## 검증 범위

Linux에서는 `dotnet build src/HANKAN.Web/HANKAN.Web.csproj --tl:off`와 `dotnet run --project tests/AccessModes.Checks/AccessModes.Checks.csproj --no-launch-profile`로 컴파일·정책 검사를 수행할 수 있다. DPAPI·Windows 작업 예약·실제 TLS/LAN 동작의 증거를 대신하지 않는다. `scripts/check-external-access.ps1`는 이미 실행한 임시 인스턴스의 준비 경계만 읽으며 서버·터널·작업을 만들지 않는다.

새 모드의 Windows 내부 시험·다른 LAN 기기의 직접 HTTPS 결과는 별도 QA에서 기록한다. 자체 서명 신뢰·origin·작은 파일 바이트/해시·HTTP 제약·기존 PoW/쿠키/CSRF 회귀를 분리한다. LAN 시간 기준을 새로 추가하지 않는다. 최대 파일·자원·전체 통합 시나리오는 미실행이면 기존 미완료 상태를 유지한다.

2026-11-20 소유자 재승인 후 격리 Windows 인스턴스에서 원본 스크립트의 Quick은 외부 로그인 화면·71바이트 익명 공유 다운로드와 해시 일치·중지 후 외부 차단을 통과했다. `a7adc97`의 원본 고정 시작은 원격 ingress가 없는 구성에서 원점 `--url` 누락으로 외부 503에 실패했으며, `fix/fixed-tunnel-origin-url`의 `70bd475`에서 수정했다. 수정한 원본 스크립트 그대로 재시험해 기본 TLS 검증·앱 HSTS 없음·외부 로그인·세션 쿠키 속성·64바이트 업로드·직접/익명 공유 다운로드와 원본 해시 일치·실제 화면의 공유 origin·커넥터 종료 후 외부 차단과 loopback local 복귀를 통과했다. 제공된 명령행·로그·JSON·User/Machine 환경 값과 보안 입력 콘솔 캡처의 토큰 원문 비교는 일치 0이었으나 Windows가 명령행을 제공하지 않은 보호 프로세스 15개는 비교하지 못했다. 임시 자원·토큰 BLOB은 정리했고 운영 인스턴스는 보존했다. 최대 파일·시간·자원·전체 통합과 인터넷 직접 공개는 미검증이다.

2026-10-04 당시 격리 시험에서 28개 시나리오 중 21개가 통과했고 7개는 일부 조건만 확인했다. 이후 개별 시험에서 잘못된 전송 길이·디스크 부족·삭제 중 사용량 정산, 격리 인스턴스의 별도 휴대폰 전송과 요청 제한 회귀를 확인했다. 현재 남은 일은 완성본 전체 통합 시험과 운영 실계정·휴대폰 확인이다. DB와 표식 동시 소실의 기록·판정, 작업 종료 후 앱 저장 폴더와 앱 임시 경로에 평문 파일이 남지 않음, 모든 역할·상태의 작은 화면·키보드 조작 등은 통합 시험에서 함께 확인한다.

이 저장소는 수업 시연용 버전이며, 후속 단계에서 상시 운영을 위한 배포·백업 운영·보안 점검 체계를 확장한다.
