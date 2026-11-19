using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace HANKAN.Web.Pages.Admin;

public sealed class AuditModel(AppDbContext db) : PageModel
{
    public List<AuditReadEvent> Items { get; private set; } = [];
    public Dictionary<string, string> Actors { get; private set; } = [];
    public long? OlderThan { get; private set; }
    public DateTime SnapshotUtc { get; private set; }
    public AuditVerification Verification { get; private set; } = null!;

    public async Task<IActionResult> OnGetAsync(long? before)
    {
        await using var transaction = await db.Database.BeginTransactionAsync();
        Verification = db.VerifyAudit();
        SnapshotUtc = Verification.ExecutedUtc;
        var query = AuditChain.ReadEvents(db).AsEnumerable();
        if (before is > 0) query = query.Where(item => item.Id < before);
        var batch = query.OrderByDescending(item => item.Id).Take(31).ToList();
        Items = batch.Take(30).ToList();
        if (batch.Count > 30) OlderThan = Items[^1].Id;
        var ids = Items.Select(item => item.ActorId).Distinct().ToList();
        Actors = await db.Users.AsNoTracking().Where(user => ids.Contains(user.Id))
            .ToDictionaryAsync(user => user.Id, user => user.Email ?? user.Id);
        return Page();
    }

    public string Actor(AuditReadEvent item) => item.ActorId switch
    {
        "anonymous" => "익명",
        "anonymous-share" => "익명 공유 이용자",
        "system" => "시스템",
        _ => Actors.GetValueOrDefault(item.ActorId, "탈퇴 또는 알 수 없는 계정")
    };

    public string EventName(string action) => action switch
    {
        "auth.login" => "로그인",
        "auth.login.locked" => "로그인 잠금",
        "auth.logout" => "로그아웃",
        "auth.register" => "계정 가입",
        "access.request" => "권한 신청",
        "access.grant" => "역할 부여",
        "access.reject" => "권한 신청 거절",
        "access.expel" => "계정 추방",
        "access.change" => "권한 변경",
        "access.denied.member" => "계정 접근 거부",
        "access.denied.viewer" => "공용 파일 접근 거부",
        "access.denied.owner" => "파일 관리 접근 거부",
        "access.denied.admin" => "관리자 접근 거부",
        "file.upload" => "파일 업로드",
        "file.rename" => "파일 이름 변경",
        "file.move" => "파일 이동",
        "file.delete" => "파일 영구 삭제",
        "file.delete.requested" => "파일 영구 삭제 요청",
        "file.delete.succeeded" => "파일 영구 삭제 완료",
        "file.delete.failed" => "파일 영구 삭제 실패",
        "file.integrity_or_unavailable" => "파일 무결성 또는 이용 가능 여부 확인 실패",
        "file.download.started" => "다운로드 응답 시작",
        "file.download.sent" => "서버 전송 완료",
        "file.download.interrupted" => "서버 전송 중단",
        "folder.create" => "폴더 생성",
        "folder.rename" => "폴더 이름 변경",
        "folder.move" => "폴더 이동",
        "folder.delete" => "폴더 삭제",
        "selection.delete.preview" => "선택 항목 삭제 영향 확인",
        "selection.delete" => "선택 항목 영구 삭제",
        "selection.delete.requested" => "선택 항목 영구 삭제 요청",
        "selection.move" => "선택 항목 이동",
        "selection.download" => "선택 항목 다운로드",
        "share.create" => "공유 생성",
        "share.create.link" => "링크 공유 생성",
        "share.create.public" => "공개 공유 생성",
        "share.cancel" => "공유 취소",
        "share.access" => "공유 접근",
        "share.password" => "공유 비밀번호 확인",
        "share.password.limited" => "공유 비밀번호 시도 제한",
        "defense.rate_limited" => "요청 제한",
        "defense.csrf" => "위조 요청 거부",
        _ => "알 수 없는 사건"
    };
}
