using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.RazorPages;
using Microsoft.EntityFrameworkCore;

namespace HANKAN.Web.Pages.Admin;

public sealed class AuditModel(AppDbContext db) : PageModel
{
    public List<AuditEvent> Items { get; private set; } = [];
    public Dictionary<string, string> Actors { get; private set; } = [];
    public long? OlderThan { get; private set; }
    public DateTime SnapshotUtc { get; private set; }
    public AuditVerification Verification { get; private set; } = null!;

    public async Task<IActionResult> OnGetAsync(long? before)
    {
        await using var transaction = await db.Database.BeginTransactionAsync();
        Verification = db.VerifyAudit();
        SnapshotUtc = Verification.ExecutedUtc;
        var query = db.AuditEvents.AsNoTracking();
        if (before is > 0) query = query.Where(item => item.Id < before);
        var batch = await query.OrderByDescending(item => item.Id).Take(31).ToListAsync();
        Items = batch.Take(30).ToList();
        if (batch.Count > 30) OlderThan = Items[^1].Id;
        var ids = Items.Select(item => item.ActorId).Distinct().ToList();
        Actors = await db.Users.AsNoTracking().Where(user => ids.Contains(user.Id))
            .ToDictionaryAsync(user => user.Id, user => user.Email ?? user.Id);
        return Page();
    }

    public string Actor(AuditEvent item) => item.ActorId switch
    {
        "anonymous" => "익명",
        "anonymous-share" => "익명 공유 이용자",
        "system" => "시스템",
        _ => Actors.GetValueOrDefault(item.ActorId, "탈퇴 또는 알 수 없는 계정")
    };
}
