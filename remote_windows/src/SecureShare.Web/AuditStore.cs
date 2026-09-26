using System.Security.Claims;
using Microsoft.EntityFrameworkCore;

namespace SecureShare.Web;

public sealed class AuditStore(AppDbContext db, SetupStore setup)
{
    public Task RecordAsync(ClaimsPrincipal principal, string action, string? targetId, string result) =>
        RecordAsync(principal.FindFirstValue(ClaimTypes.NameIdentifier) ?? "anonymous", action, targetId, result);

    public async Task RecordAsync(string actorId, string action, string? targetId, string result)
    {
        if (setup.State != SetupState.Ready) return;
        db.AuditEvents.Add(new AuditEvent
        {
            ActorId = actorId,
            Action = action,
            TargetId = targetId,
            Result = result
        });
        await db.SaveChangesAsync();
    }
}
