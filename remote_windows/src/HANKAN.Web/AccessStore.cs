using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;

namespace HANKAN.Web;

public sealed record AccountAccess(string Email, bool IsAdmin, string State, string? RequestedRole);

public sealed class AccessStore(AppDbContext db, SetupStore setup, FileTransferGate gate)
{
    public async Task<AccountAccess?> CurrentAsync(ClaimsPrincipal principal)
    {
        if (setup.State != SetupState.Ready) return null;
        var id = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (id is null) return null;
        return await db.Users.AsNoTracking().Where(user => user.Id == id)
            .Select(user => new AccountAccess(user.Email ?? "", user.IsAdmin, user.AccessState, user.RequestedRole))
            .SingleOrDefaultAsync();
    }

    public async Task<bool> RequestAsync(ClaimsPrincipal principal, string role)
    {
        if (role is not ("VIEWER" or "OWNER") || setup.State != SetupState.Ready) return false;
        var id = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (id is null) return false;
        return await db.Users.Where(user => user.Id == id && !user.IsAdmin && user.AccessState == "unrequested")
            .ExecuteUpdateAsync(update => update.SetProperty(user => user.AccessState, "pending")
                .SetProperty(user => user.RequestedRole, role)) == 1;
    }

    public async Task<bool> ChangeAsync(ClaimsPrincipal principal, string targetId, string action, string? role)
    {
        if (setup.State != SetupState.Ready || string.IsNullOrWhiteSpace(targetId)) return false;
        var actorId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (actorId is null) return false;
        if (action == "grant" && role is not ("VIEWER" or "OWNER")) return false;
        if (action is not ("grant" or "reject" or "expel")) return false;

        await gate.Transfer.WaitAsync();
        try
        {
        await using var transaction = await db.Database.BeginTransactionAsync();
        await db.Database.ExecuteSqlRawAsync("UPDATE \"AppState\" SET \"Id\" = \"Id\" WHERE \"Id\" = 1");
        if (!await db.Users.AsNoTracking().AnyAsync(user => user.Id == actorId && user.IsAdmin)) return false;
        var target = await db.Users.AsNoTracking().Where(user => user.Id == targetId && !user.IsAdmin)
            .Select(user => new { user.AccessState }).SingleOrDefaultAsync();
        if (target is null) return false;
        var next = action switch
        {
            "grant" when target.AccessState is "pending" or "rejected" or "expelled" or "viewer" or "owner" => role!.ToLowerInvariant(),
            "reject" when target.AccessState == "pending" => "rejected",
            "expel" when target.AccessState is "viewer" or "owner" => "expelled",
            _ => null
        };
        if (next is null || next == target.AccessState) return false;
        var changed = await db.Users.Where(user => user.Id == targetId && !user.IsAdmin && user.AccessState == target.AccessState)
            .ExecuteUpdateAsync(update => update.SetProperty(user => user.AccessState, next));
        if (changed != 1) return false;
        if (target.AccessState == "owner" && next != "owner")
            await db.Shares.Where(share => share.CreatorId == targetId && share.CancelledUtc == null)
                .ExecuteUpdateAsync(update => update.SetProperty(share => share.CancelledUtc, DateTime.UtcNow));
        await transaction.CommitAsync();
        return true;
        }
        finally { gate.Transfer.Release(); }
    }
}

public sealed record AccessRequirement(string Role) : IAuthorizationRequirement;

public sealed class AccessHandler(AccessStore access, AuditStore audit) : AuthorizationHandler<AccessRequirement>
{
    protected override async Task HandleRequirementAsync(AuthorizationHandlerContext context, AccessRequirement requirement)
    {
        var current = await access.CurrentAsync(context.User);
        if (current is null) return;
        if (requirement.Role == "member" || current.IsAdmin && requirement.Role is "admin" or "viewer" or "owner" ||
            requirement.Role == "viewer" && current.State is "viewer" or "owner" ||
            requirement.Role == "owner" && current.State == "owner")
            context.Succeed(requirement);
        else
            await audit.RecordAsync(context.User, "access.denied." + requirement.Role, null, "denied");
    }
}
