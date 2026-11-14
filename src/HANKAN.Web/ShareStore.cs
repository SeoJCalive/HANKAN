using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;

namespace HANKAN.Web;

public sealed record PublicShare(string Name, long SizeBytes, bool PasswordNeeded, string Token);
public sealed record ShareView(string Id, string Name, string Creator, string Mode, DateTime ExpiresUtc, string Status);
public sealed record SharedFile(string Id, string Name, long SizeBytes, DateTime ExpiresUtc, bool PasswordNeeded);

public sealed class ShareStore(AppDbContext db, SetupStore setup, FileTransferGate gate)
{
    public async Task<(string? Token, string? Error)> CreateAsync(ClaimsPrincipal principal, string fileId, string mode,
        DateTime expiresUtc, string? password)
    {
        if (!OperatingSystem.IsWindows() || setup.State != SetupState.Ready || mode is not ("link" or "public")) return (null, "공유를 만들 수 없습니다.");
        var now = DateTime.UtcNow;
        if (expiresUtc.Kind != DateTimeKind.Utc || expiresUtc <= now.AddHours(1) ||
            expiresUtc > now.AddDays(7)) return (null, "만료 시각은 현재부터 1시간 초과, 7일 이내로 지정하세요.");
        if (password is { Length: > 0 and < 4 or > 128 }) return (null, "공유 비밀번호는 4~128자로 입력하세요.");
        var actorId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (actorId is null) return (null, "공유 권한을 확인하세요.");
        await using var transaction = await db.Database.BeginTransactionAsync();
        await LockWritesAsync();
        var actor = await db.Users.AsNoTracking().SingleOrDefaultAsync(user => user.Id == actorId);
        if (actor is null || !actor.IsAdmin && actor.AccessState != "owner" || mode == "public" && !actor.IsAdmin)
            return (null, "공유 권한을 확인하세요.");
        if (!await db.StoredFiles.AsNoTracking().AnyAsync(file => file.Id == fileId && file.State == "available"))
            return (null, "사용 가능한 파일을 선택하세요.");

        var tokenBytes = RandomNumberGenerator.GetBytes(32);
        var tokenKey = RandomNumberGenerator.GetBytes(32);
        try
        {
            var grant = new ShareGrant
            {
                FileId = fileId,
                CreatorId = actorId,
                CreatorEmail = actor.Email ?? "",
                Mode = mode,
                ExpiresUtc = expiresUtc,
                TokenHash = Convert.ToHexString(SHA256.HashData(tokenBytes)),
                ProtectedTokenKey = ProtectedData.Protect(tokenKey, null, DataProtectionScope.CurrentUser),
                TokenNonce = RandomNumberGenerator.GetBytes(12),
                TokenCipher = new byte[tokenBytes.Length],
                TokenTag = new byte[16]
            };
            using (var aes = new AesGcm(tokenKey, grant.TokenTag.Length))
                aes.Encrypt(grant.TokenNonce, tokenBytes, grant.TokenCipher, grant.TokenTag);
            if (!string.IsNullOrEmpty(password))
                grant.PasswordHash = Encoding.UTF8.GetBytes(PasswordHashing.HashPassword(password));
            db.Shares.Add(grant);
            db.AuditEvents.Add(new AuditEvent { ActorId = actorId, Action = "share.create." + mode, FileId = fileId, TargetId = grant.Id });
            await db.SaveChangesAsync();
            await transaction.CommitAsync();
            return (Convert.ToHexString(tokenBytes).ToLowerInvariant(), null);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(tokenBytes);
            CryptographicOperations.ZeroMemory(tokenKey);
        }
    }

    public async Task<List<PublicShare>> PublicAsync()
    {
        if (setup.State != SetupState.Ready) return [];
        var now = DateTime.UtcNow;
        var rows = await (from share in db.Shares.AsNoTracking()
            join file in db.StoredFiles.AsNoTracking() on share.FileId equals file.Id
            where share.Mode == "public" && share.CancelledUtc == null && share.ExpiresUtc > now && file.State == "available"
            orderby share.CreatedUtc descending
            select new { Share = share, file.OriginalName, file.SizeBytes }).ToListAsync();
        var result = new List<PublicShare>();
        foreach (var row in rows)
        {
            var token = RevealToken(row.Share);
            if (token is not null) result.Add(new PublicShare(row.OriginalName, row.SizeBytes,
                row.Share.PasswordHash is not null, token));
        }
        return result;
    }

    public async Task<List<ShareView>> ListAsync(ClaimsPrincipal principal)
    {
        var actorId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (setup.State != SetupState.Ready || actorId is null) return [];
        var actor = await db.Users.AsNoTracking().SingleOrDefaultAsync(user => user.Id == actorId);
        if (actor is null || !actor.IsAdmin && actor.AccessState != "owner") return [];
        var rows = await (from share in db.Shares.AsNoTracking()
            join file in db.StoredFiles.AsNoTracking() on share.FileId equals file.Id
            where actor.IsAdmin || share.CreatorId == actorId && share.Mode == "link"
            orderby share.CreatedUtc descending
            select new { Share = share, file.OriginalName, file.State }).ToListAsync();
        var now = DateTime.UtcNow;
        return rows.Select(row => new ShareView(row.Share.Id, row.OriginalName, row.Share.CreatorEmail,
            row.Share.Mode, row.Share.ExpiresUtc, row.Share.CancelledUtc is not null ? "취소됨" :
                row.Share.ExpiresUtc <= now ? "만료됨" : row.State != "available" ? "원본 사용 불가" : "활성")).ToList();
    }

    public async Task<string?> CopyTokenAsync(ClaimsPrincipal principal, string id)
    {
        var actorId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (setup.State != SetupState.Ready || actorId is null) return null;
        var actor = await db.Users.AsNoTracking().SingleOrDefaultAsync(user => user.Id == actorId);
        if (actor is null || !actor.IsAdmin && actor.AccessState != "owner") return null;
        var share = await db.Shares.AsNoTracking().SingleOrDefaultAsync(item => item.Id == id);
        if (share is null || !actor.IsAdmin && (share.CreatorId != actorId || share.Mode != "link") ||
            !await IsActiveAsync(share)) return null;
        return RevealToken(share);
    }

    public async Task<bool> CancelAsync(ClaimsPrincipal principal, string id)
    {
        var actorId = principal.FindFirstValue(ClaimTypes.NameIdentifier);
        if (setup.State != SetupState.Ready || actorId is null) return false;
        await gate.Transfer.WaitAsync();
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync();
            await LockWritesAsync();
            var actor = await db.Users.AsNoTracking().SingleOrDefaultAsync(user => user.Id == actorId);
            if (actor is null || !actor.IsAdmin && actor.AccessState != "owner") return false;
            var share = await db.Shares.AsNoTracking().SingleOrDefaultAsync(item => item.Id == id);
            if (share is null || !actor.IsAdmin && (share.CreatorId != actorId || share.Mode != "link")) return false;
            var changed = await db.Shares.Where(item => item.Id == id && item.CancelledUtc == null)
                .ExecuteUpdateAsync(update => update.SetProperty(item => item.CancelledUtc, DateTime.UtcNow));
            if (changed != 1) return false;
            db.AuditEvents.Add(new AuditEvent { ActorId = actorId, Action = "share.cancel", FileId = share.FileId, TargetId = share.Id });
            await db.SaveChangesAsync();
            await transaction.CommitAsync();
            return true;
        }
        finally { gate.Transfer.Release(); }
    }

    public async Task<SharedFile?> FindActiveAsync(string token)
    {
        var share = await FindTokenAsync(token);
        if (share is null || !await IsActiveAsync(share)) return null;
        var file = await db.StoredFiles.AsNoTracking().SingleAsync(item => item.Id == share.FileId);
        return new SharedFile(file.Id, file.OriginalName, file.SizeBytes, share.ExpiresUtc, share.PasswordHash is not null);
    }

    public async Task<string> CheckPasswordAsync(string token, string? password)
    {
        await using var transaction = await db.Database.BeginTransactionAsync();
        await LockWritesAsync();
        var share = await FindTokenAsync(token);
        if (share is null || !await IsActiveAsync(share)) return "unavailable";
        if (share.PasswordHash is null) return "ok";
        if (share.BlockedUntilUtc > DateTime.UtcNow)
        {
            db.AuditEvents.Add(new AuditEvent { ActorId = "anonymous-share", Action = "share.password.limited", TargetId = share.Id, Result = "denied" });
            await db.SaveChangesAsync();
            await transaction.CommitAsync();
            return "limited";
        }
        var suppliedPassword = password ?? "";
        var verification = suppliedPassword is { Length: >= 1 and <= 128 }
            ? PasswordHashing.VerifySharePassword(share.PasswordHash, share.PasswordSalt, suppliedPassword)
            : PasswordVerificationResult.Failed;
        var matches = verification != PasswordVerificationResult.Failed;
        if (matches)
        {
            if (verification == PasswordVerificationResult.SuccessRehashNeeded)
            {
                share.PasswordHash = Encoding.UTF8.GetBytes(PasswordHashing.HashPassword(suppliedPassword));
                share.PasswordSalt = null;
            }
            share.FailedAttempts = 0;
            share.BlockedUntilUtc = null;
        }
        else
        {
            share.FailedAttempts++;
            if (share.FailedAttempts >= 5)
            {
                share.FailedAttempts = 0;
                share.BlockedUntilUtc = DateTime.UtcNow.AddMinutes(15);
            }
            db.AuditEvents.Add(new AuditEvent { ActorId = "anonymous-share", Action = "share.password", TargetId = share.Id,
                Result = share.BlockedUntilUtc is null ? "failure" : "denied" });
        }
        await db.SaveChangesAsync();
        await transaction.CommitAsync();
        return matches ? "ok" : share.BlockedUntilUtc is null ? "wrong" : "limited";
    }

    private async Task<ShareGrant?> FindTokenAsync(string token)
    {
        if (setup.State != SetupState.Ready || token.Length != 64 || !token.All(Uri.IsHexDigit)) return null;
        var hash = Convert.ToHexString(SHA256.HashData(Convert.FromHexString(token)));
        return await db.Shares.SingleOrDefaultAsync(share => share.TokenHash == hash);
    }

    private async Task<bool> IsActiveAsync(ShareGrant share) => share.CancelledUtc is null && share.ExpiresUtc > DateTime.UtcNow &&
        await db.StoredFiles.AsNoTracking().AnyAsync(file => file.Id == share.FileId && file.State == "available");

    private static string? RevealToken(ShareGrant share)
    {
        if (!OperatingSystem.IsWindows()) return null;
        byte[]? key = null;
        try
        {
            key = ProtectedData.Unprotect(share.ProtectedTokenKey, null, DataProtectionScope.CurrentUser);
            var token = new byte[32];
            using (var aes = new AesGcm(key, share.TokenTag.Length))
                aes.Decrypt(share.TokenNonce, share.TokenCipher, share.TokenTag, token);
            var value = Convert.ToHexString(token).ToLowerInvariant();
            CryptographicOperations.ZeroMemory(token);
            return value;
        }
        catch (CryptographicException) { return null; }
        finally { if (key is not null) CryptographicOperations.ZeroMemory(key); }
    }

    public Task LockWritesAsync() => db.Database.ExecuteSqlRawAsync("UPDATE \"AppState\" SET \"Id\" = \"Id\" WHERE \"Id\" = 1");
}
