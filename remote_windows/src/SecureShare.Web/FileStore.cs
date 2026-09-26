using System.Buffers;
using System.Security.Cryptography;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;

namespace SecureShare.Web;

public sealed class FileTransferGate
{
    public SemaphoreSlim Transfer { get; } = new(1, 1);
}

public enum FileDeleteResult { Deleted, RetryNeeded, Forbidden, NotFound }

public sealed class FileStore(AppDbContext db, SetupStore setup, FileTransferGate gate, ILogger<FileStore> logger)
{
    public const long MaxFileBytes = 99_999_999;

    public async Task RecoverAsync()
    {
        if (setup.State != SetupState.Ready) return;
        var folder = (await db.Configurations.AsNoTracking().SingleAsync()).FolderPath!;
        var pending = await db.StoredFiles.Where(file => file.State == "uploading").ToListAsync();
        foreach (var file in pending)
        {
            if (Guid.TryParseExact(file.StorageName, "N", out _))
                File.Delete(Path.Combine(folder, file.StorageName));
            db.StoredFiles.Remove(file);
        }
        await db.SaveChangesAsync();
        var deleting = await db.StoredFiles.AsNoTracking().Where(file => file.State == "deleting").ToListAsync();
        foreach (var file in deleting)
        {
            try { await CompleteDeleteAsync(file, "system"); }
            catch (Exception exception) when (IsDeleteFailure(exception))
            {
                logger.LogError(exception, "Deletion recovery failed for file {FileId}", file.Id);
                await RecordDeleteFailureAsync(file.Id, "system");
            }
        }
    }

    public async Task<List<StoredFile>> ListAsync() =>
        await db.StoredFiles.AsNoTracking().Where(file => file.State == "available")
            .OrderByDescending(file => file.CreatedUtc).ToListAsync();

    public async Task<List<StoredFile>> ListDeletingAsync() =>
        await db.StoredFiles.AsNoTracking().Where(file => file.State == "deleting")
            .OrderByDescending(file => file.CreatedUtc).ToListAsync();

    public async Task<FileDeleteResult> DeleteAsync(string id, string actorId)
    {
        if (setup.State != SetupState.Ready) return FileDeleteResult.RetryNeeded;
        await gate.Transfer.WaitAsync();
        try
        {
            StoredFile? file;
            await using (var transaction = await db.Database.BeginTransactionAsync())
            {
                await LockWritesAsync();
                var actor = await db.Users.AsNoTracking().SingleOrDefaultAsync(user => user.Id == actorId);
                if (actor is null || !actor.IsAdmin && actor.AccessState != "owner") return FileDeleteResult.Forbidden;
                file = await db.StoredFiles.AsNoTracking().SingleOrDefaultAsync(item => item.Id == id);
                if (file is null || file.State is not ("available" or "deleting")) return FileDeleteResult.NotFound;
                if (file.State == "available")
                {
                    await db.StoredFiles.Where(item => item.Id == id && item.State == "available")
                        .ExecuteUpdateAsync(update => update.SetProperty(item => item.State, "deleting"));
                    db.AuditEvents.Add(new AuditEvent { ActorId = actorId, Action = "file.delete.requested", FileId = id, TargetId = id });
                    await db.SaveChangesAsync();
                }
                await transaction.CommitAsync();
            }
            try
            {
                await CompleteDeleteAsync(file, actorId);
                return FileDeleteResult.Deleted;
            }
            catch (Exception exception) when (IsDeleteFailure(exception))
            {
                logger.LogError(exception, "Deletion needs retry for file {FileId}", id);
                await RecordDeleteFailureAsync(id, actorId);
                return FileDeleteResult.RetryNeeded;
            }
        }
        finally { gate.Transfer.Release(); }
    }

    private async Task CompleteDeleteAsync(StoredFile file, string actorId)
    {
        if (!Guid.TryParseExact(file.StorageName, "N", out _))
            throw new InvalidDataException("Invalid opaque storage name.");
        var folder = (await db.Configurations.AsNoTracking().SingleAsync()).FolderPath
            ?? throw new InvalidDataException("Storage folder is unavailable.");
        File.Delete(Path.Combine(folder, file.StorageName));
        await using var transaction = await db.Database.BeginTransactionAsync();
        await LockWritesAsync();
        if (!await db.StoredFiles.AsNoTracking().AnyAsync(item => item.Id == file.Id && item.State == "deleting"))
            return;
        await db.StoredFiles.Where(item => item.Id == file.Id && item.State == "deleting")
            .ExecuteUpdateAsync(update => update.SetProperty(item => item.State, "deleted"));
        await db.Shares.Where(share => share.FileId == file.Id && share.CancelledUtc == null)
            .ExecuteUpdateAsync(update => update.SetProperty(share => share.CancelledUtc, DateTime.UtcNow));
        db.AuditEvents.Add(new AuditEvent { ActorId = actorId, Action = "file.delete.succeeded", FileId = file.Id, TargetId = file.Id });
        await db.SaveChangesAsync();
        await transaction.CommitAsync();
    }

    private async Task RecordDeleteFailureAsync(string id, string actorId)
    {
        try
        {
            db.ChangeTracker.Clear();
            db.AuditEvents.Add(new AuditEvent { ActorId = actorId, Action = "file.delete.failed", FileId = id, TargetId = id, Result = "failure" });
            await db.SaveChangesAsync();
        }
        catch (Exception exception) when (IsDeleteFailure(exception))
        {
            logger.LogError(exception, "Deletion failure audit could not be saved for file {FileId}", id);
        }
    }

    private Task LockWritesAsync() => db.Database.ExecuteSqlRawAsync(
        "UPDATE \"AppState\" SET \"Id\" = \"Id\" WHERE \"Id\" = 1");

    private static bool IsDeleteFailure(Exception exception) =>
        exception is IOException or UnauthorizedAccessException or DbUpdateException or SqliteException;

    public async Task<(long Used, long Quota)> UsageAsync()
    {
        var quota = (await db.Configurations.AsNoTracking().SingleAsync()).QuotaBytes ?? 0;
        var used = await db.StoredFiles.Where(file => file.State != "deleted")
            .SumAsync(file => file.State == "uploading" ? file.ReservedBytes : file.SizeBytes);
        return (used, quota);
    }

    public async Task<string?> UploadAsync(Stream body, string rawName, string actorId, string actorEmail, CancellationToken cancellation)
    {
        if (!OperatingSystem.IsWindows()) return "Windows에서만 파일을 저장할 수 있습니다.";
        var name = SafeName(rawName);
        if (name is null) return "올바른 파일 이름을 선택하세요.";
        var config = await db.Configurations.AsNoTracking().SingleAsync();
        if (config.FolderPath is null || config.QuotaBytes is null) return "저장소 설정을 확인하세요.";
        var (used, quota) = await UsageAsync();
        var free = new DriveInfo(Path.GetPathRoot(config.FolderPath)!).AvailableFreeSpace;
        var reservation = Math.Min(MaxFileBytes, Math.Min(quota - used, free - 1_048_576));
        if (reservation <= 0) return "전체 용량 또는 디스크 여유 공간이 부족합니다.";
        var file = new StoredFile
        {
            Id = Guid.NewGuid().ToString("N"),
            StorageName = Guid.NewGuid().ToString("N"),
            OriginalName = name,
            UploaderId = actorId,
            UploaderEmail = actorEmail,
            ReservedBytes = reservation
        };
        db.StoredFiles.Add(file);
        await db.SaveChangesAsync(cancellation);
        var path = Path.Combine(config.FolderPath, file.StorageName);
        var committed = false;
        var buffer = ArrayPool<byte>.Shared.Rent(64 * 1024);
        byte[]? plain = null;
        byte[]? key = null;
        try
        {
            using var memory = new MemoryStream();
            while (true)
            {
                var read = await body.ReadAsync(buffer.AsMemory(0, buffer.Length), cancellation);
                if (read == 0) break;
                if (memory.Length + read > reservation || memory.Length + read > MaxFileBytes)
                    return "파일당 100 MB 미만이며 남은 용량 안에서만 업로드할 수 있습니다.";
                await memory.WriteAsync(buffer.AsMemory(0, read), cancellation);
            }
            plain = memory.ToArray();
            key = RandomNumberGenerator.GetBytes(32);
            var nonce = RandomNumberGenerator.GetBytes(12);
            var tag = new byte[16];
            var cipher = new byte[plain.Length];
            using (var aes = new AesGcm(key, tag.Length))
                aes.Encrypt(nonce, plain, cipher, tag);
            var protectedKey = ProtectedData.Protect(key, null, DataProtectionScope.CurrentUser);
            await using (var output = new FileStream(path, FileMode.CreateNew, FileAccess.Write, FileShare.None))
                await output.WriteAsync(cipher, cancellation);
            file.SizeBytes = plain.LongLength;
            file.ReservedBytes = 0;
            file.ProtectedKey = protectedKey;
            file.Nonce = nonce;
            file.Tag = tag;
            file.State = "available";
            db.AuditEvents.Add(new AuditEvent { ActorId = actorId, Action = "file.upload", FileId = file.Id, TargetId = file.Id });
            await db.SaveChangesAsync(cancellation);
            committed = true;
            return null;
        }
        finally
        {
            if (plain is not null) CryptographicOperations.ZeroMemory(plain);
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            CryptographicOperations.ZeroMemory(buffer);
            ArrayPool<byte>.Shared.Return(buffer);
            if (!committed)
            {
                try
                {
                    if (File.Exists(path)) File.Delete(path);
                    db.StoredFiles.Remove(file);
                    await db.SaveChangesAsync(CancellationToken.None);
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or DbUpdateException)
                {
                    logger.LogError(exception, "Incomplete upload cleanup failed for file {FileId}", file.Id);
                }
            }
        }
    }

    public async Task<StoredFile?> FindAvailableAsync(string id) =>
        await db.StoredFiles.AsNoTracking().SingleOrDefaultAsync(file => file.Id == id && file.State == "available");

    public async Task<byte[]?> DecryptAsync(StoredFile file, CancellationToken cancellation)
    {
        if (!OperatingSystem.IsWindows()) return null;
        if (file.SizeBytes is < 0 or > MaxFileBytes || file.FormatVersion != 1 || file.ProtectedKey is null || file.Nonce?.Length != 12 ||
            file.Tag?.Length != 16 || !Guid.TryParseExact(file.StorageName, "N", out _)) return null;
        var folder = (await db.Configurations.AsNoTracking().SingleAsync(cancellation)).FolderPath;
        if (folder is null) return null;
        byte[]? key = null;
        byte[]? plain = null;
        var verified = false;
        try
        {
            await using var input = new FileStream(Path.Combine(folder, file.StorageName), FileMode.Open, FileAccess.Read, FileShare.Read);
            if (input.Length != file.SizeBytes) return null;
            var cipher = new byte[(int)file.SizeBytes];
            await input.ReadExactlyAsync(cipher, cancellation);
            key = ProtectedData.Unprotect(file.ProtectedKey, null, DataProtectionScope.CurrentUser);
            if (key.Length != 32) return null;
            plain = new byte[cipher.Length];
            using (var aes = new AesGcm(key, file.Tag.Length))
                aes.Decrypt(file.Nonce, cipher, file.Tag, plain);
            verified = true;
            return plain;
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or CryptographicException)
        {
            return null;
        }
        finally
        {
            if (key is not null) CryptographicOperations.ZeroMemory(key);
            if (!verified && plain is not null) CryptographicOperations.ZeroMemory(plain);
        }
    }

    public async Task RecordDownloadAsync(string actorId, string fileId, string action, string result, CancellationToken cancellation)
    {
        db.AuditEvents.Add(new AuditEvent { ActorId = actorId, Action = action, FileId = fileId, TargetId = fileId, Result = result });
        await db.SaveChangesAsync(cancellation);
    }

    private static string? SafeName(string raw)
    {
        var name = raw.Replace('\\', '/').Split('/').Last().Trim();
        if (name.Length is < 1 or > 255 || name is "." or ".." || name.Any(char.IsControl)) return null;
        return name;
    }
}
