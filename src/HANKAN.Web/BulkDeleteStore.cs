using System.Text.Json;
using Microsoft.AspNetCore.DataProtection;
using Microsoft.EntityFrameworkCore;

namespace HANKAN.Web;

public enum BulkDeleteResult { Success, InvalidSelection, Forbidden, Changed }

public sealed record BulkDeleteImpact(int DirectCount, int FolderCount, int FileCount,
    long TotalBytes, int ShareCount, string PreviewToken);

public sealed record BulkDeleteOutcome(int DeletedFileCount, int RetryFileCount,
    int DeletedFolderCount, int RemainingFolderCount)
{
    public bool Partial => RetryFileCount > 0 || RemainingFolderCount > 0;
}

public sealed class BulkDeleteStore(AppDbContext db, SelectionResolver selection, FolderStore folders,
    FileStore files, FileTransferGate gate, IDataProtectionProvider protection)
{
    private readonly ITimeLimitedDataProtector protector = protection
        .CreateProtector("HANKAN.selection.delete.v1").ToTimeLimitedDataProtector();

    private sealed record FolderSnapshot(string Id, string? ParentId);
    private sealed record FileSnapshot(string Id, string? FolderId, string State, long SizeBytes);
    private sealed record ShareSnapshot(string Id, string FileId, string Mode, DateTime ExpiresUtc);
    private sealed record ImpactSnapshot(string ActorId, string? CurrentFolderId,
        string[] RootFolderIds, string[] RootFileIds, FolderSnapshot[] Folders,
        FileSnapshot[] Files, ShareSnapshot[] Shares);

    public async Task<(BulkDeleteResult Result, BulkDeleteImpact? Impact)> PreviewAsync(string actorId,
        string? currentFolderId, string[] folderIds, string[] fileIds, CancellationToken cancellation)
    {
        await gate.Transfer.WaitAsync(cancellation);
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellation);
            await LockWritesAsync(cancellation);
            if (!await CanDeleteAsync(actorId, cancellation)) return (BulkDeleteResult.Forbidden, null);
            var scope = await selection.ResolveAsync(currentFolderId, folderIds, fileIds, cancellation);
            if (scope is null || scope.DirectCount == 0) return (BulkDeleteResult.InvalidSelection, null);
            var snapshot = await CaptureAsync(actorId, currentFolderId, scope, cancellation);
            var token = protector.Protect(JsonSerializer.Serialize(snapshot), TimeSpan.FromMinutes(5));
            await transaction.CommitAsync(cancellation);
            return (BulkDeleteResult.Success, new BulkDeleteImpact(scope.DirectCount,
                scope.Folders.Count, scope.Files.Count, scope.Files.Sum(file => file.SizeBytes),
                snapshot.Shares.Length, token));
        }
        finally { gate.Transfer.Release(); }
    }

    public async Task<(BulkDeleteResult Result, BulkDeleteOutcome? Outcome)> DeleteAsync(string actorId,
        string? currentFolderId, string[] folderIds, string[] fileIds, string previewToken,
        CancellationToken cancellation)
    {
        string preview;
        try { preview = protector.Unprotect(previewToken); }
        catch (Exception exception) when (exception is System.Security.Cryptography.CryptographicException or FormatException)
        {
            return (BulkDeleteResult.Changed, null);
        }

        SelectionScope scope;
        await gate.Transfer.WaitAsync(cancellation);
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellation);
            await LockWritesAsync(cancellation);
            if (!await CanDeleteAsync(actorId, cancellation)) return (BulkDeleteResult.Forbidden, null);
            var current = await selection.ResolveAsync(currentFolderId, folderIds, fileIds, cancellation);
            if (current is null || current.DirectCount == 0) return (BulkDeleteResult.Changed, null);
            var snapshot = await CaptureAsync(actorId, currentFolderId, current, cancellation);
            if (JsonSerializer.Serialize(snapshot) != preview)
                return (BulkDeleteResult.Changed, null);

            var ids = current.Files.Select(file => file.Id).ToArray();
            if (ids.Length > 0)
            {
                var marked = await db.StoredFiles.Where(file => ids.Contains(file.Id) && file.State == "available")
                    .ExecuteUpdateAsync(update => update.SetProperty(file => file.State, "deleting"), cancellation);
                if (marked != ids.Length) return (BulkDeleteResult.Changed, null);
            }
            db.AuditEvents.Add(new AuditEvent { ActorId = actorId, Action = "selection.delete.requested",
                Result = "success" });
            await db.SaveChangesAsync(cancellation);
            await transaction.CommitAsync(cancellation);
            scope = current;
        }
        finally { gate.Transfer.Release(); }

        var deletedFiles = 0;
        var retryFiles = 0;
        foreach (var file in scope.Files)
        {
            if (cancellation.IsCancellationRequested) { retryFiles++; continue; }
            var result = await files.DeleteAsync(file.Id, actorId);
            if (result == FileDeleteResult.Deleted) deletedFiles++;
            else retryFiles++;
        }

        var folderById = scope.Folders.ToDictionary(folder => folder.Id, StringComparer.Ordinal);
        int Depth(StoredFolder folder)
        {
            var depth = 0;
            while (folder.ParentId is not null && folderById.TryGetValue(folder.ParentId, out var parent))
            {
                depth++;
                folder = parent;
            }
            return depth;
        }
        var deletedFolders = 0;
        foreach (var folder in scope.Folders.OrderByDescending(Depth))
        {
            if (cancellation.IsCancellationRequested) break;
            if (await folders.DeleteAsync(folder.Id, actorId) == FolderChangeResult.Success)
                deletedFolders++;
        }
        return (BulkDeleteResult.Success, new BulkDeleteOutcome(deletedFiles, retryFiles,
            deletedFolders, scope.Folders.Count - deletedFolders));
    }

    private async Task<ImpactSnapshot> CaptureAsync(string actorId, string? currentFolderId,
        SelectionScope scope, CancellationToken cancellation)
    {
        var ids = scope.Files.Select(file => file.Id).ToArray();
        var now = DateTime.UtcNow;
        var shares = await db.Shares.AsNoTracking()
            .Where(share => ids.Contains(share.FileId) && share.CancelledUtc == null && share.ExpiresUtc > now)
            .OrderBy(share => share.Id)
            .Select(share => new ShareSnapshot(share.Id, share.FileId, share.Mode, share.ExpiresUtc))
            .ToArrayAsync(cancellation);
        return new ImpactSnapshot(actorId, currentFolderId,
            scope.RootFolders.Select(folder => folder.Id).ToArray(),
            scope.RootFiles.Select(file => file.Id).ToArray(),
            scope.Folders.Select(folder => new FolderSnapshot(folder.Id, folder.ParentId)).ToArray(),
            scope.Files.Select(file => new FileSnapshot(file.Id, file.FolderId, file.State, file.SizeBytes)).ToArray(), shares);
    }

    private Task<bool> CanDeleteAsync(string actorId, CancellationToken cancellation) =>
        db.Users.AsNoTracking().AnyAsync(user => user.Id == actorId &&
            (user.IsAdmin || user.AccessState == "owner"), cancellation);

    private Task LockWritesAsync(CancellationToken cancellation) => db.Database.ExecuteSqlRawAsync(
        "UPDATE \"AppState\" SET \"Id\" = \"Id\" WHERE \"Id\" = 1", cancellation);
}
