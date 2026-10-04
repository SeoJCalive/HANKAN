using Microsoft.EntityFrameworkCore;

namespace HANKAN.Web;

public enum BulkMoveResult { Success, InvalidSelection, Forbidden, SameLocation, Descendant, NameCollision, MissingDestination }

public sealed class BulkMoveStore(AppDbContext db, SelectionResolver selection, FolderStore folders, FileTransferGate gate)
{
    public async Task<(BulkMoveResult Result, int MovedCount)> MoveAsync(string actorId, string? currentFolderId,
        IEnumerable<string> folderIds, IEnumerable<string> fileIds, string? destinationId, CancellationToken cancellation)
    {
        await gate.Transfer.WaitAsync(cancellation);
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync(cancellation);
            await db.Database.ExecuteSqlRawAsync("UPDATE \"AppState\" SET \"Id\" = \"Id\" WHERE \"Id\" = 1", cancellation);

            async Task<(BulkMoveResult, int)> FinishAsync(BulkMoveResult result, int count = 0)
            {
                db.AuditEvents.Add(new AuditEvent
                {
                    ActorId = actorId, Action = "selection.move", TargetId = destinationId,
                    Result = result == BulkMoveResult.Success ? "success" : result == BulkMoveResult.Forbidden ? "denied" : "failure"
                });
                await db.SaveChangesAsync(cancellation);
                await transaction.CommitAsync(cancellation);
                return (result, count);
            }

            if (!await db.Users.AsNoTracking().AnyAsync(user => user.Id == actorId &&
                (user.IsAdmin || user.AccessState == "owner"), cancellation))
                return await FinishAsync(BulkMoveResult.Forbidden);
            if (!FolderStore.ValidId(destinationId)) return await FinishAsync(BulkMoveResult.InvalidSelection);

            var scope = await selection.ResolveAsync(currentFolderId, folderIds, fileIds, cancellation);
            if (scope is null || scope.DirectCount == 0) return await FinishAsync(BulkMoveResult.InvalidSelection);
            var destination = await folders.ReadAsync(destinationId);
            if (destination is null) return await FinishAsync(BulkMoveResult.MissingDestination);
            if (currentFolderId == destinationId) return await FinishAsync(BulkMoveResult.SameLocation);

            var selectedFolderIds = scope.RootFolders.Select(folder => folder.Id).ToHashSet(StringComparer.Ordinal);
            if (destination.Path.Any(crumb => crumb.Id is not null && selectedFolderIds.Contains(crumb.Id)))
                return await FinishAsync(BulkMoveResult.Descendant);
            foreach (var folder in scope.RootFolders)
            {
                if (await db.Folders.AsNoTracking().AnyAsync(other => other.ParentId == destinationId &&
                    other.Id != folder.Id && other.Name == folder.Name, cancellation))
                    return await FinishAsync(BulkMoveResult.NameCollision);
            }

            foreach (var id in selectedFolderIds)
                (await db.Folders.SingleAsync(folder => folder.Id == id, cancellation)).ParentId = destinationId;
            foreach (var file in scope.RootFiles)
                (await db.StoredFiles.SingleAsync(item => item.Id == file.Id, cancellation)).FolderId = destinationId;
            return await FinishAsync(BulkMoveResult.Success, scope.DirectCount);
        }
        finally { gate.Transfer.Release(); }
    }
}
