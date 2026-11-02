using Microsoft.EntityFrameworkCore;

namespace HANKAN.Web;

public sealed record FolderCrumb(string? Id, string Name);
public sealed record FolderView(string? Id, IReadOnlyList<FolderCrumb> Path,
    IReadOnlyList<StoredFolder> Tree, IReadOnlyList<StoredFolder> Children);
public enum FolderChangeResult { Success, Invalid, Forbidden }

public sealed class FolderStore(AppDbContext db, FileTransferGate gate)
{
    public static bool ValidId(string? id) => id is null || Guid.TryParseExact(id, "N", out _);
    public static string? ValidName(string? input)
    {
        var name = input?.Trim();
        return name is { Length: >= 1 and <= 255 } && !name.Any(c => char.IsControl(c) || c is '/' or '\\') ? name : null;
    }

    public async Task<FolderView?> ReadAsync(string? id)
    {
        if (!ValidId(id)) return null;
        var all = await db.Folders.AsNoTracking().OrderBy(folder => folder.Name).ToListAsync();
        var byId = all.ToDictionary(folder => folder.Id);
        if (id is not null && !byId.ContainsKey(id)) return null;
        foreach (var folder in all)
        {
            var seen = new HashSet<string>();
            for (var current = folder; current is not null;)
            {
                if (!seen.Add(current.Id)) return null;
                if (current.ParentId is null) break;
                if (!byId.TryGetValue(current.ParentId, out current)) return null;
            }
        }
        var path = new List<FolderCrumb> { new(null, "공용 파일") };
        if (id is not null)
        {
            var parents = new List<FolderCrumb>();
            for (var current = byId[id]; current is not null;
                current = current.ParentId is null ? null : byId[current.ParentId])
                parents.Add(new FolderCrumb(current.Id, current.Name));
            parents.Reverse();
            path.AddRange(parents);
        }
        return new FolderView(id, path, all, all.Where(folder => folder.ParentId == id).ToList());
    }

    public Task<FolderChangeResult> CreateAsync(string? parentId, string? name, string actorId) =>
        ChangeAsync("folder.create", null, parentId, name, actorId);

    public Task<FolderChangeResult> RenameAsync(string id, string? name, string actorId) =>
        ChangeAsync("folder.rename", id, null, name, actorId);

    public Task<FolderChangeResult> MoveAsync(string id, string? parentId, string actorId) =>
        ChangeAsync("folder.move", id, parentId, null, actorId);

    public Task<FolderChangeResult> DeleteAsync(string id, string actorId) =>
        ChangeAsync("folder.delete", id, null, null, actorId);

    private async Task<FolderChangeResult> ChangeAsync(string action, string? id, string? parentId, string? rawName, string actorId)
    {
        await gate.Transfer.WaitAsync();
        try
        {
            await using var transaction = await db.Database.BeginTransactionAsync();
            await db.Database.ExecuteSqlRawAsync("UPDATE \"AppState\" SET \"Id\" = \"Id\" WHERE \"Id\" = 1");
            async Task<FolderChangeResult> FinishAsync(FolderChangeResult result, string? targetId)
            {
                db.AuditEvents.Add(new AuditEvent
                {
                    ActorId = actorId, Action = action, TargetId = targetId,
                    Result = result == FolderChangeResult.Success ? "success" : result == FolderChangeResult.Forbidden ? "denied" : "failure"
                });
                await db.SaveChangesAsync();
                await transaction.CommitAsync();
                return result;
            }

            if (!await db.Users.AsNoTracking().AnyAsync(user => user.Id == actorId && (user.IsAdmin || user.AccessState == "owner")))
                return await FinishAsync(FolderChangeResult.Forbidden, id);
            if (!ValidId(id) || !ValidId(parentId)) return await FinishAsync(FolderChangeResult.Invalid, id);
            var name = ValidName(rawName);
            if (action is "folder.create" or "folder.rename" && name is null)
                return await FinishAsync(FolderChangeResult.Invalid, id);
            StoredFolder? folder = null;
            if (id is not null)
            {
                folder = await db.Folders.SingleOrDefaultAsync(item => item.Id == id);
                if (folder is null) return await FinishAsync(FolderChangeResult.Invalid, id);
            }
            if (action is "folder.create" or "folder.move" && parentId is not null &&
                !await db.Folders.AsNoTracking().AnyAsync(item => item.Id == parentId))
                return await FinishAsync(FolderChangeResult.Invalid, id);

            if (action == "folder.create")
            {
                if (await db.Folders.AnyAsync(item => item.ParentId == parentId && item.Name == name))
                    return await FinishAsync(FolderChangeResult.Invalid, null);
                folder = new StoredFolder { Id = Guid.NewGuid().ToString("N"), ParentId = parentId, Name = name! };
                db.Folders.Add(folder);
            }
            else if (action == "folder.rename")
            {
                if (await db.Folders.AnyAsync(item => item.Id != id && item.ParentId == folder!.ParentId && item.Name == name))
                    return await FinishAsync(FolderChangeResult.Invalid, id);
                folder!.Name = name!;
            }
            else if (action == "folder.move")
            {
                if (folder!.ParentId == parentId || id == parentId ||
                    await db.Folders.AnyAsync(item => item.Id != id && item.ParentId == parentId && item.Name == folder.Name))
                    return await FinishAsync(FolderChangeResult.Invalid, id);
                var seen = new HashSet<string>();
                for (var currentId = parentId; currentId is not null;)
                {
                    if (!seen.Add(currentId) || currentId == id) return await FinishAsync(FolderChangeResult.Invalid, id);
                    var parent = await db.Folders.AsNoTracking().SingleOrDefaultAsync(item => item.Id == currentId);
                    if (parent is null) return await FinishAsync(FolderChangeResult.Invalid, id);
                    currentId = parent.ParentId;
                }
                folder.ParentId = parentId;
            }
            else if (action == "folder.delete")
            {
                if (await db.Folders.AnyAsync(item => item.ParentId == id) ||
                    await db.StoredFiles.AnyAsync(file => file.FolderId == id && file.State != "deleted"))
                    return await FinishAsync(FolderChangeResult.Invalid, id);
                db.Folders.Remove(folder!);
            }
            return await FinishAsync(FolderChangeResult.Success, folder?.Id);
        }
        finally { gate.Transfer.Release(); }
    }
}
