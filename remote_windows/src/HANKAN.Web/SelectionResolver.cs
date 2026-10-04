using Microsoft.EntityFrameworkCore;

namespace HANKAN.Web;

public sealed record SelectionScope(
    IReadOnlyList<StoredFolder> RootFolders,
    IReadOnlyList<StoredFile> RootFiles,
    IReadOnlyList<StoredFolder> Folders,
    IReadOnlyList<StoredFile> Files)
{
    public int DirectCount => RootFolders.Count + RootFiles.Count;
}

public sealed class SelectionResolver(AppDbContext db, FolderStore folders)
{
    public async Task<SelectionScope?> ResolveAsync(string? currentFolderId,
        IEnumerable<string> folderIds, IEnumerable<string> fileIds, CancellationToken cancellation = default)
    {
        if (currentFolderId == "") currentFolderId = null;
        var view = await folders.ReadAsync(currentFolderId);
        if (view is null) return null;

        var selectedFolderIds = folderIds.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        var selectedFileIds = fileIds.Distinct(StringComparer.Ordinal).Order(StringComparer.Ordinal).ToArray();
        if (selectedFolderIds.Any(id => !Guid.TryParseExact(id, "N", out _)) ||
            selectedFileIds.Any(id => !Guid.TryParseExact(id, "N", out _))) return null;

        var directFolders = view.Children.ToDictionary(folder => folder.Id, StringComparer.Ordinal);
        if (selectedFolderIds.Any(id => !directFolders.ContainsKey(id))) return null;

        var storedFiles = await db.StoredFiles.AsNoTracking()
            .Where(file => file.State != "deleted").ToListAsync(cancellation);
        var directFiles = storedFiles.Where(file => file.FolderId == currentFolderId)
            .ToDictionary(file => file.Id, StringComparer.Ordinal);
        if (selectedFileIds.Any(id => !directFiles.TryGetValue(id, out var file) || file.State != "available"))
            return null;

        var children = view.Tree.ToLookup(folder => folder.ParentId);
        var filesByFolder = storedFiles.ToLookup(file => file.FolderId);
        var expandedFolders = new List<StoredFolder>();
        var expandedFiles = new List<StoredFile>();
        var seenFolders = new HashSet<string>(StringComparer.Ordinal);
        foreach (var rootId in selectedFolderIds)
        {
            var pending = new Stack<StoredFolder>();
            pending.Push(directFolders[rootId]);
            while (pending.TryPop(out var folder))
            {
                if (!seenFolders.Add(folder.Id)) return null;
                expandedFolders.Add(folder);
                foreach (var file in filesByFolder[folder.Id])
                {
                    if (file.State != "available") return null;
                    expandedFiles.Add(file);
                }
                foreach (var child in children[folder.Id]) pending.Push(child);
            }
        }
        expandedFiles.AddRange(selectedFileIds.Select(id => directFiles[id]));
        expandedFolders.Sort((left, right) => StringComparer.Ordinal.Compare(left.Id, right.Id));
        expandedFiles.Sort((left, right) => StringComparer.Ordinal.Compare(left.Id, right.Id));
        return new SelectionScope(selectedFolderIds.Select(id => directFolders[id]).ToArray(),
            selectedFileIds.Select(id => directFiles[id]).ToArray(), expandedFolders, expandedFiles);
    }
}
