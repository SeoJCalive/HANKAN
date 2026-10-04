namespace HANKAN.Web;

public enum SelectionZipStatus { Ready, Invalid, TooLarge }

public sealed record SelectionZipEntry(string Path, StoredFile? File);

public sealed record SelectionZipPlan(SelectionZipStatus Status, IReadOnlyList<SelectionZipEntry> Entries);

public static class SelectionZipArchive
{
    public static SelectionZipPlan Plan(SelectionScope scope)
    {
        var count = scope.Folders.Count + scope.Files.Count;
        if (count == 0 || scope.RootFolders.Count == 0 && scope.RootFiles.Count == 1)
            return new(SelectionZipStatus.Invalid, []);
        if (count > 1000) return new(SelectionZipStatus.TooLarge, []);

        long bytes = 0;
        foreach (var file in scope.Files)
        {
            if (file.State != "available" || file.SizeBytes < 0 || file.SizeBytes > FileStore.MaxFileBytes)
                return new(SelectionZipStatus.Invalid, []);
            if (file.SizeBytes > 500_000_000 - bytes) return new(SelectionZipStatus.TooLarge, []);
            bytes += file.SizeBytes;
        }

        var entries = new List<SelectionZipEntry>(count);
        var foldersByParent = scope.Folders.ToLookup(folder => folder.ParentId, StringComparer.Ordinal);
        var filesByParent = scope.Files.ToLookup(file => file.FolderId, StringComparer.Ordinal);
        if (!AddChildren(scope.RootFolders, scope.RootFiles, "", entries, foldersByParent, filesByParent))
            return new(SelectionZipStatus.Invalid, []);
        return entries.Count == count
            ? new(SelectionZipStatus.Ready, entries)
            : new(SelectionZipStatus.Invalid, []);
    }

    private static bool AddChildren(IEnumerable<StoredFolder> folders, IEnumerable<StoredFile> files,
        string prefix, List<SelectionZipEntry> entries,
        ILookup<string?, StoredFolder> foldersByParent, ILookup<string?, StoredFile> filesByParent)
    {
        var children = folders.Select(folder => (Name: SafeSegment(folder.Name), Id: folder.Id, Folder: (StoredFolder?)folder, File: (StoredFile?)null))
            .Concat(files.Select(file => (Name: SafeSegment(file.OriginalName), Id: file.Id, Folder: (StoredFolder?)null, File: (StoredFile?)file)))
            .OrderBy(child => child.Name, StringComparer.OrdinalIgnoreCase)
            .ThenBy(child => child.Folder is null ? 1 : 0)
            .ThenBy(child => child.Id, StringComparer.Ordinal);
        var used = new HashSet<string>(StringComparer.OrdinalIgnoreCase);
        foreach (var child in children)
        {
            var name = UniqueName(child.Name, used);
            var path = prefix + name;
            if (path.Length > 240) return false;
            if (child.Folder is { } folder)
            {
                entries.Add(new(path + "/", null));
                if (!AddChildren(foldersByParent[folder.Id], filesByParent[folder.Id], path + "/",
                    entries, foldersByParent, filesByParent)) return false;
            }
            else entries.Add(new(path, child.File));
        }
        return true;
    }

    private static string SafeSegment(string raw)
    {
        var chars = raw.Select(ch => char.IsControl(ch) || char.IsSurrogate(ch) || ch is '<' or '>' or ':' or '"' or '/' or '\\' or '|' or '?' or '*'
            ? '_' : ch).ToArray();
        var name = new string(chars).TrimEnd(' ', '.');
        if (name.Length == 0) name = "_";
        var stem = name.Split('.')[0].TrimEnd(' ', '.');
        if (new[] { "CON", "PRN", "AUX", "NUL", "CONIN$", "CONOUT$" }.Contains(stem, StringComparer.OrdinalIgnoreCase) ||
            stem.Length == 4 && (stem.StartsWith("COM", StringComparison.OrdinalIgnoreCase) ||
                stem.StartsWith("LPT", StringComparison.OrdinalIgnoreCase)) &&
                (stem[3] is >= '1' and <= '9' or '¹' or '²' or '³'))
            name = "_" + name;
        return name.Length <= 120 ? name : name[..120].TrimEnd(' ', '.');
    }

    private static string UniqueName(string name, HashSet<string> used)
    {
        if (used.Add(name)) return name;
        for (var number = 2; ; number++)
        {
            var suffix = $" ({number})";
            var candidate = name[..Math.Min(name.Length, 120 - suffix.Length)] + suffix;
            if (used.Add(candidate)) return candidate;
        }
    }
}
