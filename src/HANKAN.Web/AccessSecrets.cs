using System.Security.AccessControl;
using System.Security.Cryptography;
using System.Security.Principal;

namespace HANKAN.Web;

public static class AccessSecrets
{
    public static string SecretPath(string dataDirectory, string? reference, string webRoot)
    {
        if (string.IsNullOrWhiteSpace(reference) || Path.IsPathRooted(reference))
            throw new InvalidDataException("Secret reference");
        var directory = Path.GetFullPath(Path.Combine(dataDirectory, "access-secrets"));
        var path = Path.GetFullPath(Path.Combine(dataDirectory, reference.Replace('\\', Path.DirectorySeparatorChar)));
        if (!path.StartsWith(directory + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Secret directory");
        CheckPath(path, webRoot);
        return path;
    }

    public static byte[] Restore(string dataDirectory, string reference, string webRoot)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException();
        var path = SecretPath(dataDirectory, reference, webRoot);
        CheckPermissions(Path.Combine(dataDirectory, "access-secrets"));
        CheckPermissions(path);
        return ProtectedData.Unprotect(File.ReadAllBytes(path), null, DataProtectionScope.CurrentUser);
    }

    public static void CheckPath(string path, string webRoot)
    {
        var full = Path.GetFullPath(path);
        var root = Path.GetFullPath(webRoot).TrimEnd(Path.DirectorySeparatorChar);
        if (full.Equals(root, StringComparison.OrdinalIgnoreCase) ||
            full.StartsWith(root + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase))
            throw new InvalidDataException("Access settings must be outside web root");
        // Reject junctions and symlinks, including ancestors, rather than guessing their final target.
        for (var current = new FileInfo(full) as FileSystemInfo; current is not null;
             current = Directory.GetParent(current.FullName))
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Linked access path");
        for (var current = new DirectoryInfo(root); current is not null; current = current.Parent)
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0)
                throw new InvalidDataException("Linked web root");
    }

    public static void CheckPermissions(string path, bool allowAdministrators = false)
    {
        if (!OperatingSystem.IsWindows()) return;
        var current = WindowsIdentity.GetCurrent().User!;
        FileSystemSecurity security = Directory.Exists(path)
            ? new DirectoryInfo(path).GetAccessControl()
            : new FileInfo(path).GetAccessControl();
        foreach (FileSystemAccessRule rule in security.GetAccessRules(true, true, typeof(SecurityIdentifier)))
            if (rule.AccessControlType == AccessControlType.Allow && rule.FileSystemRights != 0 &&
                !rule.IdentityReference.Equals(current) &&
                !rule.IdentityReference.Equals(new SecurityIdentifier(WellKnownSidType.LocalSystemSid, null)) &&
                !(allowAdministrators && rule.IdentityReference.Equals(
                    new SecurityIdentifier(WellKnownSidType.BuiltinAdministratorsSid, null))))
                throw new UnauthorizedAccessException("Access file permissions are too broad");
    }
}
