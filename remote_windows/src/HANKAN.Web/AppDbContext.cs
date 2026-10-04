using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace HANKAN.Web;

public sealed class AppUser : IdentityUser
{
    public bool IsAdmin { get; set; }
    public string AccessState { get; set; } = "unrequested";
    public string? RequestedRole { get; set; }
}

public sealed class StorageConfiguration
{
    public int Id { get; set; } = 1;
    public bool Completed { get; set; }
    public string? FolderPath { get; set; }
    public long? QuotaBytes { get; set; }
    public byte[]? DpapiProbe { get; set; }
}

public sealed class StoredFile
{
    public string Id { get; set; } = "";
    public string? FolderId { get; set; }
    public string StorageName { get; set; } = "";
    public string OriginalName { get; set; } = "";
    public string UploaderId { get; set; } = "";
    public string UploaderEmail { get; set; } = "";
    public string State { get; set; } = "uploading";
    public long SizeBytes { get; set; }
    public long ReservedBytes { get; set; }
    public byte[]? ProtectedKey { get; set; }
    public byte[]? Nonce { get; set; }
    public byte[]? Tag { get; set; }
    public int FormatVersion { get; set; } = 1;
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}

public sealed class StoredFolder
{
    public string Id { get; set; } = "";
    public string? ParentId { get; set; }
    public string Name { get; set; } = "";
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
}

public sealed class AuditEvent
{
    public long Id { get; set; }
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public string ActorId { get; set; } = "";
    public string Action { get; set; } = "";
    public string? FileId { get; set; }
    public string? TargetId { get; set; }
    public string Result { get; set; } = "success";
}

public sealed class ShareGrant
{
    public string Id { get; set; } = Guid.NewGuid().ToString("N");
    public string FileId { get; set; } = "";
    public string CreatorId { get; set; } = "";
    public string CreatorEmail { get; set; } = "";
    public string Mode { get; set; } = "link";
    public DateTime CreatedUtc { get; set; } = DateTime.UtcNow;
    public DateTime ExpiresUtc { get; set; }
    public DateTime? CancelledUtc { get; set; }
    public string TokenHash { get; set; } = "";
    public byte[] ProtectedTokenKey { get; set; } = [];
    public byte[] TokenNonce { get; set; } = [];
    public byte[] TokenCipher { get; set; } = [];
    public byte[] TokenTag { get; set; } = [];
    public byte[]? PasswordSalt { get; set; }
    public byte[]? PasswordHash { get; set; }
    public int FailedAttempts { get; set; }
    public DateTime? BlockedUntilUtc { get; set; }
}

public sealed class AppDbContext(DbContextOptions<AppDbContext> options) : IdentityDbContext<AppUser>(options)
{
    public DbSet<StorageConfiguration> Configurations => Set<StorageConfiguration>();
    public DbSet<StoredFile> StoredFiles => Set<StoredFile>();
    public DbSet<StoredFolder> Folders => Set<StoredFolder>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<ShareGrant> Shares => Set<ShareGrant>();

    protected override void OnModelCreating(ModelBuilder builder)
    {
        base.OnModelCreating(builder);
        builder.Entity<AppUser>().HasIndex(user => user.IsAdmin).IsUnique().HasFilter("\"IsAdmin\" = 1");
        builder.Entity<StorageConfiguration>().ToTable("AppState").HasKey(state => state.Id);
        builder.Entity<StoredFile>().HasIndex(file => file.StorageName).IsUnique();
        builder.Entity<StoredFile>().HasIndex(file => file.State);
        builder.Entity<StoredFile>().HasIndex(file => file.FolderId);
        builder.Entity<StoredFolder>().ToTable("Folders");
        builder.Entity<StoredFolder>().Property(folder => folder.Name).UseCollation("NOCASE");
        builder.Entity<StoredFolder>().HasIndex(folder => folder.ParentId);
        builder.Entity<StoredFolder>().HasIndex(folder => folder.Name).IsUnique().HasDatabaseName("IX_Folders_Root_Name")
            .HasFilter("\"ParentId\" IS NULL");
        builder.Entity<StoredFolder>().HasIndex(folder => new { folder.ParentId, folder.Name }).IsUnique()
            .HasDatabaseName("IX_Folders_Parent_Name").HasFilter("\"ParentId\" IS NOT NULL");
        builder.Entity<AuditEvent>().HasIndex(item => new { item.CreatedUtc, item.Id });
        builder.Entity<ShareGrant>().HasIndex(share => share.TokenHash).IsUnique();
        builder.Entity<ShareGrant>().HasIndex(share => share.FileId);
    }
}
