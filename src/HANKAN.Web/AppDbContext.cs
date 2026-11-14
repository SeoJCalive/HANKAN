using System.Globalization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

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
    public long? ChainSequence { get; set; }
    public byte[]? PreviousMac { get; set; }
    public byte[]? Mac { get; set; }
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

public sealed class AppDbContext(DbContextOptions<AppDbContext> options, ILogger<AppDbContext> logger,
    IAuditKeyProtector auditKeys) : IdentityDbContext<AppUser>(options)
{
    public DbSet<StorageConfiguration> Configurations => Set<StorageConfiguration>();
    public DbSet<StoredFile> StoredFiles => Set<StoredFile>();
    public DbSet<StoredFolder> Folders => Set<StoredFolder>();
    public DbSet<AuditEvent> AuditEvents => Set<AuditEvent>();
    public DbSet<ShareGrant> Shares => Set<ShareGrant>();

    internal const string AuditBytesSql = """
        CASE WHEN "CreatedUtc" IS NULL THEN 0 ELSE
          length(CAST(
            substr("CreatedUtc",1,10) || 'T' || substr("CreatedUtc",12,8) || '.' ||
            substr(substr("CreatedUtc",21) || '0000000',1,7) || 'Z'
          AS BLOB))
        END
        + coalesce(length(CAST(CAST("Id" AS TEXT) AS BLOB)),0)
        + coalesce(length(CAST("ActorId" AS BLOB)),0)
        + coalesce(length(CAST("Action" AS BLOB)),0)
        + coalesce(length(CAST("FileId" AS BLOB)),0)
        + coalesce(length(CAST("TargetId" AS BLOB)),0)
        + coalesce(length(CAST("Result" AS BLOB)),0)
        """;
    public AuditVerification VerifyAudit() => AuditChain.Verify(this, auditKeys);

    private List<AuditEvent> AddedAuditEvents()
    {
        ChangeTracker.DetectChanges();
        if (ChangeTracker.Entries<AuditEvent>().Any(entry => entry.State is EntityState.Modified or EntityState.Deleted) ||
            ChangeTracker.Entries<AuditChainState>().Any(entry => entry.State != EntityState.Unchanged) ||
            ChangeTracker.Entries<AuditChainRestart>().Any(entry => entry.State != EntityState.Unchanged))
            throw new InvalidOperationException("Audit history and chain metadata are read-only.");
        var added = ChangeTracker.Entries<AuditEvent>().Where(entry => entry.State == EntityState.Added)
            .Select(entry => entry.Entity).ToList();
        if (added.Any(item => item.ChainSequence is not null || item.PreviousMac is not null || item.Mac is not null))
            throw new InvalidOperationException("Audit signatures are assigned by the database save path.");
        return added;
    }

    public override int SaveChanges() => SaveChanges(true);

    public override Task<int> SaveChangesAsync(CancellationToken cancellationToken = default) =>
        SaveChangesAsync(true, cancellationToken);

    public override int SaveChanges(bool acceptAllChangesOnSuccess)
    {
        var added = AddedAuditEvents();
        if (added.Count == 0)
            return base.SaveChanges(acceptAllChangesOnSuccess);

        IDbContextTransaction? owned = null;
        var transaction = Database.CurrentTransaction;
        var savepoint = false;
        var baseCompleted = false;
        try
        {
            if (transaction is null) transaction = owned = Database.BeginTransaction();
            else
            {
                transaction.CreateSavepoint("audit_retention");
                savepoint = true;
            }
            Database.ExecuteSqlRaw("""UPDATE "AppState" SET "Id" = "Id" WHERE "Id" = 1""");
            using var chain = AuditChain.ReadVerified(this, auditKeys);
            var saved = base.SaveChanges(false);
            baseCompleted = true;
            AuditChain.Append(this, chain, added);
            var now = DateTime.UtcNow;
            var cutoff = now.AddDays(-30);
            var retention = AuditChain.Prune(this, auditKeys, now);
            if (owned is not null) owned.Commit();
            else transaction.ReleaseSavepoint("audit_retention");
            if (acceptAllChangesOnSuccess) ChangeTracker.AcceptAllChanges();
            LogAuditRetention("save", now, cutoff, retention,
                owned is not null ? "committed" : "enlisted");
            return saved;
        }
        catch (Exception exception)
        {
            try
            {
                if (owned is not null) owned.Rollback();
                else if (savepoint) transaction!.RollbackToSavepoint("audit_retention");
            }
            catch (Exception rollbackException)
            {
                logger.LogError(rollbackException, "Audit retention rollback failed trigger=save");
            }
            var discardedEntries = ChangeTracker.Entries().Count();
            ChangeTracker.Clear();
            logger.LogError(exception,
                "Audit retention failed trigger=save phase={Phase} baseCompleted={BaseCompleted} trackerCleared=true discardedEntries={DiscardedEntries}",
                baseCompleted ? "retention" : "base", baseCompleted, discardedEntries);
            throw;
        }
        finally { owned?.Dispose(); }
    }

    public override async Task<int> SaveChangesAsync(bool acceptAllChangesOnSuccess, CancellationToken cancellationToken = default)
    {
        var added = AddedAuditEvents();
        if (added.Count == 0)
            return await base.SaveChangesAsync(acceptAllChangesOnSuccess, cancellationToken);

        IDbContextTransaction? owned = null;
        var transaction = Database.CurrentTransaction;
        var savepoint = false;
        var baseCompleted = false;
        try
        {
            if (transaction is null) transaction = owned = await Database.BeginTransactionAsync(cancellationToken);
            else
            {
                await transaction.CreateSavepointAsync("audit_retention", cancellationToken);
                savepoint = true;
            }
            await Database.ExecuteSqlRawAsync("""UPDATE "AppState" SET "Id" = "Id" WHERE "Id" = 1""", cancellationToken);
            using var chain = AuditChain.ReadVerified(this, auditKeys);
            cancellationToken.ThrowIfCancellationRequested();
            var saved = await base.SaveChangesAsync(false, cancellationToken);
            baseCompleted = true;
            AuditChain.Append(this, chain, added);
            var now = DateTime.UtcNow;
            var cutoff = now.AddDays(-30);
            var retention = AuditChain.Prune(this, auditKeys, now);
            cancellationToken.ThrowIfCancellationRequested();
            if (owned is not null) await owned.CommitAsync(cancellationToken);
            else await transaction.ReleaseSavepointAsync("audit_retention", cancellationToken);
            if (acceptAllChangesOnSuccess) ChangeTracker.AcceptAllChanges();
            LogAuditRetention("save", now, cutoff, retention,
                owned is not null ? "committed" : "enlisted");
            return saved;
        }
        catch (Exception exception)
        {
            try
            {
                if (owned is not null) await owned.RollbackAsync(CancellationToken.None);
                else if (savepoint) await transaction!.RollbackToSavepointAsync("audit_retention", CancellationToken.None);
            }
            catch (Exception rollbackException)
            {
                logger.LogError(rollbackException, "Audit retention rollback failed trigger=save");
            }
            var discardedEntries = ChangeTracker.Entries().Count();
            ChangeTracker.Clear();
            logger.LogError(exception,
                "Audit retention failed trigger=save phase={Phase} baseCompleted={BaseCompleted} trackerCleared=true discardedEntries={DiscardedEntries}",
                baseCompleted ? "retention" : "base", baseCompleted, discardedEntries);
            throw;
        }
        finally
        {
            if (owned is not null) await owned.DisposeAsync();
        }
    }

    public async Task PruneAuditAsync()
    {
        IDbContextTransaction? transaction = null;
        try
        {
            transaction = await Database.BeginTransactionAsync();
            await Database.ExecuteSqlRawAsync("""UPDATE "AppState" SET "Id" = "Id" WHERE "Id" = 1""");
            var now = DateTime.UtcNow;
            var cutoff = now.AddDays(-30);
            var retention = AuditChain.Prune(this, auditKeys, now);
            await transaction.CommitAsync();
            LogAuditRetention("startup", now, cutoff, retention, "committed");
        }
        catch (Exception exception)
        {
            try
            {
                if (transaction is not null) await transaction.RollbackAsync(CancellationToken.None);
            }
            catch (Exception rollbackException)
            {
                logger.LogError(rollbackException, "Audit retention rollback failed trigger=startup");
            }
            logger.LogError(exception, "Audit retention failed trigger=startup");
            throw;
        }
        finally
        {
            if (transaction is not null) await transaction.DisposeAsync();
        }
    }

    private void LogAuditRetention(string trigger, DateTime now, DateTime cutoff,
        AuditChain.Retention retention, string transactionState)
    {
        var dbFileBytes = new FileInfo(((SqliteConnection)Database.GetDbConnection()).DataSource).Length;
        logger.LogInformation(
            "Audit retention trigger={Trigger} utc={Utc} cutoff={Cutoff} expiredDeleted={ExpiredDeleted} sizeDeleted={SizeDeleted} rows={Rows} logicalBytes={LogicalBytes} dbFileBytes={DbFileBytes} transaction={TransactionState}",
            trigger, now.ToString("O", CultureInfo.InvariantCulture), cutoff.ToString("O", CultureInfo.InvariantCulture),
            retention.ExpiredDeleted, retention.SizeDeleted, retention.Rows, retention.LogicalBytes, dbFileBytes, transactionState);
    }

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
        builder.Entity<AuditEvent>().HasIndex(item => item.ChainSequence).IsUnique();
        builder.Entity<AuditChainState>().ToTable("AuditChainState").HasKey(item => item.Id);
        builder.Entity<AuditChainState>().Property(item => item.Id).ValueGeneratedNever();
        builder.Entity<AuditChainRestart>().ToTable("AuditChainRestarts").HasKey(item => item.StartSequence);
        builder.Entity<AuditChainRestart>().Property(item => item.StartSequence).ValueGeneratedNever();
        builder.Entity<AuditEvent>().Property(item => item.CreatedUtc)
            .HasConversion(value => value, value => DateTime.SpecifyKind(value, DateTimeKind.Utc));
        builder.Entity<ShareGrant>().HasIndex(share => share.TokenHash).IsUnique();
        builder.Entity<ShareGrant>().HasIndex(share => share.FileId);
    }
}
