using System.Net.Mail;
using System.Security.Cryptography;
using System.Text;
using Microsoft.AspNetCore.Identity;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace HANKAN.Web;

public enum SetupState { Unconfigured, Ready, RecoveryRequired }

public sealed class SetupStore
{
    private const int ApplicationId = 1397966930;
    private const int SchemaVersion = FileKeyEnvelope.SchemaVersion;
    private readonly string contentRoot;
    private readonly string dataDirectory;
    private readonly string databasePath;
    private readonly string markerPath;
    private readonly object gate = new();
    private readonly SemaphoreSlim setupGate = new(1, 1);
    private readonly IServiceScopeFactory scopes;
    private readonly IAuditKeyProtector auditKeys;
    private readonly byte[] setupCodeBytes = RandomNumberGenerator.GetBytes(24);

    public string SetupCode => Convert.ToHexString(setupCodeBytes);

    public SetupStore(IServiceScopeFactory scopes, IWebHostEnvironment environment, IAuditKeyProtector auditKeys)
    {
        this.scopes = scopes;
        this.auditKeys = auditKeys;
        contentRoot = Path.GetFullPath(environment.ContentRootPath);
        dataDirectory = Path.GetFullPath(Environment.GetEnvironmentVariable("HANKAN_DATA_DIR")
            ?? Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.LocalApplicationData), "HANKAN"));
        databasePath = Path.Combine(dataDirectory, "hankan.db");
        markerPath = Path.Combine(dataDirectory, "instance.marker");
        Initialize();
    }

    public SetupState State
    {
        get
        {
            lock (gate)
            {
                try
                {
                    if (!File.Exists(databasePath) || !File.Exists(markerPath)) return SetupState.RecoveryRequired;
                    using var connection = Open();
                    if (ScalarLong(connection, "PRAGMA application_id;") != ApplicationId) return SetupState.RecoveryRequired;
                    if (ScalarLong(connection, "PRAGMA user_version;") != SchemaVersion) return SetupState.RecoveryRequired;
                    var completed = ScalarLong(connection, "SELECT Completed FROM AppState WHERE Id = 1;");
                    var adminCount = ScalarLong(connection, "SELECT COUNT(*) FROM AspNetUsers WHERE IsAdmin = 1;");
                    if (completed == 0) return adminCount == 0 ? SetupState.Unconfigured : SetupState.RecoveryRequired;
                    if (completed != 1 || adminCount != 1) return SetupState.RecoveryRequired;
                    using var command = connection.CreateCommand();
                    command.CommandText = "SELECT FolderPath, DpapiProbe, ProtectedKek FROM AppState WHERE Id = 1;";
                    using var reader = command.ExecuteReader();
                    if (!reader.Read() || reader.IsDBNull(0) || reader.IsDBNull(1)) return SetupState.RecoveryRequired;
                    if (!Directory.Exists(reader.GetString(0))) return SetupState.RecoveryRequired;
                    if (!OperatingSystem.IsWindows()) return SetupState.RecoveryRequired;
                    var plain = ProtectedData.Unprotect((byte[])reader[1], null, DataProtectionScope.CurrentUser);
                    bool validProbe;
                    try { validProbe = plain.Length == 32; }
                    finally { CryptographicOperations.ZeroMemory(plain); }
                    if (!validProbe || reader[2] is not byte[] protectedKek || protectedKek.Length == 0)
                        return SetupState.RecoveryRequired;
                    var kek = ProtectedData.Unprotect(protectedKek, null, DataProtectionScope.CurrentUser);
                    try
                    {
                        if (kek.Length != 32) return SetupState.RecoveryRequired;
                    }
                    finally { CryptographicOperations.ZeroMemory(kek); }
                    reader.Close();
                    if (!validProbe) return SetupState.RecoveryRequired;
                    var protectedKey = AuditChain.ReadProtectedKey(connection);
                    if (protectedKey is null) return SetupState.RecoveryRequired;
                    var key = AuditChain.RestoreKey(protectedKey, auditKeys);
                    CryptographicOperations.ZeroMemory(key);
                    return SetupState.Ready;
                }
                catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SqliteException or CryptographicException or PlatformNotSupportedException)
                {
                    return SetupState.RecoveryRequired;
                }
            }
        }
    }

    public async Task<string?> ConfigureAsync(string code, string email, string password, string folderInput, int quotaGiB)
    {
        await setupGate.WaitAsync();
        try
        {
            if (State != SetupState.Unconfigured) return "최초 설정을 진행할 수 없습니다. 현재 상태를 확인하세요.";
            var supplied = Encoding.ASCII.GetBytes(code);
            var expected = Encoding.ASCII.GetBytes(SetupCode);
            if (supplied.Length != expected.Length || !CryptographicOperations.FixedTimeEquals(supplied, expected))
                return "콘솔 일회용 값이 올바르지 않습니다.";
            email = email.Trim();
            if (email.Length > 254 || !MailAddress.TryCreate(email, out var address) || address.Address != email)
                return "올바른 관리자 이메일을 입력하세요.";
            if (password.Length is < 12 or > 128)
                return "비밀번호는 12~128자로 입력하세요.";
            if (quotaGiB is < 1 or > 1024) return "전체 용량은 1~1024 GiB로 입력하세요.";
            if (!Path.IsPathFullyQualified(folderInput)) return "Windows 절대 경로를 입력하세요.";

            try
            {
                var folder = Path.GetFullPath(folderInput.Trim());
                if (folder.Equals(Path.GetPathRoot(folder), StringComparison.OrdinalIgnoreCase) ||
                    IsUnder(folder, dataDirectory) || IsUnder(dataDirectory, folder) ||
                    IsUnder(folder, contentRoot) || IsUnder(contentRoot, folder))
                    return "앱 또는 데이터베이스와 분리된 전용 폴더를 선택하세요.";
                if (HasReparsePoint(folder)) return "바로가기나 연결 폴더 대신 실제 전용 폴더를 선택하세요.";
                if (Directory.Exists(folder) && Directory.EnumerateFileSystemEntries(folder).Any())
                    return "비어 있는 전용 폴더를 선택하세요. 기존 파일은 가져오지 않습니다.";
                Directory.CreateDirectory(folder);
                var probeFile = Path.Combine(folder, $".hankan-probe-{Guid.NewGuid():N}");
                using (File.Create(probeFile)) { }
                File.Delete(probeFile);

                if (!OperatingSystem.IsWindows()) return "Windows에서만 최초 설정할 수 있습니다.";
                var plainProbe = RandomNumberGenerator.GetBytes(32);
                byte[] probe;
                try { probe = ProtectedData.Protect(plainProbe, null, DataProtectionScope.CurrentUser); }
                finally { CryptographicOperations.ZeroMemory(plainProbe); }
                var restoredProbe = ProtectedData.Unprotect(probe, null, DataProtectionScope.CurrentUser);
                try
                {
                    if (restoredProbe.Length != 32) return "Windows 키 보호 기능을 확인할 수 없습니다.";
                }
                finally { CryptographicOperations.ZeroMemory(restoredProbe); }
                using var scope = scopes.CreateScope();
                var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
                var users = scope.ServiceProvider.GetRequiredService<UserManager<AppUser>>();
                using var transaction = db.Database.BeginTransaction();
                var result = await users.CreateAsync(new AppUser
                {
                    UserName = email,
                    Email = email,
                    IsAdmin = true
                }, password);
                if (!result.Succeeded) return "관리자 계정을 만들 수 없습니다. 입력값을 확인하세요.";
                var configuration = db.Configurations.Single(state => state.Id == 1 && !state.Completed);
                configuration.FolderPath = folder;
                configuration.QuotaBytes = (long)quotaGiB * 1024 * 1024 * 1024;
                configuration.DpapiProbe = probe;
                var kek = RandomNumberGenerator.GetBytes(32);
                try { configuration.ProtectedKek = ProtectedData.Protect(kek, null, DataProtectionScope.CurrentUser); }
                finally { CryptographicOperations.ZeroMemory(kek); }
                configuration.Completed = true;
                db.SaveChanges();
                AuditChain.Initialize((SqliteConnection)db.Database.GetDbConnection(),
                    (SqliteTransaction)transaction.GetDbTransaction(), auditKeys);
                transaction.Commit();
                CryptographicOperations.ZeroMemory(setupCodeBytes);
                return null;
            }
            catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SqliteException or DbUpdateException or CryptographicException or ArgumentException or PlatformNotSupportedException)
            {
                return "저장 폴더 또는 데이터베이스 준비에 실패했습니다. 경로와 접근 권한을 확인하세요.";
            }
        }
        finally
        {
            setupGate.Release();
        }
    }

    public bool IsAdmin(string? userId)
    {
        if (State != SetupState.Ready || string.IsNullOrEmpty(userId)) return false;
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT COUNT(*) FROM AspNetUsers WHERE Id = $id AND IsAdmin = 1;";
        command.Parameters.AddWithValue("$id", userId);
        return Convert.ToInt64(command.ExecuteScalar()) == 1;
    }

    public (string Email, string Folder, long QuotaBytes)? Details()
    {
        if (State != SetupState.Ready) return null;
        using var connection = Open();
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT AspNetUsers.Email, AppState.FolderPath, AppState.QuotaBytes FROM AspNetUsers CROSS JOIN AppState WHERE AspNetUsers.IsAdmin = 1 AND AppState.Id = 1;";
        using var reader = command.ExecuteReader();
        return reader.Read() ? (reader.GetString(0), reader.GetString(1), reader.GetInt64(2)) : null;
    }

    private void Initialize()
    {
        try
        {
            Directory.CreateDirectory(dataDirectory);
            if (!File.Exists(databasePath) && File.Exists(markerPath)) return;
            using var connection = Open(create: true);
            var id = ScalarLong(connection, "PRAGMA application_id;");
            if (id != 0 && id != ApplicationId) return;
            if (id == 0 && File.Exists(markerPath)) return;
            if (id == ApplicationId && File.Exists(markerPath))
            {
                if (ScalarLong(connection, "PRAGMA user_version;") == 1)
                    UpgradeV1(connection);
                if (ScalarLong(connection, "PRAGMA user_version;") == 2)
                    UpgradeV2(connection);
                if (ScalarLong(connection, "PRAGMA user_version;") == 3)
                    UpgradeV3(connection);
                if (ScalarLong(connection, "PRAGMA user_version;") == 4)
                    UpgradeV4(connection);
                if (ScalarLong(connection, "PRAGMA user_version;") == 5)
                    UpgradeV5(connection);
                if (ScalarLong(connection, "PRAGMA user_version;") == 6)
                {
                    using var transaction = connection.BeginTransaction();
                    AuditChain.UpgradeV6(connection, transaction, auditKeys);
                    transaction.Commit();
                }
                if (ScalarLong(connection, "PRAGMA user_version;") is 7 or SchemaVersion)
                    FileKeyEnvelope.Upgrade(connection,
                        bytes => OperatingSystem.IsWindows()
                            ? ProtectedData.Protect(bytes, null, DataProtectionScope.CurrentUser)
                            : throw new PlatformNotSupportedException(),
                        bytes => OperatingSystem.IsWindows()
                            ? ProtectedData.Unprotect(bytes, null, DataProtectionScope.CurrentUser)
                            : throw new PlatformNotSupportedException());
                return;
            }
            var known = ScalarLong(connection, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%';");
            if (known != 0) return;
            connection.Close();
            using var scope = scopes.CreateScope();
            var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
            db.Database.EnsureCreated();
            db.Configurations.Add(new StorageConfiguration());
            db.SaveChanges();
            using var initialized = Open();
            using var command = initialized.CreateCommand();
            command.CommandText = $"PRAGMA application_id = 1397966930; PRAGMA user_version = {SchemaVersion};";
            command.ExecuteNonQuery();
            File.WriteAllText(markerPath, "HANKAN instance\n");
        }
        catch (Exception exception) when (exception is IOException or UnauthorizedAccessException or SqliteException or DbUpdateException
            or CryptographicException or PlatformNotSupportedException)
        {
        }
    }

    private static void UpgradeV1(SqliteConnection connection)
    {
        if (ScalarLong(connection, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'AspNetUsers';") != 1 ||
            ScalarLong(connection, "SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'AppState';") != 1 ||
            ScalarLong(connection, "SELECT COUNT(*) FROM AspNetUsers WHERE IsAdmin = 1;") > 1)
            return;
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "ALTER TABLE AspNetUsers ADD COLUMN AccessState TEXT NOT NULL DEFAULT 'unrequested';";
        command.ExecuteNonQuery();
        command.CommandText = "ALTER TABLE AspNetUsers ADD COLUMN RequestedRole TEXT NULL;";
        command.ExecuteNonQuery();
        command.CommandText = "PRAGMA user_version = 2;";
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    private static void UpgradeV2(SqliteConnection connection)
    {
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE "StoredFiles" (
                "Id" TEXT NOT NULL CONSTRAINT "PK_StoredFiles" PRIMARY KEY,
                "StorageName" TEXT NOT NULL,
                "OriginalName" TEXT NOT NULL,
                "UploaderId" TEXT NOT NULL,
                "UploaderEmail" TEXT NOT NULL,
                "State" TEXT NOT NULL,
                "SizeBytes" INTEGER NOT NULL,
                "ReservedBytes" INTEGER NOT NULL,
                "ProtectedKey" BLOB NULL,
                "Nonce" BLOB NULL,
                "Tag" BLOB NULL,
                "FormatVersion" INTEGER NOT NULL,
                "CreatedUtc" TEXT NOT NULL
            );
            CREATE UNIQUE INDEX "IX_StoredFiles_StorageName" ON "StoredFiles" ("StorageName");
            CREATE INDEX "IX_StoredFiles_State" ON "StoredFiles" ("State");
            CREATE TABLE "AuditEvents" (
                "Id" INTEGER NOT NULL CONSTRAINT "PK_AuditEvents" PRIMARY KEY AUTOINCREMENT,
                "CreatedUtc" TEXT NOT NULL,
                "ActorId" TEXT NOT NULL,
                "Action" TEXT NOT NULL,
                "FileId" TEXT NULL
            );
            PRAGMA user_version = 3;
            """;
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    private static void UpgradeV3(SqliteConnection connection)
    {
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE "Shares" (
                "Id" TEXT NOT NULL CONSTRAINT "PK_Shares" PRIMARY KEY,
                "FileId" TEXT NOT NULL,
                "CreatorId" TEXT NOT NULL,
                "CreatorEmail" TEXT NOT NULL,
                "Mode" TEXT NOT NULL,
                "CreatedUtc" TEXT NOT NULL,
                "ExpiresUtc" TEXT NOT NULL,
                "CancelledUtc" TEXT NULL,
                "TokenHash" TEXT NOT NULL,
                "ProtectedTokenKey" BLOB NOT NULL,
                "TokenNonce" BLOB NOT NULL,
                "TokenCipher" BLOB NOT NULL,
                "TokenTag" BLOB NOT NULL,
                "PasswordSalt" BLOB NULL,
                "PasswordHash" BLOB NULL,
                "FailedAttempts" INTEGER NOT NULL,
                "BlockedUntilUtc" TEXT NULL
            );
            CREATE UNIQUE INDEX "IX_Shares_TokenHash" ON "Shares" ("TokenHash");
            CREATE INDEX "IX_Shares_FileId" ON "Shares" ("FileId");
            PRAGMA user_version = 4;
            """;
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    private static void UpgradeV4(SqliteConnection connection)
    {
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            ALTER TABLE "AuditEvents" ADD COLUMN "TargetId" TEXT NULL;
            ALTER TABLE "AuditEvents" ADD COLUMN "Result" TEXT NOT NULL DEFAULT 'success';
            UPDATE "AuditEvents" SET "TargetId" = "FileId",
                "Result" = CASE WHEN "Action" LIKE '%.failed' THEN 'failure' ELSE 'success' END;
            CREATE INDEX "IX_AuditEvents_CreatedUtc" ON "AuditEvents" ("CreatedUtc", "Id");
            PRAGMA user_version = 5;
            """;
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    private static void UpgradeV5(SqliteConnection connection)
    {
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = """
            CREATE TABLE "Folders" (
                "Id" TEXT NOT NULL CONSTRAINT "PK_Folders" PRIMARY KEY,
                "ParentId" TEXT NULL,
                "Name" TEXT COLLATE NOCASE NOT NULL,
                "CreatedUtc" TEXT NOT NULL
            );
            CREATE INDEX "IX_Folders_ParentId" ON "Folders" ("ParentId");
            CREATE UNIQUE INDEX "IX_Folders_Root_Name" ON "Folders" ("Name") WHERE "ParentId" IS NULL;
            CREATE UNIQUE INDEX "IX_Folders_Parent_Name" ON "Folders" ("ParentId", "Name") WHERE "ParentId" IS NOT NULL;
            ALTER TABLE "StoredFiles" ADD COLUMN "FolderId" TEXT NULL;
            CREATE INDEX "IX_StoredFiles_FolderId" ON "StoredFiles" ("FolderId");
            PRAGMA user_version = 6;
            """;
        command.ExecuteNonQuery();
        transaction.Commit();
    }

    private SqliteConnection Open(bool create = false)
    {
        var connection = new SqliteConnection(new SqliteConnectionStringBuilder
        {
            DataSource = databasePath,
            Mode = create ? SqliteOpenMode.ReadWriteCreate : SqliteOpenMode.ReadWrite
        }.ToString());
        connection.Open();
        return connection;
    }

    private static long ScalarLong(SqliteConnection connection, string sql)
    {
        using var command = connection.CreateCommand();
        command.CommandText = sql;
        return command.ExecuteScalar() is long value ? value : -1;
    }

    private static bool IsUnder(string path, string parent) =>
        path.Equals(parent, StringComparison.OrdinalIgnoreCase) ||
        path.StartsWith(parent.TrimEnd(Path.DirectorySeparatorChar) + Path.DirectorySeparatorChar, StringComparison.OrdinalIgnoreCase);

    private static bool HasReparsePoint(string path)
    {
        for (var current = new DirectoryInfo(path); current is not null; current = current.Parent)
            if (current.Exists && (current.Attributes & FileAttributes.ReparsePoint) != 0) return true;
        return false;
    }

}
