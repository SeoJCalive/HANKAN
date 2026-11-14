using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;
using Microsoft.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore.Storage;

namespace HANKAN.Web;

public interface IAuditKeyProtector
{
    byte[] Protect(byte[] key);
    byte[] Unprotect(byte[] protectedKey);
}

public sealed class WindowsAuditKeyProtector : IAuditKeyProtector
{
    public byte[] Protect(byte[] key)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows DPAPI is required.");
        return ProtectedData.Protect(key, null, DataProtectionScope.CurrentUser);
    }

    public byte[] Unprotect(byte[] protectedKey)
    {
        if (!OperatingSystem.IsWindows()) throw new PlatformNotSupportedException("Windows DPAPI is required.");
        return ProtectedData.Unprotect(protectedKey, null, DataProtectionScope.CurrentUser);
    }
}

public sealed class AuditChainState
{
    public int Id { get; set; } = 1;
    public long FormatVersion { get; set; } = 1;
    public string ChainId { get; set; } = "";
    public DateTime StartedUtc { get; set; }
    public long LegacyMaxId { get; set; }
    public byte[] ProtectedHmacKey { get; set; } = [];
    public long LastSequence { get; set; }
    public byte[] LastMac { get; set; } = new byte[32];
    public byte[] StateMac { get; set; } = [];
}

public sealed class AuditChainRestart
{
    public long StartSequence { get; set; }
    public long EndSequence { get; set; }
    public byte[] EndMac { get; set; } = [];
    public DateTime RecordedUtc { get; set; }
    public string Reason { get; set; } = "";
}

public sealed record AuditVerification(DateTime ExecutedUtc, DateTime? StartedUtc, long LegacyMaxId,
    long? FirstSequence, long? LastSequence, long VerifiedCount, long LegacyCount, bool Ok,
    string Location, string Reason, IReadOnlyList<AuditChainRestart> Restarts);

public sealed class AuditIntegrityException(AuditVerification result) : InvalidOperationException(
    $"Audit integrity failure: {result.Location}: {result.Reason}")
{
    public AuditVerification Result { get; } = result;
}

public static class AuditChain
{
    public const long LimitBytes = 104857600;

    // BinaryWriter integers are fixed-width little-endian; strings use our explicit UTF-8 length.
    private static void Text(BinaryWriter writer, string? value)
    {
        if (value is null) { writer.Write(-1); return; }
        var bytes = Encoding.UTF8.GetBytes(value);
        writer.Write(bytes.Length);
        writer.Write(bytes);
    }

    private static void Blob(BinaryWriter writer, byte[] value)
    {
        writer.Write(value.Length);
        writer.Write(value);
    }

    private static long Ticks(DateTime value) =>
        (value.Kind == DateTimeKind.Unspecified ? DateTime.SpecifyKind(value, DateTimeKind.Utc) : value.ToUniversalTime()).Ticks;

    private static byte[] Authenticate(byte[] key, Action<BinaryWriter> encode)
    {
        using var stream = new MemoryStream();
        using (var writer = new BinaryWriter(stream, Encoding.UTF8, true)) encode(writer);
        return HMACSHA256.HashData(key, stream.GetBuffer().AsSpan(0, checked((int)stream.Length)));
    }

    public static byte[] EntryMac(byte[] key, string chainId, AuditEvent entry) => Authenticate(key, writer =>
    {
        Text(writer, "HANKAN.audit.entry.v1");
        Text(writer, chainId);
        writer.Write(entry.ChainSequence!.Value);
        Blob(writer, entry.PreviousMac!);
        writer.Write(entry.Id);
        writer.Write(Ticks(entry.CreatedUtc));
        Text(writer, entry.ActorId);
        Text(writer, entry.Action);
        Text(writer, entry.FileId);
        Text(writer, entry.TargetId);
        Text(writer, entry.Result);
    });

    public static byte[] StateMac(byte[] key, AuditChainState state, IReadOnlyList<AuditChainRestart> restarts) =>
        Authenticate(key, writer =>
        {
            Text(writer, "HANKAN.audit.state.v1");
            writer.Write((long)state.Id);
            writer.Write(state.FormatVersion);
            Text(writer, state.ChainId);
            writer.Write(Ticks(state.StartedUtc));
            writer.Write(state.LegacyMaxId);
            Blob(writer, state.ProtectedHmacKey);
            writer.Write(state.LastSequence);
            Blob(writer, state.LastMac);
            writer.Write(restarts.Count);
            foreach (var restart in restarts.OrderBy(item => item.StartSequence))
            {
                writer.Write(restart.StartSequence);
                writer.Write(restart.EndSequence);
                Blob(writer, restart.EndMac);
                writer.Write(Ticks(restart.RecordedUtc));
                Text(writer, restart.Reason);
            }
        });

    private static bool Same(byte[]? left, byte[]? right) =>
        left?.Length == 32 && right?.Length == 32 && CryptographicOperations.FixedTimeEquals(left, right);

    public static byte[] RestoreKey(byte[] protectedKey, IAuditKeyProtector protector)
    {
        if (protectedKey.Length == 0) throw new CryptographicException("Audit key is missing.");
        var key = protector.Unprotect(protectedKey);
        if (key.Length == 32) return key;
        CryptographicOperations.ZeroMemory(key);
        throw new CryptographicException("Audit key length is invalid.");
    }

    public static void Initialize(SqliteConnection connection, SqliteTransaction transaction, IAuditKeyProtector protector)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "SELECT count(*) FROM AuditChainState";
        if (Convert.ToInt64(command.ExecuteScalar()) != 0)
            throw new InvalidOperationException("Audit chain is already initialized.");
        command.CommandText = "SELECT coalesce(max(Id),0) FROM AuditEvents";
        var state = new AuditChainState
        {
            ChainId = Guid.NewGuid().ToString("N"), StartedUtc = DateTime.UtcNow,
            LegacyMaxId = Convert.ToInt64(command.ExecuteScalar())
        };
        var key = RandomNumberGenerator.GetBytes(32);
        try
        {
            state.ProtectedHmacKey = protector.Protect(key);
            state.StateMac = StateMac(key, state, []);
            command.CommandText = """
                INSERT INTO AuditChainState (Id,FormatVersion,ChainId,StartedUtc,LegacyMaxId,ProtectedHmacKey,LastSequence,LastMac,StateMac)
                VALUES (1,$version,$chain,$started,$legacy,$key,0,$last,$mac)
                """;
            command.Parameters.AddWithValue("$version", state.FormatVersion);
            command.Parameters.AddWithValue("$chain", state.ChainId);
            command.Parameters.AddWithValue("$started", state.StartedUtc);
            command.Parameters.AddWithValue("$legacy", state.LegacyMaxId);
            command.Parameters.AddWithValue("$key", state.ProtectedHmacKey);
            command.Parameters.AddWithValue("$last", state.LastMac);
            command.Parameters.AddWithValue("$mac", state.StateMac);
            command.ExecuteNonQuery();
        }
        finally { CryptographicOperations.ZeroMemory(key); }
    }

    // Caller owns this transaction, including the version change and initial key.
    public static void UpgradeV6(SqliteConnection connection, SqliteTransaction transaction, IAuditKeyProtector protector)
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "PRAGMA user_version";
        if (Convert.ToInt64(command.ExecuteScalar()) == 7) return;
        command.CommandText = """
            ALTER TABLE AuditEvents ADD COLUMN ChainSequence INTEGER NULL;
            ALTER TABLE AuditEvents ADD COLUMN PreviousMac BLOB NULL;
            ALTER TABLE AuditEvents ADD COLUMN Mac BLOB NULL;
            CREATE UNIQUE INDEX IX_AuditEvents_ChainSequence ON AuditEvents (ChainSequence);
            CREATE TABLE AuditChainState (
                Id INTEGER NOT NULL PRIMARY KEY, FormatVersion INTEGER NOT NULL, ChainId TEXT NOT NULL,
                StartedUtc TEXT NOT NULL, LegacyMaxId INTEGER NOT NULL, ProtectedHmacKey BLOB NOT NULL,
                LastSequence INTEGER NOT NULL, LastMac BLOB NOT NULL, StateMac BLOB NOT NULL);
            CREATE TABLE AuditChainRestarts (
                StartSequence INTEGER NOT NULL PRIMARY KEY, EndSequence INTEGER NOT NULL,
                EndMac BLOB NOT NULL, RecordedUtc TEXT NOT NULL, Reason TEXT NOT NULL);
            """;
        command.ExecuteNonQuery();
        command.CommandText = "SELECT Completed FROM AppState WHERE Id=1";
        if (Convert.ToInt64(command.ExecuteScalar()) == 1) Initialize(connection, transaction, protector);
        command.CommandText = "PRAGMA user_version = 7";
        command.ExecuteNonQuery();
    }

    public sealed class Snapshot : IDisposable
    {
        public required AuditChainState State { get; init; }
        public required List<AuditChainRestart> Restarts { get; init; }
        public required byte[] Key { get; init; }
        public void Dispose() => CryptographicOperations.ZeroMemory(Key);
    }

    // No tracking: an outer transaction may have committed a newer tail since this context was created.
    public static Snapshot ReadVerified(AppDbContext db, IAuditKeyProtector protector)
    {
        var states = db.Set<AuditChainState>().AsNoTracking().ToList();
        var restarts = db.Set<AuditChainRestart>().AsNoTracking().OrderBy(item => item.StartSequence).ToList();
        var state = states.SingleOrDefault(item => item.Id == 1);
        byte[] key = [];
        var now = DateTime.UtcNow;
        long verified = 0, legacy = 0;
        long? first = null, last = null;
        AuditIntegrityException Fail(string location, string reason) => new(new(now, state?.StartedUtc,
            state?.LegacyMaxId ?? 0, first, last, verified, legacy, false, location, reason, restarts));
        try
        {
            if (states.Count != 1 || state is null) throw Fail("상태", "체인 상태가 없거나 단일 행이 아닙니다.");
            try { key = RestoreKey(state.ProtectedHmacKey, protector); }
            catch (Exception exception) when (exception is CryptographicException or PlatformNotSupportedException)
            { throw Fail("키", "보호 키를 복원할 수 없습니다. 같은 Windows 실행 계정과 백업을 확인하세요."); }
            if (state.FormatVersion != 1 || state.ChainId.Length != 32 || state.LastSequence < 0 ||
                state.LegacyMaxId < 0 || !Same(state.StateMac, StateMac(key, state, restarts)))
                throw Fail("상태/재시작 목록", "상태 인증 또는 형식이 올바르지 않습니다.");
            long precedingEnd = 0;
            foreach (var restart in restarts)
            {
                if (restart.StartSequence <= precedingEnd || restart.StartSequence < 1 ||
                    restart.EndSequence < restart.StartSequence || restart.EndSequence > state.LastSequence ||
                    restart.EndMac.Length != 32 || restart.Reason is not ("period" or "size" or "period+size") ||
                    precedingEnd != 0 && restart.StartSequence == precedingEnd + 1)
                    throw Fail("재시작 목록", "삭제 구간 형식 또는 순서가 올바르지 않습니다.");
                precedingEnd = restart.EndSequence;
            }
            var rows = db.AuditEvents.AsNoTracking().OrderBy(item => item.ChainSequence).ThenBy(item => item.Id).ToList();
            foreach (var row in rows.Where(item => item.ChainSequence is null))
            {
                if (row.Id > state.LegacyMaxId || row.PreviousMac is not null || row.Mac is not null)
                    throw Fail($"Id {row.Id}", "배포 경계 이후 서명 누락 또는 불완전한 체인 필드입니다.");
                legacy++;
            }
            var previous = new byte[32];
            long sequence = 0;
            var index = 0;
            foreach (var row in rows.Where(item => item.ChainSequence is not null))
            {
                while (index < restarts.Count && restarts[index].StartSequence == sequence + 1)
                {
                    sequence = restarts[index].EndSequence;
                    previous = restarts[index++].EndMac;
                }
                if (row.Id <= state.LegacyMaxId)
                    throw Fail($"Id {row.Id}, 순번 {row.ChainSequence}", "배포 전 행의 체인 필드가 변경되었습니다.");
                if (row.ChainSequence != sequence + 1)
                    throw Fail($"기대 순번 {sequence + 1} (실제 Id {row.Id}, 순번 {row.ChainSequence})", "순번이 누락·중복되었거나 삭제 구간과 겹칩니다.");
                if (!Same(row.PreviousMac, previous) || row.Mac?.Length != 32 ||
                    !Same(row.Mac, EntryMac(key, state.ChainId, row)))
                    throw Fail($"Id {row.Id}, 순번 {row.ChainSequence}", "사건 MAC 또는 이전 MAC이 일치하지 않습니다.");
                sequence = row.ChainSequence.Value;
                previous = row.Mac;
                first ??= sequence;
                last = sequence;
                verified++;
            }
            while (index < restarts.Count && restarts[index].StartSequence == sequence + 1)
            {
                sequence = restarts[index].EndSequence;
                previous = restarts[index++].EndMac;
            }
            if (index != restarts.Count || sequence != state.LastSequence || !Same(previous, state.LastMac))
                throw Fail($"기대 순번 {sequence + 1} / 끝 상태", "보존 체인과 인증된 끝 또는 삭제 구간이 일치하지 않습니다.");
            return new Snapshot { State = state, Restarts = restarts, Key = key };
        }
        catch { CryptographicOperations.ZeroMemory(key); throw; }
    }

    // A caller holding a read transaction can combine this with its page query in one snapshot.
    public static AuditVerification Verify(AppDbContext db, IAuditKeyProtector protector)
    {
        using var transaction = db.Database.CurrentTransaction is null ? db.Database.BeginTransaction() : null;
        try
        {
            using var snapshot = ReadVerified(db, protector);
            var rows = db.AuditEvents.AsNoTracking().Where(item => item.ChainSequence != null);
            return new(DateTime.UtcNow, snapshot.State.StartedUtc, snapshot.State.LegacyMaxId,
                rows.Min(item => item.ChainSequence), rows.Max(item => item.ChainSequence), rows.LongCount(),
                db.AuditEvents.LongCount(item => item.ChainSequence == null), true, "", "", snapshot.Restarts);
        }
        catch (AuditIntegrityException exception) { return exception.Result; }
    }

    public static void Append(AppDbContext db, Snapshot snapshot, IEnumerable<AuditEvent> entries)
    {
        // SaveChanges(false) keeps generated keys in EF's store-generated value sidecar.
        var saved = entries.Select(item => (Entry: item, Id: db.Entry(item).Property(row => row.Id).CurrentValue))
            .OrderBy(item => item.Id);
        foreach (var item in saved)
        {
            var entry = item.Entry;
            entry.Id = item.Id;
            entry.ChainSequence = checked(snapshot.State.LastSequence + 1);
            entry.PreviousMac = snapshot.State.LastMac.ToArray();
            entry.Mac = EntryMac(snapshot.Key, snapshot.State.ChainId, entry);
            db.Database.ExecuteSqlRaw("""
                UPDATE AuditEvents SET ChainSequence=$sequence, PreviousMac=$previous, Mac=$mac WHERE Id=$id
                """, new SqliteParameter("$sequence", entry.ChainSequence), new SqliteParameter("$previous", entry.PreviousMac),
                new SqliteParameter("$mac", entry.Mac), new SqliteParameter("$id", entry.Id));
            snapshot.State.LastSequence = entry.ChainSequence.Value;
            snapshot.State.LastMac = entry.Mac;
        }
        WriteState(db, snapshot);
    }

    private static void WriteState(AppDbContext db, Snapshot snapshot)
    {
        snapshot.State.StateMac = StateMac(snapshot.Key, snapshot.State, snapshot.Restarts);
        db.Database.ExecuteSqlRaw("UPDATE AuditChainState SET LastSequence=$sequence,LastMac=$last,StateMac=$mac WHERE Id=1",
            new SqliteParameter("$sequence", snapshot.State.LastSequence), new SqliteParameter("$last", snapshot.State.LastMac),
            new SqliteParameter("$mac", snapshot.State.StateMac));
    }

    public sealed record Retention(long ExpiredDeleted, long SizeDeleted, long Rows, long LogicalBytes);

    // The caller holds the SQLite write lock and owns commit/rollback.
    public static Retention Prune(AppDbContext db, IAuditKeyProtector protector, DateTime now)
    {
        using var snapshot = ReadVerified(db, protector);
        var cutoff = now.AddDays(-30);
        var expired = db.AuditEvents.AsNoTracking().Where(item => item.CreatedUtc < cutoff).ToList();
        var reasons = expired.ToDictionary(item => item.Id, _ => "period");
        // Keep the original seven-field SQL byte expression, including exact UTC O formatting.
        var sizes = db.Database.SqlQueryRaw<AuditSize>($"""
            SELECT Id, CreatedUtc, {AppDbContext.AuditBytesSql} AS Bytes FROM AuditEvents ORDER BY CreatedUtc, Id
            """).ToList();
        var remaining = sizes.Where(item => !reasons.ContainsKey(item.Id)).Sum(item => item.Bytes);
        foreach (var size in sizes.Where(item => !reasons.ContainsKey(item.Id)))
        {
            if (remaining <= LimitBytes) break;
            reasons.Add(size.Id, "size");
            remaining -= size.Bytes;
        }
        var selected = reasons.Count == 0 ? [] : db.AuditEvents.AsNoTracking().ToList()
            .Where(item => reasons.ContainsKey(item.Id)).ToList();
        var intervals = snapshot.Restarts.Concat(selected.Where(item => item.ChainSequence is not null)
            .Select(item => new AuditChainRestart
            {
                StartSequence = item.ChainSequence!.Value, EndSequence = item.ChainSequence.Value,
                EndMac = item.Mac!, RecordedUtc = now, Reason = reasons[item.Id]
            })).OrderBy(item => item.StartSequence).ToList();
        var merged = new List<AuditChainRestart>();
        foreach (var interval in intervals)
        {
            if (merged.Count == 0 || interval.StartSequence > merged[^1].EndSequence + 1) merged.Add(interval);
            else
            {
                var previous = merged[^1];
                if (interval.EndSequence > previous.EndSequence)
                {
                    previous.EndSequence = interval.EndSequence;
                    previous.EndMac = interval.EndMac;
                }
                previous.Reason = previous.Reason == interval.Reason ? previous.Reason : "period+size";
                previous.RecordedUtc = now;
            }
        }
        if (selected.Count != 0)
        {
            foreach (var row in selected)
                db.Database.ExecuteSqlRaw("DELETE FROM AuditEvents WHERE Id=$id", new SqliteParameter("$id", row.Id));
            db.Database.ExecuteSqlRaw("DELETE FROM AuditChainRestarts");
            foreach (var interval in merged)
                db.Database.ExecuteSqlRaw("""
                    INSERT INTO AuditChainRestarts (StartSequence,EndSequence,EndMac,RecordedUtc,Reason)
                    VALUES ($start,$end,$mac,$utc,$reason)
                    """, new SqliteParameter("$start", interval.StartSequence), new SqliteParameter("$end", interval.EndSequence),
                    new SqliteParameter("$mac", interval.EndMac), new SqliteParameter("$utc", interval.RecordedUtc),
                    new SqliteParameter("$reason", interval.Reason));
            snapshot.Restarts.Clear();
            snapshot.Restarts.AddRange(merged);
            WriteState(db, snapshot);
        }
        return new(expired.Count, reasons.Count - expired.Count, sizes.Count - reasons.Count, remaining);
    }

    private sealed class AuditSize
    {
        public long Id { get; set; }
        public DateTime CreatedUtc { get; set; }
        public long Bytes { get; set; }
    }
}
