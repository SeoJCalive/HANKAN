using System.Globalization;
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

// A damaged row remains displayable, but never enters the authenticated model.
public sealed class AuditReadEvent
{
    public long Id { get; set; }
    public string CreatedUtc { get; set; } = "";
    public string ActorId { get; set; } = "";
    public string Action { get; set; } = "";
    public string? FileId { get; set; }
    public string? TargetId { get; set; }
    public string Result { get; set; } = "";
    public long? ChainSequence { get; set; }
    public byte[]? PreviousMac { get; set; }
    public byte[]? Mac { get; set; }
    public AuditVerification? Failure { get; set; }

    public DateTime? ParseCreatedUtc() =>
        DateTime.TryParse(CreatedUtc, CultureInfo.InvariantCulture, DateTimeStyles.None, out var value)
            ? DateTime.SpecifyKind(value, DateTimeKind.Utc) : null;

    public AuditEvent ToEvent(DateTime createdUtc) => new()
    {
        Id = Id, CreatedUtc = createdUtc, ActorId = ActorId, Action = Action, FileId = FileId,
        TargetId = TargetId, Result = Result, ChainSequence = ChainSequence, PreviousMac = PreviousMac, Mac = Mac
    };
}

public static class AuditChain
{
    public const long LimitBytes = 104857600;

    private sealed class RawRow(string table, Dictionary<string, object> values)
    {
        public string Location => table + " / " + (table switch
        {
            "AuditEvents" => values["Id"] is long id ? $"Id {id}" : $"rowid {values["__rowid"]}",
            "AuditChainState" => values["Id"] is long stateId ? $"Id {stateId}" : $"rowid {values["__rowid"]}",
            _ => $"rowid {values["__rowid"]}"
        }) + (table == "AuditEvents" && values.GetValueOrDefault("ChainSequence") is long sequence
            ? $", 순번 {sequence}" : "");

        public AuditIntegrityException Fail(string field, string reason) => new(new(
            DateTime.UtcNow, null, 0, null, null, 0, 0, false, Location, $"{field} {reason}", []));

        public T Value<T>(string field)
        {
            if (values[field] is T value) return value;
            throw Fail(field, "저장 형식이 올바르지 않습니다.");
        }

        public T? NullableValue<T>(string field) where T : struct =>
            values[field] is DBNull ? null : Value<T>(field);

        public string? NullableText(string field) =>
            values[field] is DBNull ? null : Value<string>(field);

        public byte[]? Mac(string field, bool nullable = false)
        {
            if (nullable && values[field] is DBNull) return null;
            var value = Value<byte[]>(field);
            if (value.Length != 32) throw Fail(field, "MAC 길이가 올바르지 않습니다.");
            return value;
        }

        public DateTime Utc(string field)
        {
            var text = Value<string>(field);
            if (!DateTime.TryParse(text, CultureInfo.InvariantCulture, DateTimeStyles.None, out var value))
                throw Fail(field, "날짜 형식이 올바르지 않습니다.");
            return DateTime.SpecifyKind(value, DateTimeKind.Utc);
        }

        public long Integer(string field, long minimum = 0, long maximum = long.MaxValue)
        {
            var value = Value<long>(field);
            if (value < minimum || value > maximum) throw Fail(field, "정수 범위가 올바르지 않습니다.");
            return value;
        }
    }

    // GetValue preserves SQLite storage classes. Typed provider getters can coerce or throw
    // before we can attribute corruption; database/reader failures deliberately propagate.
    private static List<RawRow> ReadRows(SqliteConnection connection, SqliteTransaction? transaction,
        string table, string columns = "*", string order = "rowid")
    {
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = $"SELECT rowid AS __rowid,{columns} FROM {table} ORDER BY {order}";
        using var reader = command.ExecuteReader();
        var rows = new List<RawRow>();
        while (reader.Read())
        {
            var values = new Dictionary<string, object>();
            for (var i = 0; i < reader.FieldCount; i++) values.Add(reader.GetName(i), reader.GetValue(i));
            rows.Add(new RawRow(table, values));
        }
        return rows;
    }

    private static List<RawRow> ReadRows(AppDbContext db, string table,
        string columns = "*", string order = "rowid")
    {
        db.Database.OpenConnection();
        try
        {
            return ReadRows((SqliteConnection)db.Database.GetDbConnection(),
                (SqliteTransaction?)db.Database.CurrentTransaction?.GetDbTransaction(), table, columns, order);
        }
        finally { db.Database.CloseConnection(); }
    }

    private static AuditChainState ReadState(RawRow row)
    {
        var state = new AuditChainState
        {
            Id = (int)row.Integer("Id", 1, int.MaxValue),
            FormatVersion = row.Integer("FormatVersion", 1, 1),
            ChainId = row.Value<string>("ChainId"),
            StartedUtc = row.Utc("StartedUtc"),
            LegacyMaxId = row.Integer("LegacyMaxId"),
            ProtectedHmacKey = row.Value<byte[]>("ProtectedHmacKey"),
            LastSequence = row.Integer("LastSequence"),
            LastMac = row.Mac("LastMac")!,
            StateMac = row.Mac("StateMac")!
        };
        if (state.Id != 1) throw row.Fail("Id", "상태 행 식별자가 올바르지 않습니다.");
        if (!Guid.TryParseExact(state.ChainId, "N", out _))
            throw row.Fail("ChainId", "GUID 형식이 올바르지 않습니다.");
        if (state.ProtectedHmacKey.Length == 0) throw row.Fail("ProtectedHmacKey", "보호 키가 없습니다.");
        return state;
    }

    // Setup reads only the key column: a missing or empty key needs recovery, while other
    // malformed state values stay Ready so the verification screen can report them.
    public static byte[]? ReadProtectedKey(SqliteConnection connection)
    {
        using var command = connection.CreateCommand();
        command.CommandText = "SELECT ProtectedHmacKey FROM AuditChainState LIMIT 2";
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return null;
        var key = reader.GetValue(0) as byte[];
        return reader.Read() || key is not { Length: > 0 } ? null : key;
    }

    public static List<AuditReadEvent> ReadEvents(AppDbContext db)
    {
        var events = new List<AuditReadEvent>();
        foreach (var row in ReadRows(db, "AuditEvents"))
        {
            var item = new AuditReadEvent();
            try
            {
                item.Id = row.Integer("Id", 1);
                item.ChainSequence = row.NullableValue<long>("ChainSequence");
                if (item.ChainSequence is < 1) throw row.Fail("ChainSequence", "정수 범위가 올바르지 않습니다.");
                item.CreatedUtc = row.Value<string>("CreatedUtc");
                item.ActorId = row.Value<string>("ActorId");
                item.Action = row.Value<string>("Action");
                item.FileId = row.NullableText("FileId");
                item.TargetId = row.NullableText("TargetId");
                item.Result = row.Value<string>("Result");
                if (item.Result is not ("success" or "denied" or "failure"))
                    throw row.Fail("Result", "사건 결과가 올바르지 않습니다.");
                item.PreviousMac = row.Mac("PreviousMac", true);
                item.Mac = row.Mac("Mac", true);
                row.Utc("CreatedUtc");
            }
            catch (AuditIntegrityException exception) { item.Failure = exception.Result; }
            events.Add(item);
        }
        return events;
    }

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
        var state = new AuditChainState
        {
            ChainId = Guid.NewGuid().ToString("N"), StartedUtc = DateTime.UtcNow,
            LegacyMaxId = ReadRows(connection, transaction, "AuditEvents", "Id")
                .Select(row => row.Integer("Id", 1)).DefaultIfEmpty(0).Max()
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
        public required List<AuditEvent> Rows { get; init; }
        public void Dispose() => CryptographicOperations.ZeroMemory(Key);
    }

    // No tracking: an outer transaction may have committed a newer tail since this context was created.
    public static Snapshot ReadVerified(AppDbContext db, IAuditKeyProtector protector)
    {
        AuditChainState? state = null;
        var restarts = new List<AuditChainRestart>();
        byte[] key = [];
        var now = DateTime.UtcNow;
        long verified = 0, legacy = 0;
        long? first = null, last = null;
        AuditIntegrityException Fail(string location, string reason) => new(new(now, state?.StartedUtc,
            state?.LegacyMaxId ?? 0, first, last, verified, legacy, false, location, reason, restarts));
        try
        {
            var states = ReadRows(db, "AuditChainState").Select(ReadState).ToList();
            if (states.Count != 1) throw Fail("상태", "체인 상태가 없거나 단일 행이 아닙니다.");
            state = states[0];
            foreach (var row in ReadRows(db, "AuditChainRestarts"))
            {
                var restart = new AuditChainRestart
                {
                    StartSequence = row.Integer("StartSequence", 1),
                    EndSequence = row.Integer("EndSequence", 1),
                    EndMac = row.Mac("EndMac")!,
                    RecordedUtc = row.Utc("RecordedUtc"),
                    Reason = row.Value<string>("Reason")
                };
                if (restart.Reason is not ("period" or "size" or "period+size"))
                    throw row.Fail("Reason", "삭제 이유가 올바르지 않습니다.");
                restarts.Add(restart);
            }
            restarts.Sort((left, right) => left.StartSequence.CompareTo(right.StartSequence));
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
            var rows = ReadEvents(db).OrderBy(item => item.ChainSequence).ThenBy(item => item.Id)
                .Select(item =>
                {
                    if (item.Failure is not null) throw Fail(item.Failure.Location, item.Failure.Reason);
                    return item.ToEvent(item.ParseCreatedUtc()!.Value);
                }).ToList();
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
            return new Snapshot { State = state, Restarts = restarts, Key = key, Rows = rows };
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
            var rows = snapshot.Rows.Where(item => item.ChainSequence != null).ToList();
            return new(DateTime.UtcNow, snapshot.State.StartedUtc, snapshot.State.LegacyMaxId,
                rows.Min(item => item.ChainSequence), rows.Max(item => item.ChainSequence), rows.Count,
                snapshot.Rows.LongCount(item => item.ChainSequence == null), true, "", "", snapshot.Restarts);
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
        var expired = snapshot.Rows.Where(item => item.CreatedUtc < cutoff).ToList();
        var reasons = expired.ToDictionary(item => item.Id, _ => "period");
        // Keep the original seven-field SQL byte expression, including exact UTC O formatting.
        var sizes = ReadRows(db, "AuditEvents", $"Id, {AppDbContext.AuditBytesSql} AS Bytes", "CreatedUtc, Id")
            .Select(row => (Id: row.Integer("Id", 1), Bytes: row.Integer("Bytes"))).ToList();
        var remaining = sizes.Where(item => !reasons.ContainsKey(item.Id)).Sum(item => item.Bytes);
        foreach (var size in sizes.Where(item => !reasons.ContainsKey(item.Id)))
        {
            if (remaining <= LimitBytes) break;
            reasons.Add(size.Id, "size");
            remaining -= size.Bytes;
        }
        var selected = reasons.Count == 0 ? [] : snapshot.Rows
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
}
