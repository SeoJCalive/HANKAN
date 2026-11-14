using System.Security.Cryptography;
using System.Text;
using Microsoft.Data.Sqlite;

namespace HANKAN.Web;

public static class FileKeyEnvelope
{
    public const int SchemaVersion = 8;

    private static byte[] AssociatedData(string fileId)
    {
        if (!Guid.TryParseExact(fileId, "N", out var id) || id.ToString("N") != fileId)
            throw new CryptographicException("Invalid canonical file ID.");
        return Encoding.UTF8.GetBytes("HANKAN:file-dek:v2:" + fileId);
    }

    public static byte[] Wrap(byte[] kek, string fileId, byte[] dek)
    {
        if (kek.Length != 32 || dek.Length != 32)
            throw new CryptographicException("Invalid file key length.");
        var aad = AssociatedData(fileId);
        var envelope = new byte[61];
        envelope[0] = 1;
        RandomNumberGenerator.Fill(envelope.AsSpan(1, 12));
        using var aes = new AesGcm(kek, 16);
        aes.Encrypt(envelope.AsSpan(1, 12), dek, envelope.AsSpan(13, 32), envelope.AsSpan(45, 16), aad);
        return envelope;
    }

    public static byte[] Unwrap(byte[] kek, string fileId, byte[] envelope)
    {
        if (kek.Length != 32 || envelope.Length != 61 || envelope[0] != 1)
            throw new CryptographicException("Invalid file key envelope.");
        var aad = AssociatedData(fileId);
        var dek = new byte[32];
        try
        {
            using var aes = new AesGcm(kek, 16);
            aes.Decrypt(envelope.AsSpan(1, 12), envelope.AsSpan(13, 32), envelope.AsSpan(45, 16), dek, aad);
            return dek;
        }
        catch
        {
            CryptographicOperations.ZeroMemory(dek);
            throw;
        }
    }

    public static void Upgrade(SqliteConnection connection, Func<byte[], byte[]> protect, Func<byte[], byte[]> unprotect)
    {
        using var transaction = connection.BeginTransaction();
        using var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = "PRAGMA user_version;";
        var version = Convert.ToInt64(command.ExecuteScalar());
        if (version != SchemaVersion - 1 && version != SchemaVersion)
            throw new CryptographicException("Unsupported file key schema.");
        command.CommandText = "SELECT Completed FROM AppState WHERE Id = 1;";
        var completed = command.ExecuteScalar();
        if (completed is not long state || state is not (0 or 1))
            throw new CryptographicException("Invalid installation state.");
        byte[]? kek = null;
        try
        {
            if (version == SchemaVersion)
            {
                if (state == 1)
                {
                    command.CommandText = "SELECT ProtectedKek FROM AppState WHERE Id = 1;";
                    if (command.ExecuteScalar() is not byte[] protectedKek || protectedKek.Length == 0)
                        throw new CryptographicException("Missing file KEK.");
                    kek = unprotect(protectedKek);
                    if (kek.Length != 32) throw new CryptographicException("Invalid file KEK length.");
                }
                transaction.Commit();
                return;
            }

            if (state == 1)
            {
                command.CommandText = "SELECT DpapiProbe FROM AppState WHERE Id = 1;";
                if (command.ExecuteScalar() is not byte[] probe || probe.Length == 0)
                    throw new CryptographicException("Missing DPAPI probe.");
                var plainProbe = unprotect(probe);
                try
                {
                    if (plainProbe.Length != 32) throw new CryptographicException("Invalid DPAPI probe.");
                }
                finally { CryptographicOperations.ZeroMemory(plainProbe); }
            }
            command.CommandText = "ALTER TABLE AppState ADD COLUMN ProtectedKek BLOB NULL;";
            command.ExecuteNonQuery();
            if (state == 1)
            {
                kek = RandomNumberGenerator.GetBytes(32);
                var protectedKek = protect(kek);
                command.CommandText = "UPDATE AppState SET ProtectedKek = $kek WHERE Id = 1;";
                command.Parameters.AddWithValue("$kek", protectedKek);
                command.ExecuteNonQuery();
                command.Parameters.Clear();

                command.CommandText = "SELECT Id, State, ProtectedKey, FormatVersion FROM StoredFiles;";
                using (var reader = command.ExecuteReader())
                {
                    using var update = connection.CreateCommand();
                    update.Transaction = transaction;
                    update.CommandText = "UPDATE StoredFiles SET ProtectedKey = $key, FormatVersion = 2 WHERE Id = $id;";
                    while (reader.Read())
                    {
                        if (reader[0] is not string id)
                            throw new CryptographicException("Invalid legacy file ID.");
                        _ = AssociatedData(id);
                        if (reader[3] is not long format || format != 1)
                            throw new CryptographicException("Unsupported legacy file format.");
                        byte[]? wrapped = null;
                        if (reader.IsDBNull(2))
                        {
                            if (reader[1] is not ("uploading" or "deleted"))
                                throw new CryptographicException("Missing legacy file key.");
                        }
                        else
                        {
                            if (reader[2] is not byte[] legacy || legacy.Length == 0)
                                throw new CryptographicException("Invalid legacy file key.");
                            var dek = unprotect(legacy);
                            try { wrapped = Wrap(kek, id, dek); }
                            finally { CryptographicOperations.ZeroMemory(dek); }
                        }
                        update.Parameters.Clear();
                        update.Parameters.AddWithValue("$id", id);
                        update.Parameters.AddWithValue("$key", (object?)wrapped ?? DBNull.Value);
                        if (update.ExecuteNonQuery() != 1)
                            throw new CryptographicException("File key update was not saved.");
                    }
                }
            }
            command.CommandText = $"PRAGMA user_version = {SchemaVersion};";
            command.ExecuteNonQuery();
            transaction.Commit();
        }
        finally
        {
            if (kek is not null) CryptographicOperations.ZeroMemory(kek);
        }
    }
}
