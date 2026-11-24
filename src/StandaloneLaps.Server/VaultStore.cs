using System.Data;
using System.Data.Common;
using System.Globalization;
using System.Text.Json;
using Microsoft.Data.Sqlite;
using Npgsql;

namespace StandaloneLaps.Server;

public sealed class AgentClient
{
    public string DeviceId { get; set; }
    public string DisplayName { get; set; }
    public string CertificateSha256 { get; set; }
    public string Platform { get; set; }
    public string CreatedUtc { get; set; }
    public string CreatedBy { get; set; }
    public string DeletedUtc { get; set; }
    public string DeletedBy { get; set; }
    public bool Deleted => DeletedUtc != null;
}

public sealed class StoredRecord
{
    public Envelope Envelope { get; set; }
    public string ReceivedUtc { get; set; }
    public string AppliedUtc { get; set; }
}

public sealed class DeviceSummary
{
    public string DeviceId, Name, LastBackupUtc, LastAppliedUtc, CertificateSha256, Platform;
    public int Versions;
    public bool Deleted, Unconfirmed;
}

public sealed class StoredKey
{
    public string Name { get; set; }
    public string Sha256 { get; set; }
    public byte[] Pkcs12 { get; set; }
    public string CreatedUtc { get; set; }
}

public sealed class PackageInfo
{
    public string Token { get; set; }
    public string DeviceId { get; set; }
    public string DisplayName { get; set; }
    public string FileName { get; set; }
    public string Platform { get; set; }
    public string CreatedUtc { get; set; }
    public string ExpiresUtc { get; set; }
    public string CreatedBy { get; set; }
}

public sealed class PortalSettings
{
    public int HistoryLimit { get; set; } = ServerOptions.DefaultHistoryLimit;
    public string UpdatedUtc { get; set; }
    public string UpdatedBy { get; set; }
}

// Relational storage for SQLite (default, file in /data) or PostgreSQL. Only encrypted envelopes are stored;
// the recovery key that decrypts them is kept in the keys table, encrypted with the master key (KeyVault).
// Writes are serialized in-process; run one container instance per database.
public sealed class VaultStore
{
    private const int SchemaVersion = 1;
    private readonly ServerOptions options;
    private readonly SemaphoreSlim gate = new(1, 1);

    public VaultStore(ServerOptions options)
    {
        this.options = options;
    }

    public bool IsPostgres => options.IsPostgres;

    private DbConnection Open()
    {
        DbConnection connection = options.IsPostgres ? new NpgsqlConnection(options.ConnectionString) : new SqliteConnection(options.ConnectionString);
        connection.Open();
        if (!options.IsPostgres)
            using (var pragma = connection.CreateCommand())
            {
                pragma.CommandText = "PRAGMA journal_mode = WAL; PRAGMA synchronous = FULL; PRAGMA busy_timeout = 5000;";
                pragma.ExecuteNonQuery();
            }
        return connection;
    }

    private static DbCommand Command(DbConnection connection, DbTransaction transaction, string sql, params (string Name, object Value)[] parameters)
    {
        var command = connection.CreateCommand();
        command.Transaction = transaction;
        command.CommandText = sql;
        foreach (var (name, value) in parameters)
        {
            var parameter = command.CreateParameter();
            parameter.ParameterName = name;
            parameter.Value = value ?? DBNull.Value;
            if (value is byte[]) parameter.DbType = DbType.Binary;
            command.Parameters.Add(parameter);
        }
        return command;
    }

    private static string Text(DbDataReader reader, int index) => reader.IsDBNull(index) ? null : reader.GetString(index);

    public void Initialize()
    {
        if (!options.IsPostgres)
        {
            var builder = new SqliteConnectionStringBuilder(options.ConnectionString);
            var directory = Path.GetDirectoryName(Path.GetFullPath(builder.DataSource));
            if (!string.IsNullOrEmpty(directory)) Directory.CreateDirectory(directory);
        }
        var blob = options.IsPostgres ? "BYTEA" : "BLOB";
        var identity = options.IsPostgres ? "BIGSERIAL PRIMARY KEY" : "INTEGER PRIMARY KEY AUTOINCREMENT";
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        foreach (var sql in new[]
        {
            "CREATE TABLE IF NOT EXISTS slaps_schema (version INTEGER NOT NULL)",
            "CREATE TABLE IF NOT EXISTS slaps_clients (device_id TEXT PRIMARY KEY, display_name TEXT NOT NULL, certificate_sha256 TEXT NOT NULL UNIQUE, platform TEXT NOT NULL, created_utc TEXT NOT NULL, created_by TEXT NOT NULL, deleted_utc TEXT NULL, deleted_by TEXT NULL)",
            "CREATE TABLE IF NOT EXISTS slaps_records (device_id TEXT NOT NULL, rotation_id TEXT NOT NULL, envelope TEXT NOT NULL, received_utc TEXT NOT NULL, received_ticks BIGINT NOT NULL, applied_utc TEXT NULL, PRIMARY KEY (device_id, rotation_id))",
            "CREATE TABLE IF NOT EXISTS slaps_settings (name TEXT PRIMARY KEY, value TEXT NOT NULL)",
            $"CREATE TABLE IF NOT EXISTS slaps_keys (name TEXT PRIMARY KEY, sha256 TEXT NOT NULL, pkcs12 {blob} NOT NULL, created_utc TEXT NOT NULL)",
            $"CREATE TABLE IF NOT EXISTS slaps_packages (token TEXT PRIMARY KEY, device_id TEXT NOT NULL, display_name TEXT NOT NULL, file_name TEXT NOT NULL, platform TEXT NOT NULL, created_utc TEXT NOT NULL, expires_utc TEXT NOT NULL, expires_ticks BIGINT NOT NULL, created_by TEXT NOT NULL, content {blob} NOT NULL)",
            $"CREATE TABLE IF NOT EXISTS slaps_audit (id {identity}, utc TEXT NOT NULL, actor TEXT NOT NULL, action TEXT NOT NULL, device_id TEXT NULL, rotation_id TEXT NULL)"
        })
            using (var command = Command(connection, transaction, sql)) command.ExecuteNonQuery();
        using (var command = Command(connection, transaction, "SELECT version FROM slaps_schema"))
        {
            var current = command.ExecuteScalar();
            if (current == null)
                using (var insert = Command(connection, transaction, "INSERT INTO slaps_schema (version) VALUES (@v)", ("@v", SchemaVersion))) insert.ExecuteNonQuery();
            else if (Convert.ToInt32(current, CultureInfo.InvariantCulture) > SchemaVersion)
                throw new InvalidOperationException("The database was created by a newer SLAPS version.");
        }
        transaction.Commit();
    }

    // ---- Audit and settings ---------------------------------------------------------------------

    public void Audit(string actor, string action, Guid device, Guid rotation)
    {
        using var connection = Open();
        AuditCore(connection, null, actor, action, device, rotation);
    }

    private static void AuditCore(DbConnection connection, DbTransaction transaction, string actor, string action, Guid device, Guid rotation)
    {
        using var command = Command(connection, transaction, "INSERT INTO slaps_audit (utc, actor, action, device_id, rotation_id) VALUES (@u, @a, @x, @d, @r)",
            ("@u", Wire.Now()), ("@a", actor ?? "unknown"), ("@x", action), ("@d", device == Guid.Empty ? null : device.ToString("D")), ("@r", rotation == Guid.Empty ? null : rotation.ToString("D")));
        command.ExecuteNonQuery();
    }

    // Audit page: newest first; filter semantics shared with the IIS portal (AuditFormat), so it is applied while streaming.
    // names: actor -> display name from the sign-in entries ("portal-sign-in-<role>:<name>").
    public List<StandaloneLapsWeb.AuditEntry> AuditEntries(StandaloneLapsWeb.AuditFilter filter, int skip, int take, out bool more, out Dictionary<string, string> names)
    {
        names = new Dictionary<string, string>(StringComparer.Ordinal);
        more = false;
        using var connection = Open();
        using (var signIns = Command(connection, null, "SELECT actor, action FROM slaps_audit WHERE action LIKE 'portal-sign-in-%' ORDER BY id"))
        using (var reader = signIns.ExecuteReader())
            while (reader.Read())
                StandaloneLapsWeb.AuditFormat.CollectName(names, AuditRow(reader.GetString(0), reader.GetString(1), null, null, null, DateTimeOffset.MinValue));
        var result = new List<StandaloneLapsWeb.AuditEntry>();
        using var command = Command(connection, null,
            "SELECT a.utc, a.actor, a.action, a.device_id, a.rotation_id, c.display_name FROM slaps_audit a LEFT JOIN slaps_clients c ON c.device_id = a.device_id ORDER BY a.id DESC");
        using var rows = command.ExecuteReader();
        var matched = 0;
        while (rows.Read())
        {
            if (!DateTimeOffset.TryParse(rows.GetString(0), CultureInfo.InvariantCulture, DateTimeStyles.AssumeUniversal | DateTimeStyles.AdjustToUniversal, out var utc)) continue;
            var entry = AuditRow(rows.GetString(1), rows.GetString(2), Text(rows, 3), Text(rows, 4), Text(rows, 5), utc);
            if (!StandaloneLapsWeb.AuditFormat.Matches(entry, filter, names)) continue;
            if (matched++ < skip) continue;
            if (result.Count == take) { more = true; break; }
            result.Add(entry);
        }
        return result;
    }

    private static StandaloneLapsWeb.AuditEntry AuditRow(string actor, string rawAction, string device, string rotation, string deviceName, DateTimeOffset utc)
    {
        StandaloneLapsWeb.AuditFormat.SplitTarget(rawAction, out var action, out var target);
        return new StandaloneLapsWeb.AuditEntry { Utc = utc, Actor = actor, Action = action, Target = string.IsNullOrEmpty(target) ? null : target, DeviceId = device, RotationId = rotation, DeviceName = deviceName };
    }

    public PortalSettings Settings()
    {
        using var connection = Open();
        using var command = Command(connection, null, "SELECT value FROM slaps_settings WHERE name = 'portal'");
        if (command.ExecuteScalar() is not string json) return new PortalSettings();
        var settings = JsonSerializer.Deserialize<PortalSettings>(json, Wire.Json);
        // Fail closed: a damaged value must not silently trim history to a smaller default.
        if (settings == null || settings.HistoryLimit < ServerOptions.MinHistoryLimit || settings.HistoryLimit > ServerOptions.MaxHistoryLimit)
            throw new InvalidDataException("The stored portal settings are invalid.");
        return settings;
    }

    public int HistoryLimit => Settings().HistoryLimit;

    public void SetHistoryLimit(int limit, string actor)
    {
        if (limit < ServerOptions.MinHistoryLimit || limit > ServerOptions.MaxHistoryLimit)
            throw new ArgumentOutOfRangeException(nameof(limit), $"The history limit must be between {ServerOptions.MinHistoryLimit} and {ServerOptions.MaxHistoryLimit}.");
        gate.Wait();
        try
        {
            var previous = HistoryLimit;
            if (previous == limit) return;
            using var connection = Open();
            using var transaction = connection.BeginTransaction();
            var json = JsonSerializer.Serialize(new PortalSettings { HistoryLimit = limit, UpdatedUtc = Wire.Now(), UpdatedBy = actor }, Wire.Json);
            using (var command = Command(connection, transaction, "INSERT INTO slaps_settings (name, value) VALUES ('portal', @v) ON CONFLICT (name) DO UPDATE SET value = excluded.value", ("@v", json)))
                command.ExecuteNonQuery();
            AuditCore(connection, transaction, actor, $"settings-history-limit-{previous}-to-{limit}", Guid.Empty, Guid.Empty);
            if (limit < previous)
                foreach (var client in ClientsCore(connection, transaction).Where(c => !c.Deleted)) PruneCore(connection, transaction, Guid.Parse(client.DeviceId), limit);
            transaction.Commit();
        }
        finally { gate.Release(); }
    }

    // ---- Keys -------------------------------------------------------------------------------------

    public StoredKey Key(string name)
    {
        using var connection = Open();
        using var command = Command(connection, null, "SELECT name, sha256, pkcs12, created_utc FROM slaps_keys WHERE name = @n", ("@n", name));
        using var reader = command.ExecuteReader();
        return reader.Read() ? new StoredKey { Name = reader.GetString(0), Sha256 = reader.GetString(1), Pkcs12 = (byte[])reader.GetValue(2), CreatedUtc = reader.GetString(3) } : null;
    }

    public StoredKey[] Keys(string prefix)
    {
        using var connection = Open();
        using var command = Command(connection, null, "SELECT name, sha256, pkcs12, created_utc FROM slaps_keys ORDER BY created_utc DESC");
        using var reader = command.ExecuteReader();
        var keys = new List<StoredKey>();
        while (reader.Read())
            if (reader.GetString(0).StartsWith(prefix, StringComparison.Ordinal))
                keys.Add(new StoredKey { Name = reader.GetString(0), Sha256 = reader.GetString(1), Pkcs12 = (byte[])reader.GetValue(2), CreatedUtc = reader.GetString(3) });
        return keys.ToArray();
    }

    // Inserts a key once; returns false if the name already exists (another instance created it first).
    public bool AddKey(StoredKey key, string actor)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using (var exists = Command(connection, transaction, "SELECT COUNT(*) FROM slaps_keys WHERE name = @n", ("@n", key.Name)))
            if (Convert.ToInt64(exists.ExecuteScalar(), CultureInfo.InvariantCulture) > 0) return false;
        using (var command = Command(connection, transaction, "INSERT INTO slaps_keys (name, sha256, pkcs12, created_utc) VALUES (@n, @s, @p, @c)",
            ("@n", key.Name), ("@s", key.Sha256), ("@p", key.Pkcs12), ("@c", key.CreatedUtc ?? Wire.Now()))) command.ExecuteNonQuery();
        AuditCore(connection, transaction, actor, "key-created-" + key.Name, Guid.Empty, Guid.Empty);
        transaction.Commit();
        return true;
    }

    public void ReplaceKey(StoredKey key, string actor)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using (var command = Command(connection, transaction, "INSERT INTO slaps_keys (name, sha256, pkcs12, created_utc) VALUES (@n, @s, @p, @c) ON CONFLICT (name) DO UPDATE SET sha256 = excluded.sha256, pkcs12 = excluded.pkcs12, created_utc = excluded.created_utc",
            ("@n", key.Name), ("@s", key.Sha256), ("@p", key.Pkcs12), ("@c", key.CreatedUtc ?? Wire.Now()))) command.ExecuteNonQuery();
        AuditCore(connection, transaction, actor, "key-replaced-" + key.Name, Guid.Empty, Guid.Empty);
        transaction.Commit();
    }

    public void RemoveKey(string name, string actor)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using (var command = Command(connection, transaction, "DELETE FROM slaps_keys WHERE name = @n", ("@n", name))) command.ExecuteNonQuery();
        AuditCore(connection, transaction, actor, "key-removed-" + name, Guid.Empty, Guid.Empty);
        transaction.Commit();
    }

    // Named JSON documents in slaps_settings (e.g. the Entra setup state); "portal" stays reserved for PortalSettings.
    public string GetDocument(string name)
    {
        using var connection = Open();
        using var command = Command(connection, null, "SELECT value FROM slaps_settings WHERE name = @n", ("@n", name));
        return command.ExecuteScalar() as string;
    }

    public void SetDocument(string name, string json)
    {
        if (name == "portal") throw new ArgumentException("Reserved setting name.", nameof(name));
        using var connection = Open();
        using var command = Command(connection, null, "INSERT INTO slaps_settings (name, value) VALUES (@n, @v) ON CONFLICT (name) DO UPDATE SET value = excluded.value", ("@n", name), ("@v", json));
        command.ExecuteNonQuery();
    }

    // ---- Clients ----------------------------------------------------------------------------------

    public AgentClient[] Clients()
    {
        using var connection = Open();
        return ClientsCore(connection, null);
    }

    private static AgentClient[] ClientsCore(DbConnection connection, DbTransaction transaction)
    {
        using var command = Command(connection, transaction, "SELECT device_id, display_name, certificate_sha256, platform, created_utc, created_by, deleted_utc, deleted_by FROM slaps_clients");
        using var reader = command.ExecuteReader();
        var clients = new List<AgentClient>();
        while (reader.Read())
            clients.Add(new AgentClient
            {
                DeviceId = reader.GetString(0), DisplayName = reader.GetString(1), CertificateSha256 = reader.GetString(2), Platform = reader.GetString(3),
                CreatedUtc = reader.GetString(4), CreatedBy = reader.GetString(5), DeletedUtc = Text(reader, 6), DeletedBy = Text(reader, 7)
            });
        return clients.ToArray();
    }

    public AgentClient Client(Guid device) => Clients().FirstOrDefault(c => c.DeviceId == device.ToString("D"));

    public AgentClient ClientByCertificate(string sha256)
    {
        using var connection = Open();
        using var command = Command(connection, null, "SELECT device_id FROM slaps_clients WHERE certificate_sha256 = @s", ("@s", sha256.ToUpperInvariant()));
        return command.ExecuteScalar() is string device ? Client(Guid.Parse(device)) : null;
    }

    // Registers a new agent or replaces the certificate pin of an existing one (rekey revokes the old certificate immediately).
    public void RegisterClient(AgentClient client, bool replace, string actor)
    {
        if (client == null || !Guid.TryParseExact(client.DeviceId, "D", out var device) || device == Guid.Empty || !Wire.IsHex64(client.CertificateSha256))
            throw new ArgumentException("Invalid agent registration.");
        gate.Wait();
        try
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction();
            var existing = ClientsCore(connection, transaction);
            var current = existing.FirstOrDefault(c => c.DeviceId == client.DeviceId);
            if (replace)
            {
                if (current == null) throw new InvalidOperationException("The device is not registered.");
                if (current.Deleted) throw new InvalidOperationException("Restore the device before issuing a new certificate.");
            }
            else
            {
                if (current != null) throw new InvalidOperationException("The device ID is already registered.");
                if (existing.Any(c => !c.Deleted && string.Equals(c.DisplayName, client.DisplayName, StringComparison.OrdinalIgnoreCase)))
                    throw new ArgumentException("An active device with this name already exists.");
            }
            if (existing.Any(c => string.Equals(c.CertificateSha256, client.CertificateSha256, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("The certificate is already registered.");
            var sql = replace
                ? "UPDATE slaps_clients SET certificate_sha256 = @s, platform = @p WHERE device_id = @d"
                : "INSERT INTO slaps_clients (device_id, display_name, certificate_sha256, platform, created_utc, created_by) VALUES (@d, @n, @s, @p, @c, @b)";
            using (var command = Command(connection, transaction, sql, ("@d", client.DeviceId), ("@n", client.DisplayName), ("@s", client.CertificateSha256.ToUpperInvariant()),
                ("@p", client.Platform ?? "windows"), ("@c", client.CreatedUtc ?? Wire.Now()), ("@b", client.CreatedBy ?? actor))) command.ExecuteNonQuery();
            AuditCore(connection, transaction, actor, replace ? "client-certificate-replaced" : "client-added", device, Guid.Empty);
            transaction.Commit();
        }
        finally { gate.Release(); }
    }

    public bool SetDeleted(Guid device, bool deleted, string actor)
    {
        gate.Wait();
        try
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction();
            var client = ClientsCore(connection, transaction).FirstOrDefault(c => c.DeviceId == device.ToString("D"));
            if (client == null || client.Deleted == deleted) return false;
            if (!deleted && ClientsCore(connection, transaction).Any(c => !c.Deleted && c.DeviceId != client.DeviceId && string.Equals(c.DisplayName, client.DisplayName, StringComparison.OrdinalIgnoreCase)))
                throw new InvalidOperationException("An active device with the same name exists. Delete it first.");
            if (deleted) PruneCore(connection, transaction, device, HistoryLimitCore(connection, transaction));
            using (var command = Command(connection, transaction, "UPDATE slaps_clients SET deleted_utc = @u, deleted_by = @b WHERE device_id = @d",
                ("@u", deleted ? Wire.Now() : null), ("@b", deleted ? actor : null), ("@d", device.ToString("D")))) command.ExecuteNonQuery();
            AuditCore(connection, transaction, actor, deleted ? "device-delete" : "device-restore", device, Guid.Empty);
            if (!deleted) PruneCore(connection, transaction, device, HistoryLimitCore(connection, transaction));
            transaction.Commit();
            return true;
        }
        finally { gate.Release(); }
    }

    private static int HistoryLimitCore(DbConnection connection, DbTransaction transaction)
    {
        using var command = Command(connection, transaction, "SELECT value FROM slaps_settings WHERE name = 'portal'");
        return command.ExecuteScalar() is string json ? JsonSerializer.Deserialize<PortalSettings>(json, Wire.Json).HistoryLimit : ServerOptions.DefaultHistoryLimit;
    }

    // ---- Records ----------------------------------------------------------------------------------

    private static StoredRecord[] RecordsCore(DbConnection connection, DbTransaction transaction, Guid device)
    {
        using var command = Command(connection, transaction, "SELECT envelope, received_utc, applied_utc, rotation_id FROM slaps_records WHERE device_id = @d ORDER BY received_ticks DESC, rotation_id",
            ("@d", device.ToString("D")));
        using var reader = command.ExecuteReader();
        var records = new List<StoredRecord>();
        while (reader.Read())
        {
            var envelope = JsonSerializer.Deserialize<Envelope>(reader.GetString(0), Wire.Json);
            if (!Wire.Valid(envelope, device, Guid.Parse(reader.GetString(3)))) throw new InvalidDataException("Invalid stored record.");
            records.Add(new StoredRecord { Envelope = envelope, ReceivedUtc = reader.GetString(1), AppliedUtc = Text(reader, 2) });
        }
        return records.ToArray();
    }

    public StoredRecord Get(Guid device, Guid rotation)
    {
        using var connection = Open();
        if (IsDeletedCore(connection, null, device)) return null;
        return RecordsCore(connection, null, device).FirstOrDefault(r => r.Envelope.rotationId == rotation);
    }

    private static bool IsDeletedCore(DbConnection connection, DbTransaction transaction, Guid device)
    {
        using var command = Command(connection, transaction, "SELECT deleted_utc FROM slaps_clients WHERE device_id = @d", ("@d", device.ToString("D")));
        return command.ExecuteScalar() is string;
    }

    // Stores a new envelope; an identical retry succeeds, different content for an existing rotation ID fails (409).
    public bool Put(Guid device, Guid rotation, Envelope envelope)
    {
        gate.Wait();
        try
        {
            using var connection = Open();
            using var transaction = connection.BeginTransaction();
            if (IsDeletedCore(connection, transaction, device)) throw new UnauthorizedAccessException("Device is deleted.");
            var stored = RecordsCore(connection, transaction, device).FirstOrDefault(r => r.Envelope.rotationId == rotation);
            var limit = HistoryLimitCore(connection, transaction);
            if (stored != null)
            {
                PruneCore(connection, transaction, device, limit);
                transaction.Commit();
                return Wire.SameEnvelope(stored.Envelope, envelope);
            }
            var now = DateTimeOffset.UtcNow;
            using (var command = Command(connection, transaction, "INSERT INTO slaps_records (device_id, rotation_id, envelope, received_utc, received_ticks) VALUES (@d, @r, @e, @u, @t)",
                ("@d", device.ToString("D")), ("@r", rotation.ToString("D")), ("@e", JsonSerializer.Serialize(envelope, Wire.Json)), ("@u", now.ToString("O", CultureInfo.InvariantCulture)), ("@t", now.UtcTicks)))
                command.ExecuteNonQuery();
            PruneCore(connection, transaction, device, limit);
            transaction.Commit();
            return true;
        }
        finally { gate.Release(); }
    }

    public bool Applied(Guid device, Guid rotation)
    {
        gate.Wait();
        try
        {
            using var connection = Open();
            if (IsDeletedCore(connection, null, device)) return false;
            using var command = Command(connection, null, "UPDATE slaps_records SET applied_utc = COALESCE(applied_utc, @u) WHERE device_id = @d AND rotation_id = @r",
                ("@u", Wire.Now()), ("@d", device.ToString("D")), ("@r", rotation.ToString("D")));
            return command.ExecuteNonQuery() > 0;
        }
        finally { gate.Release(); }
    }

    public HistoryEntry[] History(Guid device, int skip, int take)
    {
        using var connection = Open();
        if (IsDeletedCore(connection, null, device)) return Array.Empty<HistoryEntry>();
        var limit = HistoryLimitCore(connection, null);
        return RecordsCore(connection, null, device).Take(limit).Skip(Math.Max(0, skip)).Take(Math.Min(limit, Math.Max(0, take)))
            .Select(r => new HistoryEntry { rotationId = r.Envelope.rotationId, createdUtc = r.Envelope.createdUtc, receivedUtc = r.ReceivedUtc, appliedReportedUtc = r.AppliedUtc }).ToArray();
    }

    // Keeps the newest versions plus the most recent version reported as applied (same rule as the IIS vault).
    private static void PruneCore(DbConnection connection, DbTransaction transaction, Guid device, int limit)
    {
        var records = RecordsCore(connection, transaction, device);
        if (records.Length <= limit) return;
        var keep = records.Take(limit).ToList();
        var confirmed = records.FirstOrDefault(r => r.AppliedUtc != null);
        if (confirmed != null && !keep.Contains(confirmed)) { keep.RemoveAt(keep.Count - 1); keep.Add(confirmed); }
        AuditCore(connection, transaction, "system:retention", "trim-history-to-" + limit, device, Guid.Empty);
        foreach (var record in records.Except(keep))
            using (var command = Command(connection, transaction, "DELETE FROM slaps_records WHERE device_id = @d AND rotation_id = @r",
                ("@d", device.ToString("D")), ("@r", record.Envelope.rotationId.ToString("D")))) command.ExecuteNonQuery();
    }

    public DeviceSummary[] Devices(bool deleted, string query)
    {
        query = (query ?? "").Trim();
        using var connection = Open();
        var limit = HistoryLimitCore(connection, null);
        return ClientsCore(connection, null).Where(c => c.Deleted == deleted)
            .Where(c => query.Length == 0 || c.DisplayName.Contains(query, StringComparison.OrdinalIgnoreCase) || c.DeviceId.Contains(query, StringComparison.OrdinalIgnoreCase))
            .Select(c =>
            {
                var history = RecordsCore(connection, null, Guid.Parse(c.DeviceId)).Take(limit).ToArray();
                return new DeviceSummary
                {
                    DeviceId = c.DeviceId, Name = c.DisplayName, CertificateSha256 = c.CertificateSha256, Platform = c.Platform, Deleted = c.Deleted, Versions = history.Length,
                    LastBackupUtc = history.FirstOrDefault()?.ReceivedUtc, LastAppliedUtc = history.FirstOrDefault(r => r.AppliedUtc != null)?.AppliedUtc,
                    Unconfirmed = history.Length > 0 && history[0].AppliedUtc == null
                };
            })
            .OrderBy(d => d.Name, StringComparer.OrdinalIgnoreCase).ToArray();
    }

    // ---- Client packages (24 h downloads) -------------------------------------------------------

    public void StorePackage(PackageInfo info, byte[] content)
    {
        using var connection = Open();
        using (var cleanup = Command(connection, null, "DELETE FROM slaps_packages WHERE expires_ticks <= @t", ("@t", DateTimeOffset.UtcNow.UtcTicks))) cleanup.ExecuteNonQuery();
        using var command = Command(connection, null, "INSERT INTO slaps_packages (token, device_id, display_name, file_name, platform, created_utc, expires_utc, expires_ticks, created_by, content) VALUES (@k, @d, @n, @f, @p, @c, @e, @t, @b, @z)",
            ("@k", info.Token), ("@d", info.DeviceId), ("@n", info.DisplayName), ("@f", info.FileName), ("@p", info.Platform), ("@c", info.CreatedUtc), ("@e", info.ExpiresUtc),
            ("@t", Wire.Timestamp(info.ExpiresUtc).UtcTicks), ("@b", info.CreatedBy), ("@z", content));
        command.ExecuteNonQuery();
    }

    public (PackageInfo Info, byte[] Content) Package(string token)
    {
        using var connection = Open();
        using var command = Command(connection, null, "SELECT device_id, display_name, file_name, platform, created_utc, expires_utc, created_by, content FROM slaps_packages WHERE token = @k AND expires_ticks > @t",
            ("@k", token), ("@t", DateTimeOffset.UtcNow.UtcTicks));
        using var reader = command.ExecuteReader();
        if (!reader.Read()) return (null, null);
        return (new PackageInfo
        {
            Token = token, DeviceId = reader.GetString(0), DisplayName = reader.GetString(1), FileName = reader.GetString(2), Platform = reader.GetString(3),
            CreatedUtc = reader.GetString(4), ExpiresUtc = reader.GetString(5), CreatedBy = reader.GetString(6)
        }, (byte[])reader.GetValue(7));
    }

    public void DeletePackage(string token)
    {
        using var connection = Open();
        using var command = Command(connection, null, "DELETE FROM slaps_packages WHERE token = @k", ("@k", token));
        command.ExecuteNonQuery();
    }

    // ---- Import from an IIS vault (migration) ---------------------------------------------------

    public void ImportRecord(Guid device, Envelope envelope, string receivedUtc, string appliedUtc)
    {
        using var connection = Open();
        using var command = Command(connection, null, "INSERT INTO slaps_records (device_id, rotation_id, envelope, received_utc, received_ticks, applied_utc) VALUES (@d, @r, @e, @u, @t, @a) ON CONFLICT (device_id, rotation_id) DO NOTHING",
            ("@d", device.ToString("D")), ("@r", envelope.rotationId.ToString("D")), ("@e", JsonSerializer.Serialize(envelope, Wire.Json)), ("@u", receivedUtc),
            ("@t", Wire.Timestamp(receivedUtc).UtcTicks), ("@a", appliedUtc));
        command.ExecuteNonQuery();
    }

    public void ImportClient(AgentClient client, string actor)
    {
        using var connection = Open();
        using var transaction = connection.BeginTransaction();
        using (var command = Command(connection, transaction, "INSERT INTO slaps_clients (device_id, display_name, certificate_sha256, platform, created_utc, created_by, deleted_utc, deleted_by) VALUES (@d, @n, @s, @p, @c, @b, @x, @y) ON CONFLICT (device_id) DO NOTHING",
            ("@d", client.DeviceId), ("@n", client.DisplayName), ("@s", client.CertificateSha256.ToUpperInvariant()), ("@p", client.Platform ?? "windows"),
            ("@c", client.CreatedUtc ?? Wire.Now()), ("@b", client.CreatedBy ?? actor), ("@x", client.DeletedUtc), ("@y", client.DeletedBy))) command.ExecuteNonQuery();
        AuditCore(connection, transaction, actor, "client-imported", Guid.Parse(client.DeviceId), Guid.Empty);
        transaction.Commit();
    }

    public void ImportHistoryLimit(int limit, string actor)
    {
        using var connection = Open();
        var json = JsonSerializer.Serialize(new PortalSettings { HistoryLimit = limit, UpdatedUtc = Wire.Now(), UpdatedBy = actor }, Wire.Json);
        using var command = Command(connection, null, "INSERT INTO slaps_settings (name, value) VALUES ('portal', @v) ON CONFLICT (name) DO UPDATE SET value = excluded.value", ("@v", json));
        command.ExecuteNonQuery();
    }
}
