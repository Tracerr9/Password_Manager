using Password_Manager.Models;
using SQLite;

namespace Password_Manager.Services.Data
{
    public class VaultRepository
    {
        private const string DatabaseFilename = "localvault.db3";

        private const SQLiteOpenFlags Flags =
            SQLiteOpenFlags.ReadWrite |
            SQLiteOpenFlags.Create |
            SQLiteOpenFlags.FullMutex;

        private readonly string _databasePath;
        private readonly SemaphoreSlim _initLock = new(1, 1);
        private SQLiteAsyncConnection? _database;
        private bool _disposed;

        public VaultRepository(string? customDatabasePath = null)
        {
            _databasePath = customDatabasePath
                ?? Path.Combine(FileSystem.AppDataDirectory, DatabaseFilename);
        }

        private async Task<SQLiteAsyncConnection> GetDatabaseAsync()
        {
            ObjectDisposedException.ThrowIf(_disposed, this);

            if (_database is not null)
                return _database;

            await _initLock.WaitAsync();
            try
            {
                ObjectDisposedException.ThrowIf(_disposed, this);

                if (_database is not null)
                    return _database;

                var connection = new SQLiteAsyncConnection(_databasePath, Flags);

                int secureDelete = await connection.ExecuteScalarAsync<int>("PRAGMA secure_delete = ON;");
                string journalMode = await connection.ExecuteScalarAsync<string>("PRAGMA journal_mode = DELETE;");
                await connection.ExecuteScalarAsync<int>("PRAGMA synchronous = FULL;");

                if (secureDelete != 1)
                    throw new InvalidOperationException("SQLite gagal mengaktifkan PRAGMA secure_delete.");

                await connection.CreateTableAsync<MetadataModel>();
                await connection.CreateTableAsync<EntryModel>();

                _database = connection;
                return _database;
            }
            finally
            {
                _initLock.Release();
            }
        }
        public async Task<bool> IsVaultInitializedAsync()
        {
            var db = await GetDatabaseAsync();
            int count = await db.Table<MetadataModel>().CountAsync();
            return count > 0;
        }
        public async Task<MetadataModel?> GetMetadataAsync()
        {
            var db = await GetDatabaseAsync();
            return await db.Table<MetadataModel>()
                           .Where(m => m.Id == 1)
                           .FirstOrDefaultAsync();
        }

        public async Task SaveMetadataAsync(MetadataModel metadata)
        {
            var db = await GetDatabaseAsync();
            metadata.Id = 1;
            metadata.UpdatedAtUtc = DateTime.UtcNow;

            if (metadata.CreatedAtUtc == default)
                metadata.CreatedAtUtc = metadata.UpdatedAtUtc;

            await db.InsertOrReplaceAsync(metadata);
        }

        public async Task<List<EntryModel>> GetAllEntriesAsync()
        {
            var db = await GetDatabaseAsync();
            return await db.Table<EntryModel>().ToListAsync();
        }

        public async Task<EntryModel?> GetEntryByIdAsync(string id)
        {
            var db = await GetDatabaseAsync();
            return await db.Table<EntryModel>()
                           .Where(e => e.Id == id)
                           .FirstOrDefaultAsync();
        }

        public async Task SaveEntryAsync(EntryModel entry)
        {
            var db = await GetDatabaseAsync();
            entry.UpdatedAtUtc = DateTime.UtcNow;

            if (entry.CreatedAtUtc == default)
                entry.CreatedAtUtc = entry.UpdatedAtUtc;

            await db.InsertOrReplaceAsync(entry);
        }

        public async Task DeleteEntryAsync(string id)
        {
            var db = await GetDatabaseAsync();
            await db.DeleteAsync<EntryModel>(id);
        }

        /// <summary>
        /// Menutup koneksi SQLite dan melepas file lock (berguna saat lock vault atau backup file .db3).
        /// Koneksi akan otomatis terbuka kembali jika method query dipanggil lagi.
        /// </summary>
        public async Task CloseAsync()
        {
            await _initLock.WaitAsync();
            try
            {
                if (_database is not null)
                {
                    await _database.CloseAsync();
                    _database = null;
                }
            }
            finally
            {
                _initLock.Release();
            }
        }

        public async ValueTask DisposeAsync()
        {
            if (_disposed)
                return;

            await CloseAsync();
            _disposed = true;
            _initLock.Dispose();
        }
    }
}
