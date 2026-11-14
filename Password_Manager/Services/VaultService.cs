using Password_Manager.Models;
using Password_Manager.Services.Crypto;
using Password_Manager.Services.Data;
using Password_Manager.Services.Session;
using System.Security.Cryptography;
using System.Text.Json;
using static Password_Manager.Services.Session.SessionService;
namespace Password_Manager.Services
{
    /// <summary>
    /// Data ringkas yang aman ditampilkan di daftar utama (tanpa password).
    /// </summary>
    public record VaultEntrySummary(
        string Id,
        string Title,
        string Username,
        string? Url,
        DateTime UpdatedAtUtc
    );

    /// <summary>
    /// Data rahasia yang hanya didekripsi on-demand saat user membuka detail atau menyalin.
    /// </summary>
    public record EntrySecret(
        string Password,
        string? Notes
    );

    public record SaveEntryRequest(
        string? Id, // Null jika buat baru, terisi jika edit entri lama
        string Title,
        string Username,
        string? Url,
        string Password,
        string? Notes
    );

    public sealed class VaultService
    {
        private const int CurrentSchemaVersion = 1;

        private readonly CryptoService _crypto;
        private readonly VaultRepository _repository;
        private readonly VaultSessionService _session;

        public VaultService(
            CryptoService crypto,
            VaultRepository repository,
            VaultSessionService session)
        {
            _crypto = crypto;
            _repository = repository;
            _session = session;
        }

        // ==========================================
        // 1. SETUP, UNLOCK, & ROTASI MASTER PASSWORD
        // ==========================================

        public Task<bool> IsVaultInitializedAsync()
            => _repository.IsVaultInitializedAsync();

        /// <summary>
        /// Membuat vault baru untuk pertama kali dan langsung membuka sesi (Unlocked).
        /// </summary>
        public async Task SetupVaultAsync(string masterPassword)
        {
            if (string.IsNullOrWhiteSpace(masterPassword))
                throw new ArgumentException("Master password tidak boleh kosong.", nameof(masterPassword));

            if (await _repository.IsVaultInitializedAsync())
                throw new InvalidOperationException("Vault sudah pernah dibuat sebelumnya.");

            VaultInitResult init = _crypto.InitializeVaultKeys(masterPassword);

            var metadata = new MetadataModel
            {
                Id = 1,
                SchemaVersion = init.Kdf.SchemaVersion,
                KdfMemoryKb = init.Kdf.MemoryKb,
                KdfIterations = init.Kdf.Iterations,
                KdfParallelism = init.Kdf.Parallelism,
                Salt = init.Salt,
                EncryptedDek = init.EncryptedDek,
                DekNonce = init.DekNonce,
                DekTag = init.DekTag
            };

            await _repository.SaveMetadataAsync(metadata);

            // Pindahkan kepemilikan PlainDek ke RAM (otomatis membersihkan array sumber)
            _session.Unlock(init.PlainDek);
        }

        /// <summary>
        /// Memverifikasi Master Password. Mengembalikan true jika cocok, false jika salah.
        /// </summary>
        public async Task<bool> TryUnlockAsync(string masterPassword)
        {
            if (string.IsNullOrEmpty(masterPassword))
                return false;

            MetadataModel metadata = await _repository.GetMetadataAsync()
                ?? throw new InvalidOperationException("Vault belum diinisialisasi.");

            var kdf = new KdfParameters(
                MemoryKb: metadata.KdfMemoryKb,
                Iterations: metadata.KdfIterations,
                Parallelism: metadata.KdfParallelism,
                SchemaVersion: metadata.SchemaVersion
            );

            try
            {
                byte[] plainDek = _crypto.UnwrapDek(
                    masterPassword,
                    metadata.Salt,
                    metadata.EncryptedDek,
                    metadata.DekNonce,
                    metadata.DekTag,
                    kdf
                );

                _session.Unlock(plainDek);
                return true;
            }
            catch (AuthenticationTagMismatchException)
            {
                // Master password salah atau metadata telah dimodifikasi
                return false;
            }
        }

        /// <summary>
        /// Mengganti Master Password tanpa perlu mengenkripsi ulang seluruh tabel VaultEntries.
        /// Sekaligus memperbarui parameter KDF ke standar default terbaru.
        /// </summary>
        public async Task<bool> ChangeMasterPasswordAsync(string currentMasterPassword, string newMasterPassword)
        {
            if (string.IsNullOrWhiteSpace(newMasterPassword))
                throw new ArgumentException("Master password baru tidak boleh kosong.", nameof(newMasterPassword));

            MetadataModel metadata = await _repository.GetMetadataAsync()
                ?? throw new InvalidOperationException("Vault belum diinisialisasi.");

            var currentKdf = new KdfParameters(
                MemoryKb: metadata.KdfMemoryKb,
                Iterations: metadata.KdfIterations,
                Parallelism: metadata.KdfParallelism,
                SchemaVersion: metadata.SchemaVersion
            );

            byte[] plainDek;
            try
            {
                plainDek = _crypto.UnwrapDek(
                    currentMasterPassword,
                    metadata.Salt,
                    metadata.EncryptedDek,
                    metadata.DekNonce,
                    metadata.DekTag,
                    currentKdf
                );
            }
            catch (AuthenticationTagMismatchException)
            {
                return false;
            }

            byte[] newSalt = RandomNumberGenerator.GetBytes(16);
            var upgradedKdf = new KdfParameters(SchemaVersion: CurrentSchemaVersion);
            byte[] newKek = _crypto.DeriveKek(newMasterPassword, newSalt, upgradedKdf);

            try
            {
                byte[] dekAad = CryptoService.BuildVaultDekAad(upgradedKdf.SchemaVersion);
                EncryptedPayload rewrappedDek = _crypto.EncryptBytes(plainDek, newKek, dekAad);

                metadata.SchemaVersion = upgradedKdf.SchemaVersion;
                metadata.KdfMemoryKb = upgradedKdf.MemoryKb;
                metadata.KdfIterations = upgradedKdf.Iterations;
                metadata.KdfParallelism = upgradedKdf.Parallelism;
                metadata.Salt = newSalt;
                metadata.EncryptedDek = rewrappedDek.Ciphertext;
                metadata.DekNonce = rewrappedDek.Nonce;
                metadata.DekTag = rewrappedDek.Tag;

                await _repository.SaveMetadataAsync(metadata);
                return true;
            }
            finally
            {
                CryptographicOperations.ZeroMemory(plainDek);
                CryptographicOperations.ZeroMemory(newKek);
            }
        }

        // ==========================================
        // 2. OPERASI ENTRI KREDENSIAL
        // ==========================================

        /// <summary>
        /// Mengambil semua entri dan hanya mendekripsi bagian Header (Title, Username, Url)
        /// agar bisa dicari/diurutkan di RAM tanpa membuka password-nya.
        /// </summary>
        public async Task<List<VaultEntrySummary>> GetAllSummariesAsync(string? searchTerm = null)
        {
            List<EntryModel> encryptedEntries = await _repository.GetAllEntriesAsync();

            List<VaultEntrySummary> summaries = _session.UseDek(dek =>
            {
                var list = new List<VaultEntrySummary>(encryptedEntries.Count);

                foreach (EntryModel entry in encryptedEntries)
                {
                    byte[] headerAad = CryptoService.BuildEntryAad(entry.SchemaVersion, entry.Id, "header");
                    var headerPayload = new EncryptedPayload(entry.EncryptedHeader, entry.HeaderNonce, entry.HeaderTag);

                    byte[] headerJsonBytes = _crypto.DecryptBytes(headerPayload, dek, headerAad);
                    try
                    {
                        EntryHeaderData header = JsonSerializer.Deserialize<EntryHeaderData>(headerJsonBytes)
                            ?? new EntryHeaderData("(Tanpa Judul)", string.Empty, null);

                        list.Add(new VaultEntrySummary(
                            Id: entry.Id,
                            Title: header.Title,
                            Username: header.Username,
                            Url: header.Url,
                            UpdatedAtUtc: entry.UpdatedAtUtc
                        ));
                    }
                    finally
                    {
                        CryptographicOperations.ZeroMemory(headerJsonBytes);
                    }
                }

                return list;
            });

            IEnumerable<VaultEntrySummary> query = summaries;

            if (!string.IsNullOrWhiteSpace(searchTerm))
            {
                string term = searchTerm.Trim();
                query = query.Where(s =>
                    s.Title.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                    s.Username.Contains(term, StringComparison.OrdinalIgnoreCase) ||
                    (s.Url is not null && s.Url.Contains(term, StringComparison.OrdinalIgnoreCase)));
            }

            return query.OrderBy(s => s.Title, StringComparer.OrdinalIgnoreCase).ToList();
        }

        /// <summary>
        /// Mendekripsi password dan catatan hanya untuk 1 entri yang diminta (On-Demand).
        /// </summary>
        public async Task<EntrySecret> GetEntrySecretAsync(string entryId)
        {
            EntryModel entry = await _repository.GetEntryByIdAsync(entryId)
                ?? throw new KeyNotFoundException("Entri tidak ditemukan.");

            return _session.UseDek(dek =>
            {
                byte[] pwAad = CryptoService.BuildEntryAad(entry.SchemaVersion, entry.Id, "password");
                var pwPayload = new EncryptedPayload(entry.EncryptedPassword, entry.PasswordNonce, entry.PasswordTag);
                string password = _crypto.DecryptToString(pwPayload, dek, pwAad);

                string? notes = null;
                if (entry.EncryptedNotes is { Length: > 0 } && entry.NotesNonce is not null && entry.NotesTag is not null)
                {
                    byte[] notesAad = CryptoService.BuildEntryAad(entry.SchemaVersion, entry.Id, "notes");
                    var notesPayload = new EncryptedPayload(entry.EncryptedNotes, entry.NotesNonce, entry.NotesTag);
                    notes = _crypto.DecryptToString(notesPayload, dek, notesAad);
                }

                return new EntrySecret(password, notes);
            });
        }

        /// <summary>
        /// Menyimpan entri baru atau memperbarui entri lama dengan Nonce baru dan AAD terikat ID.
        /// </summary>
        public async Task SaveEntryAsync(SaveEntryRequest request)
        {
            EntryModel? existing = string.IsNullOrWhiteSpace(request.Id)
                ? null
                : await _repository.GetEntryByIdAsync(request.Id);

            var entry = existing ?? new EntryModel
            {
                Id = Guid.NewGuid().ToString("N"),
                SchemaVersion = CurrentSchemaVersion
            };

            // Pastikan versi skema ikut ter-update saat disimpan ulang
            entry.SchemaVersion = CurrentSchemaVersion;

            _session.UseDek(dek =>
            {
                // 1. Enkripsi Header (Title, Username, Url)
                var headerObj = new EntryHeaderData(request.Title.Trim(), request.Username.Trim(), request.Url?.Trim());
                byte[] headerBytes = JsonSerializer.SerializeToUtf8Bytes(headerObj);
                try
                {
                    byte[] headerAad = CryptoService.BuildEntryAad(entry.SchemaVersion, entry.Id, "header");
                    EncryptedPayload encryptedHeader = _crypto.EncryptBytes(headerBytes, dek, headerAad);

                    entry.EncryptedHeader = encryptedHeader.Ciphertext;
                    entry.HeaderNonce = encryptedHeader.Nonce;
                    entry.HeaderTag = encryptedHeader.Tag;
                }
                finally
                {
                    CryptographicOperations.ZeroMemory(headerBytes);
                }

                // 2. Enkripsi Password (selalu membuat Nonce 12-byte baru)
                byte[] pwAad = CryptoService.BuildEntryAad(entry.SchemaVersion, entry.Id, "password");
                EncryptedPayload encryptedPw = _crypto.EncryptString(request.Password, dek, pwAad);

                entry.EncryptedPassword = encryptedPw.Ciphertext;
                entry.PasswordNonce = encryptedPw.Nonce;
                entry.PasswordTag = encryptedPw.Tag;

                // 3. Enkripsi Notes (opsional)
                if (!string.IsNullOrEmpty(request.Notes))
                {
                    byte[] notesAad = CryptoService.BuildEntryAad(entry.SchemaVersion, entry.Id, "notes");
                    EncryptedPayload encryptedNotes = _crypto.EncryptString(request.Notes, dek, notesAad);

                    entry.EncryptedNotes = encryptedNotes.Ciphertext;
                    entry.NotesNonce = encryptedNotes.Nonce;
                    entry.NotesTag = encryptedNotes.Tag;
                }
                else
                {
                    entry.EncryptedNotes = null;
                    entry.NotesNonce = null;
                    entry.NotesTag = null;
                }

                return true;
            });

            await _repository.SaveEntryAsync(entry);
        }

        public async Task DeleteEntryAsync(string entryId)
        {
            if (!_session.IsUnlocked)
                throw new UnauthorizedAccessException("Vault dalam keadaan terkunci.");

            await _repository.DeleteEntryAsync(entryId);
        }
    }
}

