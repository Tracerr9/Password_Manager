using SQLite;

namespace Password_Manager.Models;

/// <summary>
/// Struktur metadata yang diserialisasi ke JSON lalu dienkripsi ke kolom EncryptedHeader.
/// </summary>
public record EntryHeaderData(
    string Title,
    string Username,
    string? Url
);

[Table("VaultEntries")]
public class EntryModel
{
    [PrimaryKey]
    public string Id { get; set; } = Guid.NewGuid().ToString("N");

    public int SchemaVersion { get; set; } = 1;

    // Metadata (Title, Username, Url) kini 100% terenkripsi di disk
    public byte[] EncryptedHeader { get; set; } = [];
    public byte[] HeaderNonce { get; set; } = [];
    public byte[] HeaderTag { get; set; } = [];

    // Kredensial utama (didekripsi on-demand saat dibuka/disalin)
    public byte[] EncryptedPassword { get; set; } = [];
    public byte[] PasswordNonce { get; set; } = [];
    public byte[] PasswordTag { get; set; } = [];

    public byte[]? EncryptedNotes { get; set; }
    public byte[]? NotesNonce { get; set; }
    public byte[]? NotesTag { get; set; }

    public DateTime CreatedAtUtc { get; set; }
    public DateTime UpdatedAtUtc { get; set; }
}