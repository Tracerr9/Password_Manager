using SQLite;
using System;
using System.Collections.Generic;
using System.Text;

namespace Password_Manager.Models
{
    [Table("VaultEntry")]
    public class EntryModel
    {
        [PrimaryKey]
        public string Id { get; set; } = Guid.NewGuid().ToString("N");

        public int SchemaVersion { get; set; } = 1;

        [Indexed]
        public string Title { get; set; } = string.Empty;
        public string Username { get; set; } = string.Empty;
        public string? Url { get; set; }

        public byte[] EncryptedPassword { get; set; } = [];
        public byte[] PasswordNonce { get; set; } = [];
        public byte[] PasswordTag { get; set; } = [];

        public byte[]? EncryptedNotes { get; set; }
        public byte[]? NotesNonce { get; set; }
        public byte[]? NotesTag { get; set; }

        public DateTime CreatedAtUtc { get; set; }
        public DateTime UpdatedAtUtc { get; set; }
    }
}
