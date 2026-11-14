using SQLite;

namespace Password_Manager.Models
{
    [Table("VaultMetadata")]
    public class MetadataModel
    {
        [PrimaryKey]
        public int Id { get; set; } = 1;

        public int SchemaVersion { get; set; } = 1;
        public int KdfMemoryKb { get; set; }
        public int KdfIterations { get; set; }
        public int KdfParallelism { get; set; }

        public byte[] Salt { get; set; } = [];
        public byte[] EncryptedDek { get; set; } = [];
        public byte[] DekNonce { get; set; } = [];
        public byte[] DekTag { get; set; } = [];

        public DateTime CreatedAtUtc { get; set; }
        public DateTime UpdatedAtUtc { get; set; }
    }
}
