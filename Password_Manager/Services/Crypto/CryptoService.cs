using System.Security.Cryptography;
using System.Text;
using Konscious.Security.Cryptography;

namespace Password_Manager.Services.Crypto;

public record KdfParameters(
    int MemoryKb = 65536,
    int Iterations = 3,
    int Parallelism = 4,
    int SchemaVersion = 1
);

public record EncryptedPayload(byte[] Ciphertext, byte[] Nonce, byte[] Tag);

public record VaultInitResult(
    KdfParameters Kdf,
    byte[] Salt,
    byte[] EncryptedDek,
    byte[] DekNonce,
    byte[] DekTag,
    byte[] PlainDek
);

public class CryptoService
{
    private const int SaltSize = 16;
    private const int KeySize = 32;
    private const int NonceSize = 12;
    private const int TagSize = 16;

    public static byte[] BuildVaultDekAad(int schemaVersion)
        => Encoding.UTF8.GetBytes($"v{schemaVersion}:vault:dek");

    public static byte[] BuildEntryAad(int schemaVersion, string entryId, string fieldName)
        => Encoding.UTF8.GetBytes($"v{schemaVersion}:entry:{entryId}:{fieldName}");

    public byte[] DeriveKek(string masterPassword, byte[] salt, KdfParameters kdf)
    {
        byte[] passwordBytes = Encoding.UTF8.GetBytes(masterPassword);
        try
        {
            using var argon2 = new Argon2id(passwordBytes)
            {
                Salt = salt,
                DegreeOfParallelism = kdf.Parallelism,
                MemorySize = kdf.MemoryKb,
                Iterations = kdf.Iterations
            };

            return argon2.GetBytes(KeySize);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(passwordBytes);
        }
    }

    public VaultInitResult InitializeVaultKeys(string masterPassword, KdfParameters? customKdf = null)
    {
        KdfParameters kdf = customKdf ?? new KdfParameters();
        byte[] salt = RandomNumberGenerator.GetBytes(SaltSize);
        byte[] plainDek = RandomNumberGenerator.GetBytes(KeySize);
        byte[] kek = DeriveKek(masterPassword, salt, kdf);

        try
        {
            byte[] dekAad = BuildVaultDekAad(kdf.SchemaVersion);
            EncryptedPayload wrappedDek = EncryptBytes(plainDek, kek, dekAad);

            return new VaultInitResult(
                Kdf: kdf,
                Salt: salt,
                EncryptedDek: wrappedDek.Ciphertext,
                DekNonce: wrappedDek.Nonce,
                DekTag: wrappedDek.Tag,
                PlainDek: plainDek
            );
        }
        catch
        {
            CryptographicOperations.ZeroMemory(plainDek);
            throw;
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    public byte[] UnwrapDek(
        string masterPassword,
        byte[] salt,
        byte[] encryptedDek,
        byte[] dekNonce,
        byte[] dekTag,
        KdfParameters kdf)
    {
        byte[] kek = DeriveKek(masterPassword, salt, kdf);
        try
        {
            byte[] dekAad = BuildVaultDekAad(kdf.SchemaVersion);
            var payload = new EncryptedPayload(encryptedDek, dekNonce, dekTag);
            return DecryptBytes(payload, kek, dekAad);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(kek);
        }
    }

    public EncryptedPayload EncryptString(string plaintext, byte[] dek, ReadOnlySpan<byte> associatedData = default)
    {
        byte[] plainBytes = Encoding.UTF8.GetBytes(plaintext);
        try
        {
            return EncryptBytes(plainBytes, dek, associatedData);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainBytes);
        }
    }

    public string DecryptToString(EncryptedPayload payload, byte[] dek, ReadOnlySpan<byte> associatedData = default)
    {
        byte[] plainBytes = DecryptBytes(payload, dek, associatedData);
        try
        {
            return Encoding.UTF8.GetString(plainBytes);
        }
        finally
        {
            CryptographicOperations.ZeroMemory(plainBytes);
        }
    }

    public EncryptedPayload EncryptBytes(
        ReadOnlySpan<byte> plaintext,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> associatedData = default)
    {
        byte[] nonce = RandomNumberGenerator.GetBytes(NonceSize);
        byte[] ciphertext = new byte[plaintext.Length];
        byte[] tag = new byte[TagSize];

        using var aes = new AesGcm(key, TagSize);
        aes.Encrypt(nonce, plaintext, ciphertext, tag, associatedData);

        return new EncryptedPayload(ciphertext, nonce, tag);
    }

    public byte[] DecryptBytes(
        EncryptedPayload payload,
        ReadOnlySpan<byte> key,
        ReadOnlySpan<byte> associatedData = default)
    {
        byte[] plaintext = new byte[payload.Ciphertext.Length];

        using var aes = new AesGcm(key, TagSize);
        aes.Decrypt(payload.Nonce, payload.Ciphertext, payload.Tag, plaintext, associatedData);

        return plaintext;
    }
}