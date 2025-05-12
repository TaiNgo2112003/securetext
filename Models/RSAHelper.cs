using System.Security.Cryptography;
using System.Text;

public static class RSAHelper
{
    private const int DefaultKeySize = 2048;
    private static readonly RSAEncryptionPadding DefaultEncryptionPadding = RSAEncryptionPadding.OaepSHA256;

    // Tạo cặp khóa RSA
    public static (RSAParameters PublicKey, RSAParameters PrivateKey) GenerateKeys(int keySize = DefaultKeySize)
    {
        using var rsa = RSA.Create();
        rsa.KeySize = keySize;
        return (rsa.ExportParameters(false), rsa.ExportParameters(true));
    }

    // Export khóa dưới dạng XML (chỉ dùng cho tương thích)
    public static string ExportToXml(RSAParameters key, bool includePrivateKey)
    {
        ValidateKey(key, includePrivateKey);

        using var rsa = RSA.Create();
        rsa.ImportParameters(key);
        return rsa.ToXmlString(includePrivateKey);
    }
    public static string ExportPublicKeyToPEM(RSAParameters rsaParameters)
    {
        using (var rsa = RSA.Create())
        {
            rsa.ImportParameters(rsaParameters);
            var key = rsa.ExportRSAPublicKey();
            return "-----BEGIN PUBLIC KEY-----\n" + Convert.ToBase64String(key, Base64FormattingOptions.InsertLineBreaks) + "\n-----END PUBLIC KEY-----";
        }
    }

    public static string ExportPrivateKeyToPEM(RSAParameters rsaParameters)
    {
        using (var rsa = RSA.Create())
        {
            rsa.ImportParameters(rsaParameters);
            var key = rsa.ExportRSAPrivateKey();
            return "-----BEGIN PRIVATE KEY-----\n" + Convert.ToBase64String(key, Base64FormattingOptions.InsertLineBreaks) + "\n-----END PRIVATE KEY-----";
        }
    }
    // Import khóa từ XML
    public static RSAParameters ImportFromXml(string xmlString, bool isPrivateKey)
    {
        if (string.IsNullOrWhiteSpace(xmlString))
            throw new ArgumentException("XML string cannot be empty.");

        using var rsa = RSA.Create();
        rsa.FromXmlString(xmlString);
        return rsa.ExportParameters(isPrivateKey);
    }

    // Mã hóa dữ liệu
    public static string Encrypt(string plainText, RSAParameters publicKey)
    {
        if (string.IsNullOrWhiteSpace(plainText))
            throw new ArgumentException("Plain text cannot be empty.");

        ValidateKey(publicKey, false);

        using var rsa = RSA.Create();
        rsa.ImportParameters(publicKey);

        var plainData = Encoding.UTF8.GetBytes(plainText);
        var maxSize = GetMaxDataSize(rsa, DefaultEncryptionPadding);

        if (plainData.Length > maxSize)
            throw new ArgumentException($"Data too large. Maximum is {maxSize} bytes for this key.");

        var encryptedData = rsa.Encrypt(plainData, DefaultEncryptionPadding);
        return Convert.ToBase64String(encryptedData);
    }

    // Giải mã dữ liệu
    public static string Decrypt(string cipherText, RSAParameters privateKey)
    {
        if (string.IsNullOrWhiteSpace(cipherText))
            throw new ArgumentException("Cipher text cannot be empty.");

        ValidateKey(privateKey, true);

        using var rsa = RSA.Create();
        rsa.ImportParameters(privateKey);

        var cipherData = Convert.FromBase64String(cipherText);
        var decryptedData = rsa.Decrypt(cipherData, DefaultEncryptionPadding);

        return Encoding.UTF8.GetString(decryptedData);
    }

    // Tính toán kích thước dữ liệu tối đa có thể mã hóa
    private static int GetMaxDataSize(RSA rsa, RSAEncryptionPadding padding)
    {
        return padding == RSAEncryptionPadding.OaepSHA256 ?
            (rsa.KeySize / 8) - 66 : // OAEP SHA-256
            (rsa.KeySize / 8) - 42;   // OAEP SHA-1
    }

    // Kiểm tra khóa hợp lệ
    private static void ValidateKey(RSAParameters key, bool isPrivateKey)
    {
        if (key.Modulus == null || key.Modulus.Length == 0)
            throw new ArgumentException("Invalid key: Modulus is empty");

        if (isPrivateKey && (key.D == null || key.D.Length == 0))
            throw new ArgumentException("Invalid private key: Exponent is empty");
    }
}