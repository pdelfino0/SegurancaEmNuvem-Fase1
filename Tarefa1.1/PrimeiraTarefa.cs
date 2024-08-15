using System.Security.Cryptography;
using System.Text;

namespace Fase_1___Seguranca_na_nuvem;

public abstract class PrimeiraTarefa()
{
    private static byte[] HexStringToByteArray(string hex)
    {
        var bytes = new byte[hex.Length / 2];

        for (var i = 0; i < hex.Length; i += 2)
        {
            bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
        }

        return bytes;
    }

    private static string DecryptAes(string cipherText, string key, string iv)
    {
        var cipherTextBytes = HexStringToByteArray(cipherText);

        using var aes = Aes.Create();
        aes.Key = HexStringToByteArray(key);
        aes.IV = HexStringToByteArray(iv);
        aes.Mode = CipherMode.CBC;

        using var decryptor = aes.CreateDecryptor(aes.Key, aes.IV);
        using var ms = new MemoryStream(cipherTextBytes);
        using var cs = new CryptoStream(ms, decryptor, CryptoStreamMode.Read);
        using var sr = new StreamReader(cs, Encoding.UTF8);

        return sr.ReadToEnd();
    }

    public static void Main()
    {
        const string hex =
            "EF794476D605765572683CE849FBD4555CE8EC1382019662E277F31B8035E285787C1DA9D2CC5B3441F5CB900C41BA70902A932209C3966B83FB4387ABBC95E0";

        const string key = "240B31B44A27BEC5062B3A74C63271A4";
        const string iv = "C4AB0DF3D808D72AAADBC68206483B18";

        var decryptedMessage = DecryptAes(hex, key, iv);

        Console.WriteLine("Mensagem descriptiveness:" + decryptedMessage);
    }
}