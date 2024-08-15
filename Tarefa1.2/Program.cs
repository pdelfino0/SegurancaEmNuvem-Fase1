using System.Security.Cryptography;
using System.Text;

byte[] HexStringToByteArray(string hex)
{
    var bytes = new byte[hex.Length / 2];

    for (var i = 0; i < hex.Length; i += 2)
    {
        bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
    }

    return bytes;
}

byte[] ApplyPkcs7Padding(byte[] data, int blockSize)
{
    int paddingLength = blockSize - (data.Length % blockSize);
    byte[] paddedData = new byte[data.Length + paddingLength];
    Array.Copy(data, paddedData, data.Length);
    for (int i = data.Length; i < paddedData.Length; i++)
    {
        paddedData[i] = (byte)paddingLength;
    }

    return paddedData;
}

byte[] RemovePkcs7Padding(byte[] data)
{
    int paddingLength = data[data.Length - 1];
    byte[] unpaddedData = new byte[data.Length - paddingLength];
    Array.Copy(data, unpaddedData, unpaddedData.Length);
    return unpaddedData;
}

byte[] EncryptAesCtr(string clearText, string key, byte[] iv)
{
    var clearBytes = Encoding.UTF8.GetBytes(clearText);
    clearBytes = ApplyPkcs7Padding(clearBytes, 16);

    using var aes = Aes.Create();
    aes.Key = HexStringToByteArray(key);
    aes.IV = iv;
    aes.Mode = CipherMode.ECB;
    aes.Padding = PaddingMode.None;

    using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

    byte[] encryptedBytes = new byte[clearBytes.Length];

    for (int i = 0; i < clearBytes.Length; i += aes.BlockSize / 8)
    {
        byte[] counterBlock = IncrementCounter(iv, i / (aes.BlockSize / 8));
        byte[] encryptedCounterBlock = new byte[aes.BlockSize / 8];
        encryptor.TransformBlock(counterBlock, 0, counterBlock.Length, encryptedCounterBlock, 0);

        int blockSize = Math.Min(aes.BlockSize / 8, clearBytes.Length - i);

        for (int j = 0; j < blockSize; j++)
        {
            encryptedBytes[i + j] = (byte)(clearBytes[i + j] ^ encryptedCounterBlock[j]);
        }
    }

    return encryptedBytes;
}

byte[] DecryptAesCtr(byte[] encryptedBytes, string key, byte[] iv)
{
    using var aes = Aes.Create();
    aes.Key = HexStringToByteArray(key);
    aes.IV = iv;
    aes.Mode = CipherMode.ECB;
    aes.Padding = PaddingMode.None;

    using var encryptor = aes.CreateEncryptor(aes.Key, aes.IV);

    byte[] decryptedBytes = new byte[encryptedBytes.Length];

    for (int i = 0; i < encryptedBytes.Length; i += aes.BlockSize / 8)
    {
        byte[] counterBlock = IncrementCounter(iv, i / (aes.BlockSize / 8));
        byte[] encryptedCounterBlock = new byte[aes.BlockSize / 8];
        encryptor.TransformBlock(counterBlock, 0, counterBlock.Length, encryptedCounterBlock, 0);

        int blockSize = Math.Min(aes.BlockSize / 8, encryptedBytes.Length - i);

        for (int j = 0; j < blockSize; j++)
        {
            decryptedBytes[i + j] = (byte)(encryptedBytes[i + j] ^ encryptedCounterBlock[j]);
        }
    }

    return RemovePkcs7Padding(decryptedBytes);
}

static byte[] IncrementCounter(byte[] counter, int increment)
{
    byte[] newCounter = (byte[])counter.Clone();
    for (int i = newCounter.Length - 1; i >= 0; i--)
    {
        increment += newCounter[i];
        newCounter[i] = (byte)increment;
        increment >>= 8;
    }

    return newCounter;
}

const string textToBeEncrypted = "Pedro Fernandes Delfino";
const string key = "09A281E7B7B9F461C2CB914021E0FAF3";

Console.WriteLine("Mensagem antes de ser criptografada: " + textToBeEncrypted);

var randomCounterIv = RandomNumberGenerator.GetBytes(16);

var encryptedMessage = EncryptAesCtr(textToBeEncrypted, key, randomCounterIv);
Console.WriteLine("Encrypted: " + BitConverter.ToString(encryptedMessage).Replace("-", ""));

var decryptedMessage = DecryptAesCtr(encryptedMessage, key, randomCounterIv);
Console.WriteLine("Mensagem após decriptografia: " + Encoding.UTF8.GetString(decryptedMessage));

Console.WriteLine("IV usado: " + BitConverter.ToString(randomCounterIv).Replace("-", ""));

