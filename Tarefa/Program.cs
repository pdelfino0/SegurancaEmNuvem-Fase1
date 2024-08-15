using System.Numerics;
using System.Security.Cryptography;
using System.Text;

BigInteger GenerateRandomBigInteger(int digits, BigInteger maxValue)
{
    BigInteger minValue = BigInteger.Pow(10, digits - 1);
    BigInteger result;

    do
    {
        byte[] bytes = new byte[digits / 2 + 1];
        RandomNumberGenerator.Fill(bytes);
        result = new BigInteger(bytes);
        result = BigInteger.Abs(result);
    } while (result < minValue || result >= maxValue);

    return result;
}

string getFirstNBytesSha256(BigInteger key, int nBytes)
{
    using SHA256 SHA256 = SHA256.Create();
    string vString = key.ToString();
    byte[] vBytes = Encoding.UTF8.GetBytes(vString);
    byte[] hashBytes = SHA256.ComputeHash(vBytes);

    string hashString = BitConverter.ToString(hashBytes).Replace("-", "");
    return hashString.Substring(0, nBytes * 2);
}

var g = BigInteger.Parse("2");
var p = BigInteger.Parse("1041607122029938459843911326429539139964006065005940226363139");

BigInteger b = GenerateRandomBigInteger(40, p);

var B = BigInteger.ModPow(g, b, p);

Console.WriteLine("B: " + B);
Console.WriteLine("b: " + b);
Console.WriteLine("g: " + g);
Console.WriteLine("p: " + p);

const string A = "105008283869277434967871522668292359874644989537271965222162";

Console.WriteLine("A: " + A);

BigInteger bigIntA = BigInteger.Parse(A);

BigInteger v = BigInteger.ModPow(bigIntA, b, p);

Console.WriteLine("v: " + v);

string k = getFirstNBytesSha256(v, 16);

Console.WriteLine("First 16 bytes of v: " + k);