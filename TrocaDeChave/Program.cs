using System.Numerics;
using System.Security.Cryptography;
using System.Text;

const string A = "105008283869277434967871522668292359874644989537271965222162";
const string g = "2";
const string p = "1041607122029938459843911326429539139964006065005940226363139";

const string b = "";


Console.WriteLine("A chave da Alice é: " + A);
Console.WriteLine("O valor de g é: " + g);
Console.WriteLine("O valor de p é: " + p);

var bigIntA = BigInteger.Parse(A);
var bigIntG = BigInteger.Parse(g);
var bigIntP = BigInteger.Parse(p);

var bigIntMiniB = GenerateRandomBigInteger(40, bigIntP);
var bigIntB = BigInteger.ModPow(bigIntG, bigIntMiniB, bigIntP);

var chavePublicaBob = bigIntB;

Console.WriteLine("Para a chave pública de Bob, B, foi gerado o valor: " + chavePublicaBob);

var bigIntV = BigInteger.ModPow(bigIntA, bigIntMiniB, bigIntP);

Console.WriteLine("O valor de v é: " + bigIntV);
Console.WriteLine("O valor da chave é: " + GetFirstNBytesSha256(bigIntV, 16));

Console.WriteLine("Digite uma palavra para cifrar: ");
var palavra = Console.ReadLine();


return;

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

string GetFirstNBytesSha256(BigInteger key, int nBytes)
{
    using SHA256 SHA256 = SHA256.Create();
    string vString = key.ToString();
    byte[] vBytes = Encoding.UTF8.GetBytes(vString);
    byte[] hashBytes = SHA256.ComputeHash(vBytes);
    string hashString = BitConverter.ToString(hashBytes).Replace("-", "");
    return hashString.Substring(0, nBytes * 2);
}