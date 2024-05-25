using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Laboratorium3.Zadanie3.NET
{
    public class Program
    {
        public static void Main()
        {
            const string cipherTextHex = "23c73dde8faedd91413fb5dd1d7e066d70425ed1e058d0e2f7e9e43501824a95446baf28f6ce7ffd3c544f40efb5c80f235de1321214328781a6ea0c0c4c7b74be3968ca1ffb8455";
            var cipherTextBytes = StringToByteArray(cipherTextHex);
            var stopwatch = Stopwatch.StartNew();

            var key = new byte[8];
            for (var i = 0; i < 4; i++) 
                key[4 + i] = 5;

            Parallel.For(0, 256, i =>
            {
                for (var j = 0; j <= 255; j++)
                {
                    for (var k = 0; k <= 255; k++)
                    {
                        for (var l = 0; l <= 255; l++)
                        {
                            key[0] = (byte)i;
                            key[1] = (byte)j;
                            key[2] = (byte)k;
                            key[3] = (byte)l;

                            var decryptedText = Decrypt(cipherTextBytes, key);
                            if (!string.IsNullOrEmpty(decryptedText) && decryptedText.StartsWith("test"))
                            {
                                Console.WriteLine($"Znaleziono klucz: {ByteArrayToString(key)}");
                                Console.WriteLine($"Tekst jawny: {decryptedText}");
                                stopwatch.Stop();
                                Console.WriteLine($"Czas wykonania: {stopwatch.Elapsed.TotalSeconds} sekund");
                                return;
                            }
                        }
                    }
                }
            });

            Console.WriteLine("Nie znaleziono klucza.");
        }

        private static string Decrypt(byte[] cipherTextBytes, byte[] key)
        {
            using var des = new DESCryptoServiceProvider();
            des.Key = key;
            des.Mode = CipherMode.ECB;
            des.Padding = PaddingMode.PKCS7;

            var decryptor = des.CreateDecryptor(des.Key, des.IV);
            try
            {
                var plainTextBytes = decryptor.TransformFinalBlock(cipherTextBytes, 0, cipherTextBytes.Length);
                return Encoding.ASCII.GetString(plainTextBytes);
            }
            catch (CryptographicException)
            {
                return "";
            }
        }

        private static byte[] StringToByteArray(string hex)
        {
            var length = hex.Length;
            var bytes = new byte[length / 2];
            for (var i = 0; i < length; i += 2)
                bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
            return bytes;
        }

        private static string ByteArrayToString(byte[] bytes)
        {
            var hex = new StringBuilder(bytes.Length * 2);
            foreach (var b in bytes)
                hex.Append($"{b:x2}");
            return hex.ToString();
        }
    }
}
