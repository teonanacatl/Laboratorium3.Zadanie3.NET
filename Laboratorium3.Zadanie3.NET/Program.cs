using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Laboratorium3.Zadanie3.NET
{
    public static class Program
    {
        private static int _found;
        private static readonly ConcurrentBag<string> Results = new();
        private static readonly Stopwatch Stopwatch = new();

        public static void Main()
        {
            const string cipherTextHex =
                "23c73dde8faedd91413fb5dd1d7e066d70425ed1e058d0e2f7e9e43501824a95446baf28f6ce7ffd3c544f40efb5c80f235de1321214328781a6ea0c0c4c7b74be3968ca1ffb8455";
            var cipherTextBytes = StringToByteArray(cipherTextHex);
            Stopwatch.Start();

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Environment.ProcessorCount
            };

            Parallel.For(0, 256, parallelOptions, i =>
            {
                if (Interlocked.CompareExchange(ref _found, 1, 1) == 1)
                {
                    return;
                }

                var key = new byte[8];
                for (var x = 0; x < 4; x++)
                    key[4 + x] = 5;
                key[0] = (byte)i;

                using var des = DES.Create();
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                for (var j = 0; j <= 255 && Interlocked.CompareExchange(ref _found, 1, 1) != 1; j++)
                {
                    key[1] = (byte)j;

                    for (var k = 0; k <= 255 && Interlocked.CompareExchange(ref _found, 1, 1) != 1; k++)
                    {
                        key[2] = (byte)k;

                        for (var l = 0; l <= 255 && Interlocked.CompareExchange(ref _found, 1, 1) != 1; l++)
                        {
                            key[3] = (byte)l;
                            des.Key = key;

                            var decryptedText = Decrypt(cipherTextBytes, des);
                            if (!string.IsNullOrEmpty(decryptedText) && decryptedText.StartsWith("test"))
                            {
                                if (Interlocked.CompareExchange(ref _found, 1, 0) == 0)
                                {
                                    Results.Add($"Znaleziono klucz: {ByteArrayToString(key)}");
                                    Results.Add($"Tekst jawny: {decryptedText}");
                                }
                                return;
                            }
                        }
                    }
                }
            });

            Stopwatch.Stop();

            if (_found == 1)
            {
                foreach (var result in Results) Console.WriteLine(result);
                Console.WriteLine($"Czas wykonania: {Stopwatch.Elapsed.TotalSeconds} sekund");
            }
            else
            {
                Console.WriteLine("Nie znaleziono klucza.");
            }
        }

        private static string Decrypt(byte[] cipherTextBytes, SymmetricAlgorithm des)
        {
            try
            {
                var decryptor = des.CreateDecryptor(des.Key, des.IV);
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
