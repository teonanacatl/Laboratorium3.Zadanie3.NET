using System.Collections.Concurrent;
using System.Diagnostics;
using System.Security.Cryptography;
using System.Text;

namespace Laboratorium3.Zadanie3.NET
{
    public static class Program
    {
        private static volatile bool _found;
        private static readonly ConcurrentBag<string> Results = new();
        private static readonly object LockObj = new();
        private static Stopwatch _stopwatch = new();

        public static void Main()
        {
            const string cipherTextHex =
                "23c73dde8faedd91413fb5dd1d7e066d70425ed1e058d0e2f7e9e43501824a95446baf28f6ce7ffd3c544f40efb5c80f235de1321214328781a6ea0c0c4c7b74be3968ca1ffb8455";
            var cipherTextBytes = StringToByteArray(cipherTextHex);
            _stopwatch.Start();

            var key = new byte[8];
            for (var i = 0; i < 4; i++)
                key[4 + i] = 5;

            var parallelOptions = new ParallelOptions
            {
                MaxDegreeOfParallelism = Environment.ProcessorCount
            };

            Parallel.For(0, 256, parallelOptions, (i, state) =>
            {
                if (_found)
                {
                    state.Stop();
                    return;
                }

                using var des = DES.Create();
                des.Mode = CipherMode.ECB;
                des.Padding = PaddingMode.PKCS7;

                for (var j = 0; j <= 255 && !_found; j++)
                {
                    for (var k = 0; k <= 255 && !_found; k++)
                    {
                        for (var l = 0; l <= 255 && !_found; l++)
                        {
                            key[0] = (byte)i;
                            key[1] = (byte)j;
                            key[2] = (byte)k;
                            key[3] = (byte)l;
                            des.Key = key;

                            var decryptedText = Decrypt(cipherTextBytes, des);
                            if (!string.IsNullOrEmpty(decryptedText) && decryptedText.StartsWith("test"))
                            {
                                lock (LockObj)
                                {
                                    if (_found) return;
                                    _found = true;
                                    Results.Add($"Znaleziono klucz: {ByteArrayToString(key)}");
                                    Results.Add($"Tekst jawny: {decryptedText}");
                                    state.Stop();
                                }

                                return;
                            }

                            LogProgress(key);
                        }
                    }
                }
            });

            _stopwatch.Stop();

            if (_found)
            {
                foreach (var result in Results) Console.WriteLine(result);
                Console.WriteLine($"Czas wykonania: {_stopwatch.Elapsed.TotalSeconds} sekund");
            }
            else
            {
                Console.WriteLine("Nie znaleziono klucza.");
            }
        }

        private static string Decrypt(byte[] cipherTextBytes, SymmetricAlgorithm des)
        {
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

        private static void LogProgress(byte[] key)
        {
            if (_stopwatch.Elapsed.TotalMinutes >= 1)
            {
                Console.WriteLine(
                    $"Elapsed Time: {_stopwatch.Elapsed.TotalMinutes:F2} minutes, Checking Key: {ByteArrayToString(key)}");
                _stopwatch.Restart();
            }
        }
    }
}