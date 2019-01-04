using System;
using System.Buffers;
using System.Collections.Generic;
using System.Diagnostics.Contracts;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security;
using System.Runtime.InteropServices;
using System.Security.Cryptography;
using System.Text;
using System.Threading;
using Microsoft.AspNetCore.Cryptography.KeyDerivation;

namespace Hutch
{
    // ReSharper disable IdentifierTypo
    internal static class Program
    {
        private static string LookupTable = "17Grb8fVyeD5&mUnYWtcqzdTK4LgBJA3Xx%MpR!hsiPvaSZ9NQCH=F$oj^Ekw6u_2";

        private static void Main(string[] args)
        {
            Console.WriteLine("Hutch - Stateless Password Generator v1.0");
            
            var pwdHolder = new SecureString();

            Console.Write("Enter Website >");
            var website = Console.ReadLine();

            if (!Uri.TryCreate(website, UriKind.Absolute, out var websiteUri))
                throw new InvalidProgramException("Invalid Url.");


            Console.Write("Enter Account (Case Sensitive!) >");

            var account = Console.ReadLine();
            if (account == null)
                throw new InvalidProgramException("Account name must not be empty.");

            Console.Write("Enter Master Password >");

            do
            {
                var key = Console.ReadKey(true);
                
                if (key.Key != ConsoleKey.Backspace && key.Key != ConsoleKey.Enter)
                {
                    pwdHolder.AppendChar(key.KeyChar);
                    Console.Write("*");
                }
                else
                {
                    if (key.Key == ConsoleKey.Backspace && pwdHolder.Length > 0)
                    {
                        pwdHolder.RemoveAt(pwdHolder.Length - 1);
                        Console.Write("\b \b");
                    }
                    else if (key.Key == ConsoleKey.Enter)
                    {
                        break;
                    }
                }
            } while (true);

            var privatePool = ArrayPool<byte>.Create();
            var hashBytes = privatePool.Rent(64);

            var saltBytes = privatePool.Rent(128);
            var saltHashedBytes = privatePool.Rent(64);

            try
            {
                HashSecureString(pwdHolder, ref hashBytes);

                var pwdLtScramble = Scramble(ref hashBytes, LookupTable.ToCharArray()).ToCharArray();
                
                var wbPlain = Encoding.UTF8.GetBytes(websiteUri.DnsSafeHost.ToLowerInvariant());
                var acPlain = Encoding.UTF8.GetBytes(account);

                var websiteStream = Encoding.UTF8.GetBytes(Scramble(ref wbPlain, pwdLtScramble));
                var accountStream  = Encoding.UTF8.GetBytes(Scramble(ref acPlain, pwdLtScramble));
                 
                using (var hasher = SHA512.Create())
                {
                    Buffer.BlockCopy(hasher.ComputeHash(websiteStream), 0, saltBytes, 0, 64);
                    Buffer.BlockCopy(hasher.ComputeHash(accountStream), 0, saltBytes, 64, 64);
                    Buffer.BlockCopy(hasher.ComputeHash(saltBytes), 0, saltHashedBytes, 0, 64);
                }

                var scrambledPwd = Scramble(ref hashBytes, pwdLtScramble);

                var derivedPass = KeyDerivation.Pbkdf2(
                    password: scrambledPwd,
                    salt: saltBytes,
                    prf: KeyDerivationPrf.HMACSHA512,
                    iterationCount: 500_000,
                    numBytesRequested: 48);

                var generatedPassword = Scramble(ref derivedPass, pwdLtScramble);
                Console.WriteLine();

                var oldFg = Console.ForegroundColor;
                var oldBg = Console.BackgroundColor;

                Console.Write($"Generated Password for the site \"{websiteUri.DnsSafeHost}\" with account \"{account}\" is : ");

                Console.BackgroundColor = ConsoleColor.White;
                Console.ForegroundColor = ConsoleColor.Red;

                Console.WriteLine(generatedPassword);

                Console.BackgroundColor = oldBg;
                Console.ForegroundColor = oldFg;

            }
            finally
            {
                privatePool.Return(saltHashedBytes, true);
                privatePool.Return(hashBytes, true);
                privatePool.Return(saltBytes, true);
            }

            privatePool.Return(saltHashedBytes, true);
            privatePool.Return(hashBytes, true);
            privatePool.Return(saltBytes, true);
        }


        private static string Scramble(ref byte[] data, IReadOnlyList<char> lt)
        {
            BigInteger intData = 0;

            intData = data.Aggregate(intData, (current, t) => current * 256 + t);

            // Encode BigInteger to Base58 string
            var result = "";
            while (intData > 0)
            {
                var remainder = (int)(intData % lt.Count);
                intData /= lt.Count;
                result = lt[remainder] + result;
            }

            // Append `1` for each leading 0 byte
            for (var i = 0; i < data.Length && data[i] == 0; i++)
            {
                result = '1' + result;
            }

            intData = 0;
            return result;
        }

        private static void HashSecureString(SecureString input, ref byte[] outbuffer)
        {
            var pointer = Marshal.SecureStringToBSTR(input);
            var length = Marshal.ReadInt32(pointer, -4);
            var bytes = new byte[length];
            var bytesPin = GCHandle.Alloc(bytes, GCHandleType.Pinned);
            try
            {
                Marshal.Copy(pointer, bytes, 0, length);
                Marshal.ZeroFreeBSTR(pointer);
                var counter = 0;
                using (var hasher = SHA512.Create())
                    foreach (var hashbyte in hasher.ComputeHash(bytes))
                        outbuffer[counter++] = hashbyte;
            }
            finally
            {
                for (var i = 0; i < bytes.Length; i++)
                    bytes[i] = 0;

                bytesPin.Free();
            }
        }
    }
}