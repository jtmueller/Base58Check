using System;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;

namespace Base58Check
{
    /// <summary>
    /// Base58Check Encoding / Decoding (Bitcoin-style)
    /// </summary>
    /// <remarks>
    /// See here for more details: https://en.bitcoin.it/wiki/Base58Check_encoding
    /// </remarks>
    public static class Base58CheckEncoding
    {
        private const int CHECK_SUM_SIZE = 4;
        private const string DIGITS = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";

        /// <summary>
        /// Encodes data with a 4-byte checksum
        /// </summary>
        /// <param name="data">Data to be encoded</param>
        /// <returns></returns>
        public static string Encode(byte[] data)
        {
            return EncodePlain(AddCheckSum(data));
        }

        /// <summary>
        /// Encodes data in plain Base58, without any checksum.
        /// </summary>
        /// <param name="data">The data to be encoded</param>
        /// <returns></returns>
        public static string EncodePlain(byte[] data)
        {
            // Decode byte[] to BigInteger
            var intData = data.Aggregate<byte, BigInteger>(0, (current, t) => current * 256 + t);

            // Encode BigInteger to Base58 string
            string result = string.Empty;
            while (intData > 0)
            {
                int remainder = (int)(intData % 58);
                intData /= 58;
                result = DIGITS[remainder] + result;
            }

            // Append `1` for each leading 0 byte
            for (int i = 0; i < data.Length && data[i] == 0; i++)
            {
                result = '1' + result;
            }

            return result;
        }

        /// <summary>
        /// Decodes data in Base58Check format (with 4 byte checksum)
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
        public static byte[] Decode(string data)
        {
            byte[] dataWithCheckSum = DecodePlain(data);
            byte[]? dataWithoutCheckSum = VerifyAndRemoveCheckSum(dataWithCheckSum);

            if (dataWithoutCheckSum == null)
            {
                throw new FormatException("Base58 checksum is invalid");
            }

            return dataWithoutCheckSum;
        }

        /// <summary>
        /// Decodes data in plain Base58, without any checksum.
        /// </summary>
        /// <param name="data">Data to be decoded</param>
        /// <returns>Returns decoded data if valid; throws FormatException if invalid</returns>
        public static byte[] DecodePlain(string data)
        {
            // Decode Base58 string to BigInteger 
            BigInteger intData = 0;
            for (int i = 0; i < data.Length; i++)
            {
                int digit = DIGITS.IndexOf(data[i]); //Slow

                if (digit < 0)
                {
                    throw new FormatException(string.Format("Invalid Base58 character `{0}` at position {1}", data[i], i));
                }

                intData = intData * 58 + digit;
            }

            // Encode BigInteger to byte[]
            // Leading zero bytes get encoded as leading `1` characters
            int leadingZeroCount = data.TakeWhile(c => c == '1').Count();
            var leadingZeros = Enumerable.Repeat((byte)0, leadingZeroCount);
            var bytesWithoutLeadingZeros =
              intData.ToByteArray()
              .Reverse()// to big endian
              .SkipWhile(b => b == 0);//strip sign byte
            byte[] result = leadingZeros.Concat(bytesWithoutLeadingZeros).ToArray();

            return result;
        }

        private static byte[] AddCheckSum(byte[] data)
        {
            byte[] checkSum = GetCheckSum(data);
            byte[] dataWithCheckSum = ArrayHelpers.ConcatArrays(data, checkSum);

            return dataWithCheckSum;
        }

        //Returns null if the checksum is invalid
        private static byte[]? VerifyAndRemoveCheckSum(byte[] data)
        {
            byte[] result = ArrayHelpers.SubArray(data, 0, data.Length - CHECK_SUM_SIZE);
            byte[] givenCheckSum = ArrayHelpers.SubArray(data, data.Length - CHECK_SUM_SIZE);
            byte[] correctCheckSum = GetCheckSum(result);

            return givenCheckSum.SequenceEqual(correctCheckSum) ? result : null;
        }

        private static byte[] GetCheckSum(byte[] data)
        {
            SHA256 sha256 = new SHA256Managed();
            byte[] hash1 = sha256.ComputeHash(data);
            byte[] hash2 = sha256.ComputeHash(hash1);

            byte[] result = new byte[CHECK_SUM_SIZE];
            Buffer.BlockCopy(hash2, 0, result, 0, result.Length);

            return result;
        }
    }
}
