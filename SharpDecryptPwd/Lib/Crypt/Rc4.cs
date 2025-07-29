using System;
using System.Text;
using System.Security.Cryptography;
using System.Collections.Generic;
using System.Linq;

namespace SharpDecryptPwd.Lib.Crypt
{
    public static class RC4Crypt
    {
        /// <summary>
        /// Decrypt data using key.
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        public static byte[] Decrypt(byte[] key, byte[] data)
        {
            return EncryptOutput(key, data).ToArray();
        }

        /// <summary>
        /// Init our encryption.
        /// </summary>
        /// <param name="key"></param>
        /// <returns></returns>
        private static byte[] EncryptInitalize(byte[] key)
        {
            byte[] s = Enumerable.Range(0, 256)
              .Select(i => (byte)i)
              .ToArray();

            for (int i = 0, j = 0; i < 256; i++)
            {
                j = (j + key[i % key.Length] + s[i]) & 255;

                Swap(s, i, j);
            }

            return s;
        }

        /// <summary>
        /// Loop
        /// </summary>
        /// <param name="key"></param>
        /// <param name="data"></param>
        /// <returns></returns>
        private static IEnumerable<byte> EncryptOutput(byte[] key, IEnumerable<byte> data)
        {
            byte[] s = EncryptInitalize(key);

            int i = 0;
            int j = 0;

            return data.Select((b) =>
            {
                i = (i + 1) & 255;
                j = (j + s[i]) & 255;

                Swap(s, i, j);

                return (byte)(b ^ s[(s[i] + s[j]) & 255]);
            });
        }

        /// <summary>
        /// Swap byte.
        /// </summary>
        /// <param name="s"></param>
        /// <param name="i"></param>
        /// <param name="j"></param>
        private static void Swap(byte[] s, int i, int j)
        {
            byte c = s[i];

            s[i] = s[j];
            s[j] = c;
        }


        #region RC4
        /// <summary>
        /// Returns the RC4-encrypted string
        /// </summary>
        /// <param name="str">Encrypted characters</param>
        /// <param name="ckey">Key</param>
        public static string EncryptRC4wq(string str, string ckey)
        {
            int[] s = new int[256];
            for (int i = 0; i < 256; i++)
                s[i] = i;

            char[] keys = ckey.ToCharArray();
            int[] key = new int[keys.Length];
            for (int i = 0; i < keys.Length; i++)
                key[i] = keys[i];
            
            char[] datas = str.ToCharArray();
            int[] mingwen = new int[datas.Length];
            for (int i = 0; i < datas.Length; i++)
                mingwen[i] = datas[i];

            // Get a 256-bit array (key) through a loop
            int j = 0;
            int k = 0;
            int length = key.Length;
            int a;
            for (int i = 0; i < 256; i++)
            {
                a = s[i];
                j = (j + a + key[k]);
                if (j >= 256)
                {
                    j = j % 256;
                }
                s[i] = s[j];
                s[j] = a;
                if (++k >= length)
                {
                    k = 0;
                }
            }
            // the ciphertext array is obtained
            int x = 0, y = 0, a2, b, c;
            int length2 = mingwen.Length;
            int[] miwen = new int[length2];
            for (int i = 0; i < length2; i++)
            {
                x = x + 1;
                x = x % 256;
                a2 = s[x];
                y = y + a2;
                y = y % 256;
                s[x] = b = s[y];
                s[y] = a2;
                c = a2 + b;
                c = c % 256;
                miwen[i] = mingwen[i] ^ s[c];
            }
            
            char[] mi = new char[miwen.Length];
            for (int i = 0; i < miwen.Length; i++)
                mi[i] = (char)miwen[i];

            string miwenstr = new string(mi);
            return miwenstr;
        }

        /// <summary>
        /// Returns the characters decrypted by rc4
        /// </summary>
        /// <param name="str">Encrypted string</param>
        /// <param name="ckey">Key</param>
        public static string DecryptRC4wq(string str, string ckey)
        {
            int[] s = new int[256];
            for (int i = 0; i < 256; i++)
                s[i] = i;

            char[] keys = ckey.ToCharArray();
            int[] key = new int[keys.Length];
            for (int i = 0; i < keys.Length; i++)
                key[i] = keys[i];

            // Ciphertext to array
            char[] datas = str.ToCharArray();
            int[] miwen = new int[datas.Length];
            for (int i = 0; i < datas.Length; i++)
                miwen[i] = datas[i];

            // Get a 256-bit array (key) through a loop
            int j = 0;
            int k = 0;
            int length = key.Length;
            int a;
            for (int i = 0; i < 256; i++)
            {
                a = s[i];
                j = (j + a + key[k]);
                if (j >= 256)
                {
                    j = j % 256;
                }
                s[i] = s[j];
                s[j] = a;
                if (++k >= length)
                {
                    k = 0;
                }
            }
            // the plaintext array is obtained
            int x = 0, y = 0, a2, b, c;
            int length2 = miwen.Length;
            int[] mingwen = new int[length2];
            for (int i = 0; i < length2; i++)
            {
                x = x + 1;
                x = x % 256;
                a2 = s[x];
                y = y + a2;
                y = y % 256;
                s[x] = b = s[y];
                s[y] = a2;
                c = a2 + b;
                c = c % 256;
                mingwen[i] = miwen[i] ^ s[c];
            }

            char[] ming = new char[mingwen.Length];
            for (int i = 0; i < mingwen.Length; i++)
                ming[i] = (char)mingwen[i];

            string mingwenstr = new string(ming);
            return mingwenstr;
        }
        #endregion
    }
}
