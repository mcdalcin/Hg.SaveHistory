using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using Org.BouncyCastle.Crypto.Engines;
using Org.BouncyCastle.Crypto.Modes;
using Org.BouncyCastle.Crypto.Parameters;

namespace Hg.SaveHistory.API
{
    public static class HgScriptSpecific
    {
        #region Members

        private static string STEAM_DELIMITER = "MANCUBUS";
        private static string BETHESDA_DELIMITER = "PAINELEMENTAL";

        /// <summary>
        ///     Decrypt a file from DOOM Eternal Saves
        ///     Function taken from https://github.com/GoobyCorp/DOOMSaveManager/blob/master/Crypto.cs
        ///     Thank you for the reverse engineering of the save file encryption.
        ///     TODO: convert to native .NET when possible and remove dependency
        /// </summary>
        /// <param name="fileKey">decryption key</param>
        /// <param name="filePath">full path to file</param>
        /// <returns>plain text decrypted data</returns>
        public static string DOOMEternal_Decrypt(string fileKey, string filePath)
        {
            string plaintext;

            try
            {
                byte[] fileData = File.ReadAllBytes(filePath);
                byte[] nonceBytes = new byte[12];
                byte[] cipherBytes = new byte[fileData.Length - 12];

                Buffer.BlockCopy(fileData, 0, nonceBytes, 0, nonceBytes.Length);
                Buffer.BlockCopy(fileData, nonceBytes.Length, cipherBytes, 0, cipherBytes.Length);

                byte[] fileKeyBytes = Encoding.UTF8.GetBytes(fileKey);
                byte[] fileKeyHash = new SHA256Managed().ComputeHash(fileKeyBytes);

                var gcmBlockCipher = new GcmBlockCipher(new AesEngine());
                var parameters = new AeadParameters(new KeyParameter(fileKeyHash, 0, 16), 128, nonceBytes, fileKeyBytes);

                gcmBlockCipher.Init(false, parameters);

                byte[] plainBytes = new byte[gcmBlockCipher.GetOutputSize(cipherBytes.Length)];
                int outputOffset = gcmBlockCipher.ProcessBytes(cipherBytes, 0, cipherBytes.Length, plainBytes, 0);

                gcmBlockCipher.DoFinal(plainBytes, outputOffset);

                plaintext = Encoding.UTF8.GetString(plainBytes);
            }
            catch (Exception exception)
            {
                Logger.Error(exception.Message);
                return null;
            }

            return plaintext;
        }

        /// <summary>
        ///     Encrypt a file for OOM Eternal Saves. 
        ///     Function taken from https://github.com/GoobyCorp/DOOMSaveManager/blob/master/Crypto.cs
        ///     Thank you for the reverse engineering of the save file encryption.
        ///     TODO: convert to native .NET when possible and remove dependency
        /// </summary>
        /// <param name="fileKey">encryption key</param>
        /// <param name="filePath">full path to file</param>
        /// <returns>plain text decrypted data</returns>
        public static byte[] DOOMEternal_Encrypt(string fileKey, string filePath) {
            string aad = fileKey + Path.GetFileName(filePath);
            byte[] nonce = RandomBytes(12);
            byte[] aadBytes = Encoding.UTF8.GetBytes(aad);
            byte[] aadHash = new SHA256Managed().ComputeHash(aadBytes);
            
            var cipher = new GcmBlockCipher(new AesEngine());
            var cParams = new AeadParameters(new KeyParameter(aadHash, 0, 16), 128, nonce, aadBytes);
            cipher.Init(true, cParams);
            
            byte[] data = File.ReadAllBytes(filePath);
            byte[] encryptedData = new byte[cipher.GetOutputSize(data.Length)];
            int retLen = cipher.ProcessBytes(data, 0, data.Length, encryptedData, 0);
            cipher.DoFinal(encryptedData, retLen);

            byte[] output = new byte[nonce.Length + encryptedData.Length];
            Buffer.BlockCopy(nonce, 0, output, 0, nonce.Length);
            Buffer.BlockCopy(encryptedData, 0, output, nonce.Length, encryptedData.Length);
            return output;
        }

        private static byte[] RandomBytes(int size) {
            byte[] output = new byte[size];
            new Random().NextBytes(output);
            return output;
        }

        #endregion
    }
}