using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using BtmI2p.AesHelper;
using BtmI2p.MiscUtils;
using CryptSharp.Utility;
using NLog;

namespace BtmI2p.CryptFile.Lib
{
    public class ScryptPassEncryptedDataWrongVersionException : Exception
    {
        public ScryptPassEncryptedDataWrongVersionException(
            int requiredVersion,
            int actualVersion
        )
        {
            RequiredVersion = requiredVersion;
            ActualVersion = actualVersion;
        }

        public int RequiredVersion { get; set; }
        public int ActualVersion { get; set; }
    }

    public class ScryptPassEncryptedData
    {
        public byte[] Salt;
        public byte[] EncryptedData;
        public int DataFormatVersion = 0;
        /**/
        public ScryptPassEncryptedData()
        {
        }
        public static void WriteToFile<T1>(T1 value, string path, byte[] pass)
        {
            if(!File.Exists(path))
                File.Create(path).Close();
            var serializedValue = FromValue(value, pass)
                .WriteObjectToJson();
            File.WriteAllText(
                path,
                serializedValue,
                Encoding.UTF8
            );
        }

        public static T1 ReadFromFile<T1>(string path, AesProtectedByteArray pass)
        {
            using (var tempPass = pass.TempData)
            {
                return ReadFromFile<T1>(path, tempPass.Data);
            }
        }

        /// <exception cref="EnumException{EGetValueT1ErrCodes}"></exception>
        public static T1 ReadFromFile<T1>(string path, byte[] pass)
        {
            if(!File.Exists(path))
                throw new ArgumentException("path");
            var encryptedT1 = File.ReadAllText(
                path,
                Encoding.UTF8
            ).ParseJsonToType<ScryptPassEncryptedData>();
            return encryptedT1.GetValue<T1>(pass);
        }

        public static ScryptPassEncryptedData FromValue<T1>(
            T1 value, 
            byte[] pass,
            CryptConfigFileHelperScryptParameters scryptParameters = null
        )
        {
            return new ScryptPassEncryptedData(
                Encoding.UTF8.GetBytes(value.WriteObjectToJson()),
                pass,
                null,
                scryptParameters
            );
        }

        public ScryptPassEncryptedData(
            byte[] originData,
            byte[] pass,
            byte[] salt = null,
            CryptConfigFileHelperScryptParameters scryptParameters = null
        )
        {
            if (salt == null)
            {
                salt = new byte[32];
                MiscFuncs.GetRandomBytes(salt);
            }
            if(salt.Length != 32)
                throw new Exception("salt.Length != 32");
            Salt = salt;
            EncryptedData = CryptConfigFileHelper.Encrypt(
                originData,
                pass,
                salt,
                scryptParameters
            );
        }


        public async Task ChangePass(
            byte[] oldPass,
            byte[] newPass,
            CryptConfigFileHelperScryptParameters
                scryptParameters = null
        )
        {
            if(!CheckPass(oldPass))
                throw new ArgumentException(
                    MyNameof.GetLocalVarName(() => oldPass)
                );
            var originData = GetOriginData(
                oldPass,
                scryptParameters
            );
            Salt = new byte[32];
            MiscFuncs.GetRandomBytes(Salt);
            EncryptedData = CryptConfigFileHelper.Encrypt(
                originData,
                newPass,
                Salt,
                scryptParameters
            );
        }

        public bool CheckPass(
            byte[] pass,
            CryptConfigFileHelperScryptParameters scryptParameters = null
        )
        {
            try
            {
                CryptConfigFileHelper.Decrypt(
                    EncryptedData,
                    pass,
                    Salt,
                    scryptParameters
                );
                return true;
            }
            catch
            {
                return false;
            }
        }

        public byte[] GetOriginData(
            byte[] pass,
            CryptConfigFileHelperScryptParameters scryptParameters = null)
        {
            return CryptConfigFileHelper.Decrypt(
                EncryptedData,
                pass,
                Salt,
                scryptParameters
            );
        }

        public enum EGetValueT1ErrCodes
        {
            WrongPassword
        }
        public T1 GetValue<T1>(
            byte[] pass,
            CryptConfigFileHelperScryptParameters scryptParameters = null
            )
        {
            try
            {
                return Encoding.UTF8.GetString(CryptConfigFileHelper.Decrypt(
                    EncryptedData,
                    pass,
                    Salt,
                    scryptParameters
                    )).ParseJsonToType<T1>();
            }
            catch (EnumException<CryptConfigFileHelper.EDecryptErrCodes> enumExc)
            {
                if (enumExc.ExceptionCode == CryptConfigFileHelper.EDecryptErrCodes.WrongPassword)
                    throw EnumException.Create(
                        EGetValueT1ErrCodes.WrongPassword,
                        innerException: enumExc
                    );
                throw;
            }
        }
    }

    public class CryptConfigFileHelperScryptParameters
    {
        public int Cost = 8192;
        public int BlockSize = 8;
        public int Parallel = 1;
    }

    public static class CryptConfigFileHelper
    {
        public static AesKeyIvPair GenKeyAndIv(
            byte[] pass, 
            byte[] salt, 
            CryptConfigFileHelperScryptParameters scryptParameters = null)
        {
            if(scryptParameters == null)
                scryptParameters = new CryptConfigFileHelperScryptParameters();
            byte[] passHash;
            byte[] saltHash;
            using (var mySha256 = new SHA256Managed())
            {
                passHash = mySha256.ComputeHash(pass);
                saltHash = mySha256.ComputeHash(salt);
            }
            var derivedKey = SCrypt.ComputeDerivedKey(
                passHash,
                saltHash,
                scryptParameters.Cost,
                scryptParameters.BlockSize,
                scryptParameters.Parallel,
                1,
                48
            );
            var initKey = new byte[32];
            var iv = new byte[16];
            Array.Copy(derivedKey,0,initKey,0,32);
            Array.Copy(derivedKey,32,iv,0,16);
            return new AesKeyIvPair() {Iv = iv, Key = initKey};
        }

        private static readonly Logger _logger = LogManager.GetCurrentClassLogger();
        public static byte[] Encrypt(
            byte[] data, 
            byte[] pass,
            byte[] salt,
            CryptConfigFileHelperScryptParameters scryptParameters = null)
        {
            if(data == null || pass == null || salt == null)
                throw new ArgumentNullException();
            var keyIvGenerated = GenKeyAndIv(pass, salt, scryptParameters);
            return keyIvGenerated.EncryptData(data);
        }

        public enum EDecryptErrCodes
        {
            WrongPassword
        }
        public static byte[] Decrypt(
            byte[] encryptedData, 
            byte[] pass, 
            byte[] salt,
            CryptConfigFileHelperScryptParameters scryptParameters = null)
        {
            if (encryptedData == null || pass == null || salt == null)
                throw new ArgumentNullException();
            var keyIvGenerated = GenKeyAndIv(pass, salt, scryptParameters);
            try
            {
                return keyIvGenerated.DecryptData(encryptedData);
            }
            catch (EnumException<AesKeyIvPair.EDecryptDataErrCodes> enumExc)
            {
                if (enumExc.ExceptionCode == AesKeyIvPair.EDecryptDataErrCodes.WrongKey)
                    throw EnumException.Create(EDecryptErrCodes.WrongPassword,
                        innerException:enumExc);
                throw;
            }
        }
    }
}
