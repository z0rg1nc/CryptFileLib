using System;
using System.Diagnostics;
using System.IO;
using System.Security.Cryptography;
using System.Text;
using BtmI2p.AesHelper;
using BtmI2p.CryptFile.Lib;
using BtmI2p.MiscUtils;
using Xunit;
using Xunit.Abstractions;

namespace BtmI2p.CryptFile.Test
{
    public class TestCryptFile
    {
        private readonly ITestOutputHelper _output;
        public TestCryptFile(ITestOutputHelper output)
        {
	        _output = output;
        }
        [Fact]
        public void TestDecryptWrongAesKey()
        {
            const string dataFileName = "PNG_transparency_demonstration_1.png";
            Assert.Equal(true, File.Exists(dataFileName));
            var dataToEncrypt = File.ReadAllBytes(dataFileName);
            var pass = Encoding.UTF8.GetBytes("TestPassword");
            var salt = new byte[32];
            var mySha256 = SHA256.Create();
            int seed =
                BitConverter.ToInt32(mySha256.ComputeHash(BitConverter.GetBytes((int)DateTime.UtcNow.Ticks & DateTime.UtcNow.Millisecond)), 0);
            var randomSource = new Random(seed);
            randomSource.NextBytes(salt);
            var keyIvGenerated = CryptConfigFileHelper.GenKeyAndIv(pass, salt);
            byte[] encryptedData = keyIvGenerated.EncryptData(dataToEncrypt);

            var changedKey = new byte[keyIvGenerated.Key.Length];
            keyIvGenerated.Key.CopyTo(changedKey, 0);
            changedKey[0] = (byte)(changedKey[0] ^ 3);
            Assert.Throws<EnumException<AesKeyIvPair.EDecryptDataErrCodes>>(() =>
            {
                byte[] originData = new AesKeyIvPair {Iv = keyIvGenerated.Iv, Key = changedKey}
                    .DecryptData(encryptedData);
                _output.WriteLine("Err key decrypted");
                Assert.Equal(originData, dataToEncrypt);
            });
        }

        [Fact]
        public void TestEncryptDecryptImageFile()
        {
            const string dataFileName = "PNG_transparency_demonstration_1.png";
            var fileExists = File.Exists(dataFileName);
            _output.WriteLine(fileExists + string.Empty);
            Assert.Equal(true, fileExists);
            var dataToEncrypt = File.ReadAllBytes(dataFileName);
            var pass = Encoding.UTF8.GetBytes("TestPassword");
            var salt = new byte[32];
            var mySha256 = SHA256.Create();
            int seed =
                BitConverter.ToInt32(
                    mySha256.ComputeHash(
                        BitConverter.GetBytes(
                            (int) DateTime.UtcNow.Ticks 
                            & DateTime.UtcNow.Millisecond
                        )
                    ),
                    0
                );
            var randomSource = new Random(seed);
            randomSource.NextBytes(salt);
            _output.WriteLine("{0} {1} {2}",dataToEncrypt.Length,pass.Length,salt.Length);
            var encryptedData = CryptConfigFileHelper.Encrypt(dataToEncrypt, pass, salt);
            _output.WriteLine("{0}", encryptedData.Length);
            var decryptedData = CryptConfigFileHelper.Decrypt(encryptedData, pass, salt);
            Assert.Equal(dataToEncrypt, decryptedData);
            var encryptedFileName = dataFileName + ".aes256";
            File.WriteAllText(
                encryptedFileName,
                new ScryptPassEncryptedData
                {
                    EncryptedData = encryptedData,
                    Salt = salt
                }.WriteObjectToJson()
            );
        }

        [Fact]
        public void TestGenerateKeySpeed()
        {
            var sw = new Stopwatch();

            sw.Start();

            var pass = Encoding.UTF8.GetBytes("TestPassword");
            var salt = Encoding.UTF8.GetBytes("nNmy:8nPS<wEgC)kQklo");
            var keyIvPair = CryptConfigFileHelper.GenKeyAndIv(pass, salt);

            sw.Stop();
            _output.WriteLine("Key {0}", BitConverter.ToString(keyIvPair.Key));
            _output.WriteLine("Iv {0}", BitConverter.ToString(keyIvPair.Iv));
            _output.WriteLine("Elapsed={0}", sw.Elapsed.TotalMilliseconds);
        }
    }
}
