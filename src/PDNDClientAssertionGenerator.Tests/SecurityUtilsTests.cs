// (c) 2024-2025 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under the MIT License (see LICENSE.txt for details)
using System.Security.Cryptography;
using System.Text;
using PDNDClientAssertionGenerator.Utils;

namespace PDNDClientAssertionGenerator.Tests
{
    public class SecurityUtilsTests : IDisposable
    {
        private readonly List<string> _tempFiles = new();

        // ---------- Helpers ----------

        private string WritePemToTempFile(string pem)
        {
            string path = Path.Combine(Path.GetTempPath(), $"pemtest_{Guid.NewGuid():N}.pem");
            File.WriteAllText(path, pem);
            _tempFiles.Add(path);
            return path;
        }

        private static string ToPem(string label, byte[] der)
        {
            var b64 = Convert.ToBase64String(der);
            var sb = new StringBuilder();
            sb.AppendLine($"-----BEGIN {label}-----");

            // Wrap at 64 characters per PEM convention
            for (int i = 0; i < b64.Length; i += 64)
            {
                int len = Math.Min(64, b64.Length - i);
                sb.AppendLine(b64.Substring(i, len));
            }

            sb.AppendLine($"-----END {label}-----");
            return sb.ToString();
        }

        private static byte[] RandomData(int size = 32)
        {
            var bytes = new byte[size];
            RandomNumberGenerator.Fill(bytes);
            return bytes;
        }

        private static void AssertRsaSameModulus(RSA privImported, RSA privOriginal)
        {
            var p1 = privImported.ExportParameters(false);
            var p2 = privOriginal.ExportParameters(false);

            Assert.NotNull(p1.Modulus);
            Assert.NotNull(p2.Modulus);
            Assert.Equal(p2.Modulus, p1.Modulus);
        }

        public void Dispose()
        {
            foreach (var f in _tempFiles)
            {
                try { if (File.Exists(f)) File.Delete(f); } catch { /* ignore */ }
            }
        }

        // ---------- Tests: success paths ----------

        [Fact]
        public void CreateRsaFromKeyFile_PKCS1_Pem_Success()
        {
            using var rsa = RSA.Create(2048);
            var derPkcs1 = rsa.ExportRSAPrivateKey(); // PKCS#1 DER
            var pem = ToPem("RSA PRIVATE KEY", derPkcs1);
            var path = WritePemToTempFile(pem);

            using var imported = SecurityUtils.CreateRsaFromKeyFile(path);

            // Verify the imported key matches the original (public modulus)
            AssertRsaSameModulus(imported, rsa);

            // Sign/Verify sanity check
            var data = RandomData();
            var sig = imported.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.True(imported.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        [Fact]
        public void CreateRsaFromKeyFile_PKCS8_Unencrypted_Pem_Success()
        {
            using var rsa = RSA.Create(2048);
            var derPkcs8 = rsa.ExportPkcs8PrivateKey(); // PKCS#8 DER
            var pem = ToPem("PRIVATE KEY", derPkcs8);
            var path = WritePemToTempFile(pem);

            using var imported = SecurityUtils.CreateRsaFromKeyFile(path);

            AssertRsaSameModulus(imported, rsa);

            var data = RandomData();
            var sig = imported.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.True(imported.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        [Fact]
        public void CreateRsaFromKeyFile_PKCS8_Encrypted_Pem_WithPassword_Success()
        {
            using var rsa = RSA.Create(2048);

            ReadOnlySpan<char> password = "test-password";
            var pbe = new PbeParameters(
                PbeEncryptionAlgorithm.Aes256Cbc,
                HashAlgorithmName.SHA256,
                iterationCount: 100_000);

            var derEncrypted = rsa.ExportEncryptedPkcs8PrivateKey(password, pbe);
            var pem = ToPem("ENCRYPTED PRIVATE KEY", derEncrypted);
            var path = WritePemToTempFile(pem);

            using var imported = SecurityUtils.CreateRsaFromKeyFile(path, password);

            AssertRsaSameModulus(imported, rsa);

            var data = RandomData();
            var sig = imported.SignData(data, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            Assert.True(imported.VerifyData(data, sig, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1));
        }

        [Fact]
        public void GetRsaFromKeyPath_ShimsToCreateRsaFromKeyFile()
        {
            using var rsa = RSA.Create(2048);
            var derPkcs8 = rsa.ExportPkcs8PrivateKey();
            var pem = ToPem("PRIVATE KEY", derPkcs8);
            var path = WritePemToTempFile(pem);

            using var imported = SecurityUtils.GetRsaFromKeyPath(path);
            AssertRsaSameModulus(imported, rsa);
        }

        [Fact]
        public void CreateRsaFromKeyFile_Pem_WithExtraWhitespace_Success()
        {
            using var rsa = RSA.Create(2048);
            var derPkcs1 = rsa.ExportRSAPrivateKey();
            var cleanPem = ToPem("RSA PRIVATE KEY", derPkcs1);

            // Inject extra spaces and blank lines
            var messyPem = "\r\n  " + cleanPem.Replace("\n", "\n   ") + "\n \r\n";
            var path = WritePemToTempFile(messyPem);

            using var imported = SecurityUtils.CreateRsaFromKeyFile(path);
            AssertRsaSameModulus(imported, rsa);
        }

        // ---------- Tests: ExtractDerBlock ----------

        [Fact]
        public void ExtractDerBlock_PKCS1_Roundtrip_MatchesExportedDer()
        {
            using var rsa = RSA.Create(2048);
            var der = rsa.ExportRSAPrivateKey();
            var pem = ToPem("RSA PRIVATE KEY", der);

            var extracted = InvokeExtractDerBlock(pem, "RSA PRIVATE KEY");
            Assert.Equal(der, extracted);
        }

        [Fact]
        public void ExtractDerBlock_PKCS8_Roundtrip_MatchesExportedDer()
        {
            using var rsa = RSA.Create(2048);
            var der = rsa.ExportPkcs8PrivateKey();
            var pem = ToPem("PRIVATE KEY", der);

            var extracted = InvokeExtractDerBlock(pem, "PRIVATE KEY");
            Assert.Equal(der, extracted);
        }

        [Fact]
        public void ExtractDerBlock_EncryptedPKCS8_Roundtrip_MatchesExportedDer()
        {
            using var rsa = RSA.Create(2048);
            ReadOnlySpan<char> password = "s3cr3t";
            var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 60000);
            var der = rsa.ExportEncryptedPkcs8PrivateKey(password, pbe);
            var pem = ToPem("ENCRYPTED PRIVATE KEY", der);

            var extracted = InvokeExtractDerBlock(pem, "ENCRYPTED PRIVATE KEY");
            Assert.Equal(der, extracted);
        }

        // ---------- Tests: error paths ----------

        [Fact]
        public void CreateRsaFromKeyFile_EncryptedPem_MissingPassword_Throws()
        {
            using var rsa = RSA.Create(2048);
            ReadOnlySpan<char> password = "pw";
            var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 100_000);
            var derEnc = rsa.ExportEncryptedPkcs8PrivateKey(password, pbe);
            var pem = ToPem("ENCRYPTED PRIVATE KEY", derEnc);
            var path = WritePemToTempFile(pem);

            var ex = Assert.Throws<InvalidOperationException>(() =>
            {
                using var _ = SecurityUtils.CreateRsaFromKeyFile(path /* no password */);
            });
            Assert.Contains("password", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void CreateRsaFromKeyFile_EncryptedPem_WrongPassword_Throws()
        {
            using var rsa = RSA.Create(2048);
            ReadOnlySpan<char> password = "correct";
            var pbe = new PbeParameters(PbeEncryptionAlgorithm.Aes256Cbc, HashAlgorithmName.SHA256, 90_000);
            var derEnc = rsa.ExportEncryptedPkcs8PrivateKey(password, pbe);
            var pem = ToPem("ENCRYPTED PRIVATE KEY", derEnc);
            var path = WritePemToTempFile(pem);

            Assert.Throws<CryptographicException>(() =>
            {
                using var _ = SecurityUtils.CreateRsaFromKeyFile(path, "wrong".AsSpan());
            });
        }

        [Fact]
        public void CreateRsaFromKeyFile_PathDoesNotExist_Throws()
        {
            var nonExisting = Path.Combine(Path.GetTempPath(), $"missing_{Guid.NewGuid():N}.pem");
            var ex = Assert.Throws<FileNotFoundException>(() =>
            {
                using var _ = SecurityUtils.CreateRsaFromKeyFile(nonExisting);
            });
            Assert.Contains("not found", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Theory]
        [InlineData("")]
        [InlineData("   ")]
        public void CreateRsaFromKeyFile_EmptyOrWhitespacePath_Throws(string path)
        {
            var ex = Assert.Throws<ArgumentException>(() =>
            {
                using var _ = SecurityUtils.CreateRsaFromKeyFile(path);
            });
            Assert.Contains("null or empty", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void CreateRsaFromKeyFile_PfxExtension_Throws()
        {
            var pfxPath = Path.Combine(Path.GetTempPath(), $"dummy_{Guid.NewGuid():N}.pfx");
            File.WriteAllText(pfxPath, "not-a-real-pfx");
            _tempFiles.Add(pfxPath);

            var ex = Assert.Throws<InvalidOperationException>(() =>
            {
                using var _ = SecurityUtils.CreateRsaFromKeyFile(pfxPath);
            });

            Assert.Contains("Only PEM keys are supported", ex.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void ExtractDerBlock_InvalidLabel_Throws_Wrapped()
        {
            using var rsa = RSA.Create(2048);
            var der = rsa.ExportPkcs8PrivateKey();
            var pem = ToPem("PRIVATE KEY", der);

            var ex = Assert.Throws<System.Reflection.TargetInvocationException>(() =>
            {
                InvokeExtractDerBlock(pem, "RSA PRIVATE KEY");
            });

            Assert.IsType<FormatException>(ex.InnerException);
            Assert.Contains("not found or malformed", ex.InnerException!.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public void CreateRsaFromKeyFile_MalformedBase64_ThrowsArgumentException()
        {
            // Valid headers but invalid base64 payload (contains '@')
            var pem = "-----BEGIN PRIVATE KEY-----\n@@@@@@\n-----END PRIVATE KEY-----\n";
            var path = WritePemToTempFile(pem);

            // ImportFromPem throws ArgumentException ("No supported key formats... (Parameter 'input')")
            var ex = Assert.Throws<ArgumentException>(() =>
            {
                using var _ = SecurityUtils.CreateRsaFromKeyFile(path);
            });

            Assert.Contains("No supported key formats", ex.Message, StringComparison.OrdinalIgnoreCase);
            Assert.Equal("input", ex.ParamName);
        }

        [Fact]
        public void CreateRsaFromKeyFile_Base64OkButInvalidDer_ThrowsCryptographicException()
        {
            // Construct base64 that decodes but is not a valid DER-encoded PKCS#8 key
            // We'll just take random bytes and base64-encode them.
            var garbageDer = RandomData(256);
            var b64 = Convert.ToBase64String(garbageDer);

            var pem = $"-----BEGIN PRIVATE KEY-----\n{b64}\n-----END PRIVATE KEY-----\n";
            var path = WritePemToTempFile(pem);

            // ImportFromPem will likely throw CryptographicException.
            // Our catch will attempt ImportPkcs8PrivateKey which will also throw CryptographicException.
            Assert.Throws<CryptographicException>(() =>
            {
                using var _ = SecurityUtils.CreateRsaFromKeyFile(path);
            });
        }

        // ---------- Private: reflection helper to call private ExtractDerBlock ----------

        private static byte[] InvokeExtractDerBlock(string pem, string label)
        {
            var mi = typeof(SecurityUtils).GetMethod("ExtractDerBlock",
                System.Reflection.BindingFlags.NonPublic | System.Reflection.BindingFlags.Static)
                ?? throw new InvalidOperationException("ExtractDerBlock method not found.");

            return (byte[]?)mi.Invoke(null, new object[] { pem, label })
                   ?? throw new InvalidOperationException("ExtractDerBlock returned null.");
        }
    }
}