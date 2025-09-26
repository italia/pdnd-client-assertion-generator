// (c) 2024-2025 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under the MIT License (see LICENSE.txt for details)
using System.Security.Cryptography;
using System.Text;

namespace PDNDClientAssertionGenerator.Utils
{
    public static class SecurityUtils
    {
        /// <summary>
        /// Backward-compatible shim: keeps existing call sites working.
        /// Supported PEM formats:
        /// - PKCS#1: -----BEGIN RSA PRIVATE KEY-----
        /// - PKCS#8: -----BEGIN PRIVATE KEY-----
        /// - PKCS#8 (encrypted): -----BEGIN ENCRYPTED PRIVATE KEY-----
        /// </summary>
        public static RSA GetRsaFromKeyPath(string keyPath, ReadOnlySpan<char> password = default) =>
            CreateRsaFromKeyFile(keyPath, password);

        /// <summary>
        /// Creates an RSA instance from a PEM key file (.pem/.key).
        /// Supports PKCS#1, PKCS#8 (unencrypted), PKCS#8 (encrypted).
        /// </summary>
        /// <param name="keyPath">Path to the PEM key file.</param>
        /// <param name="password">Password for encrypted PKCS#8 PEM (ignored otherwise).</param>
        /// <returns>An RSA instance. The caller must dispose it.</returns>
        /// <exception cref="ArgumentException">Path null/empty.</exception>
        /// <exception cref="FileNotFoundException">File not found.</exception>
        /// <exception cref="InvalidOperationException">Access issues or unsupported format.</exception>
        /// <exception cref="FormatException">Malformed PEM/base64.</exception>
        /// <exception cref="CryptographicException">Import errors.</exception>
        public static RSA CreateRsaFromKeyFile(string keyPath, ReadOnlySpan<char> password = default)
        {
            if (string.IsNullOrWhiteSpace(keyPath))
                throw new ArgumentException("Key path cannot be null or empty.", nameof(keyPath));

            var normalizedPath = keyPath.Trim();
            if (!File.Exists(normalizedPath))
                throw new FileNotFoundException($"Key file not found: {normalizedPath}");

            // Explicitly block PFX/P12
            var ext = Path.GetExtension(normalizedPath).ToLowerInvariant();
            if (ext is ".pfx" or ".p12")
                throw new InvalidOperationException("Only PEM keys are supported (PKCS#1 / PKCS#8).");

            // Read PEM text
            string pem;
            try
            {
                pem = File.ReadAllText(normalizedPath);
            }
            catch (UnauthorizedAccessException ex)
            {
                throw new InvalidOperationException("Access denied while reading the key file.", ex);
            }
            catch (IOException ex)
            {
                throw new InvalidOperationException("I/O error while reading the key file.", ex);
            }

            // Encrypted PKCS#8
            if (pem.Contains("BEGIN ENCRYPTED PRIVATE KEY", StringComparison.Ordinal))
            {
                if (password.IsEmpty)
                    throw new InvalidOperationException("A password is required for an encrypted PKCS#8 PEM key.");

                var der = ExtractDerBlock(pem, "ENCRYPTED PRIVATE KEY");
                var rsa = RSA.Create();
                rsa.ImportEncryptedPkcs8PrivateKey(password, der, out _);
                return rsa;
            }

            // Unencrypted (PKCS#1 or PKCS#8): ImportFromPem handles both
            var rsaPlain = RSA.Create();
            try
            {
                rsaPlain.ImportFromPem(pem);
                return rsaPlain;
            }
            catch (CryptographicException)
            {
                // Fallback: explicit DER extraction for edge cases
                if (pem.Contains("BEGIN PRIVATE KEY", StringComparison.Ordinal))
                {
                    var der = ExtractDerBlock(pem, "PRIVATE KEY"); // PKCS#8 (unencrypted)
                    rsaPlain.ImportPkcs8PrivateKey(der, out _);
                    return rsaPlain;
                }
                if (pem.Contains("BEGIN RSA PRIVATE KEY", StringComparison.Ordinal))
                {
                    var der = ExtractDerBlock(pem, "RSA PRIVATE KEY"); // PKCS#1
                    rsaPlain.ImportRSAPrivateKey(der, out _);
                    return rsaPlain;
                }

                throw new InvalidOperationException("Unsupported or malformed PEM format.");
            }
        }

        /// <summary>
        /// Extracts DER bytes from a specific PEM block label. Strips whitespace.
        /// </summary>
        private static byte[] ExtractDerBlock(string pem, string label)
        {
            var begin = $"-----BEGIN {label}-----";
            var end = $"-----END {label}-----";

            var start = pem.IndexOf(begin, StringComparison.Ordinal);
            var stop = pem.IndexOf(end, StringComparison.Ordinal);
            if (start < 0 || stop < 0 || stop <= start)
                throw new FormatException($"PEM block '{label}' not found or malformed.");

            var base64Area = pem.Substring(start + begin.Length, stop - (start + begin.Length));

            var sb = new StringBuilder(base64Area.Length);
            foreach (var ch in base64Area)
                if (!char.IsWhiteSpace(ch))
                    sb.Append(ch);

            try 
            { 
                return Convert.FromBase64String(sb.ToString()); 
            }
            catch (FormatException ex) 
            { 
                throw new FormatException($"Invalid base64 content in PEM block '{label}'.", ex); 
            }
        }
    }
}