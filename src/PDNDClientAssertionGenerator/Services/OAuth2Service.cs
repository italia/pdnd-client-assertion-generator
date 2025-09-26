// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using PDNDClientAssertionGenerator.Configuration;
using PDNDClientAssertionGenerator.Interfaces;
using PDNDClientAssertionGenerator.Models;
using PDNDClientAssertionGenerator.Utils;
using System.IdentityModel.Tokens.Jwt;
using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Json;

namespace PDNDClientAssertionGenerator.Services
{
    /// <summary>
    /// Service for handling OAuth2 client assertion generation and token requests.
    /// </summary>
    public class OAuth2Service : IOAuth2Service
    {
        private readonly ClientAssertionConfig _config;

        /// <summary>
        /// Initializes a new instance of the <see cref="OAuth2Service"/> class.
        /// </summary>
        /// <param name="config">An <see cref="IOptions{ClientAssertionConfig}"/> object containing the configuration for client assertion generation.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="config"/> is null.</exception>
        public OAuth2Service(IOptions<ClientAssertionConfig> config)
        {
            _config = config.Value ?? throw new ArgumentNullException(nameof(config));
        }

        /// <inheritdoc />
        public async Task<string> GenerateClientAssertionAsync(CancellationToken ct = default)
        {
            if (ct.IsCancellationRequested) return string.Empty;

            // Generate a unique token ID (JWT ID)
            Guid tokenId = Guid.NewGuid();

            // Define the current UTC time and the token expiration time.
            DateTime issuedAt = DateTime.UtcNow;
            DateTime expiresAt = issuedAt.AddSeconds(_config.Duration);

            // Define JWT header as a dictionary of key-value pairs.
            Dictionary<string, string> headers = new()
            {
                { "kid", _config.KeyId },    // Key ID used to identify the signing key
                { "alg", _config.Algorithm }, // Algorithm used for signing (e.g., RS256)
                { "typ", _config.Type }       // Type of the token, usually "JWT"
            };

            // Define the payload as a list of claims, which represent the content of the JWT.
            var payloadClaims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Iss, _config.Issuer),   // Issuer of the token
                new Claim(JwtRegisteredClaimNames.Sub, _config.Subject),  // Subject of the token
                new Claim(JwtRegisteredClaimNames.Aud, _config.Audience), // Audience for which the token is intended
                new Claim("purposeId", _config.PurposeId),                // Custom claim for the purpose of the token
                new Claim(JwtRegisteredClaimNames.Jti, tokenId.ToString("D").ToLower()), // JWT ID
                new Claim(JwtRegisteredClaimNames.Iat, issuedAt.ToUnixTimestamp().ToString(), ClaimValueTypes.Integer64), // Issued At time (as Unix timestamp)
                new Claim(JwtRegisteredClaimNames.Exp, expiresAt.ToUnixTimestamp().ToString(), ClaimValueTypes.Integer64)  // Expiration time (as Unix timestamp)
            };

            // Create signing credentials using RSA for signing the token.
            using var rsa = SecurityUtils.GetRsaFromKeyPath(_config.KeyPath, _config.KeyPassword.AsSpan());
            var rsaSecurityKey = new RsaSecurityKey(rsa);
            var signingCredentials = new SigningCredentials(rsaSecurityKey, SecurityAlgorithms.RsaSha256)
            {
                CryptoProviderFactory = new CryptoProviderFactory { CacheSignatureProviders = false }
            };

            // Create the JWT token with the specified header and payload claims.
            var token = new JwtSecurityToken(
                new JwtHeader(signingCredentials, headers),
                new JwtPayload(payloadClaims)
            );

            // Use JwtSecurityTokenHandler to convert the token into a string.
            var tokenHandler = new JwtSecurityTokenHandler();
            string clientAssertion = string.Empty;

            try
            {
                clientAssertion = tokenHandler.WriteToken(token);
            }
            catch (Exception ex)
            {
                throw new InvalidOperationException("Failed to generate JWT token.", ex);
            }

            return await Task.FromResult(clientAssertion); // Return the generated token as a string.
        }

        /// <inheritdoc />
        public async Task<PDNDTokenResponse> RequestAccessTokenAsync(string clientAssertion, CancellationToken ct = default)
        {
            using var httpClient = new HttpClient();

            // Create the payload for the POST request in URL-encoded format.
            var payload = new Dictionary<string, string>
            {
                { "client_id", _config.ClientId }, // Client ID as per OAuth2 spec
                { "client_assertion", clientAssertion }, // Client assertion (JWT) generated in the previous step
                { "client_assertion_type", "urn:ietf:params:oauth:client-assertion-type:jwt-bearer" }, // Assertion type
                { "grant_type", "client_credentials" } // Grant type for client credentials
            };

            // Set the Accept header to request JSON responses from the server.
            httpClient.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));

            // Create the content for the POST request (FormUrlEncodedContent).
            var content = new FormUrlEncodedContent(payload);

            // Send the POST request to the OAuth2 server and await the response.
            HttpResponseMessage response = await httpClient
                .PostAsync(_config.ServerUrl, content, ct)
                .ConfigureAwait(false);

            // Ensure the response indicates success (throws an exception if not).
            response.EnsureSuccessStatusCode();

            // Read and parse the response body as a JSON string.
            string jsonResponse = await response.Content
                .ReadAsStringAsync(ct)
                .ConfigureAwait(false);

            try
            {
                // Deserialize the JSON response into the PDNDTokenResponse object.
                return JsonSerializer.Deserialize<PDNDTokenResponse>(jsonResponse)
                             ?? throw new InvalidOperationException("Token response is null or invalid JSON.");
            }
            catch (JsonException ex)
            {
                // Handle JSON deserialization errors.
                throw new InvalidOperationException("Failed to deserialize the token response.", ex);
            }
        }
    }
}