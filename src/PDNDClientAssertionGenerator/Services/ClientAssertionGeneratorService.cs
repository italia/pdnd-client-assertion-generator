// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using PDNDClientAssertionGenerator.Interfaces;
using PDNDClientAssertionGenerator.Models;

namespace PDNDClientAssertionGenerator.Services
{
    /// <summary>
    /// This service handles the generation of client assertions and the retrieval of access tokens.
    /// </summary>
    public class ClientAssertionGeneratorService : IClientAssertionGenerator
    {
        // Dependency on the OAuth2 service for generating client assertions and requesting tokens.
        private readonly IOAuth2Service _oauth2Service;

        /// <summary>
        /// Initializes a new instance of the <see cref="ClientAssertionGeneratorService"/> class.
        /// </summary>
        /// <param name="oauth2Service">An instance of <see cref="IOAuth2Service"/> used for generating client assertions and requesting tokens.</param>
        /// <exception cref="ArgumentNullException">Thrown when <paramref name="oauth2Service"/> is null.</exception>
        public ClientAssertionGeneratorService(IOAuth2Service oauth2Service)
        {
            _oauth2Service = oauth2Service ?? throw new ArgumentNullException(nameof(oauth2Service));
        }

        /// <inheritdoc />
        public async Task<string> GetClientAssertionAsync(CancellationToken ct = default)
        {
            return await _oauth2Service.GenerateClientAssertionAsync(ct);
        }

        /// <inheritdoc />
        public async Task<PDNDTokenResponse> GetTokenAsync(string clientAssertion, CancellationToken ct = default)
        {
            return await _oauth2Service.RequestAccessTokenAsync(clientAssertion, ct);
        }
    }
}