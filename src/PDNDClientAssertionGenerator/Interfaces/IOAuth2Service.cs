// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using PDNDClientAssertionGenerator.Models;

namespace PDNDClientAssertionGenerator.Interfaces
{
    public interface IOAuth2Service
    {
        /// <summary>
        /// Asynchronously generates a client assertion (JWT) token.
        /// </summary>
        /// <param name="ct">A token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation, containing the generated client assertion as a string.</returns>
        Task<string> GenerateClientAssertionAsync(CancellationToken ct = default);

        /// <summary>
        /// Asynchronously requests an access token by sending the client assertion to the OAuth2 server.
        /// </summary>
        /// <param name="clientAssertion">The client assertion (JWT) used for the token request.</param>
        /// <param name="ct">A token that can be used to cancel the operation.</param>
        /// <returns>A task that represents the asynchronous operation, containing the response with the access token as a <see cref="PDNDTokenResponse"/>.</returns>
        Task<PDNDTokenResponse> RequestAccessTokenAsync(string clientAssertion, CancellationToken ct = default);
    }
}