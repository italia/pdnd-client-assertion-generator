// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using Microsoft.Extensions.Options;
using Moq;
using Moq.Protected;
using PDNDClientAssertionGenerator.Configuration;
using PDNDClientAssertionGenerator.Services;
using System.Net;
using System.Net.Http;

namespace PDNDClientAssertionGenerator.Tests
{
    public class OAuth2ServiceTests
    {
        private readonly OAuth2Service _oauth2Service;
        private readonly Mock<HttpMessageHandler> _handlerMock;
        private readonly Mock<IOptions<ClientAssertionConfig>> _mockOptions;
        private readonly Mock<IHttpClientFactory> _mockHttpClientFactory;

        public OAuth2ServiceTests()
        {
            // Set up the HttpMessageHandler mock
            _handlerMock = new Mock<HttpMessageHandler>();

            // Set up the HttpClientFactory mock
            _mockHttpClientFactory = new Mock<IHttpClientFactory>();
            _mockHttpClientFactory
                .Setup(f => f.CreateClient(It.IsAny<string>()))
                .Returns(new HttpClient(_handlerMock.Object));

            // Set up the ClientAssertionConfig object
            var clientAssertionConfig = new ClientAssertionConfig
            {
                ServerUrl = "https://test-server-url.com",
                ClientId = "test-client-id",
                KeyId = "test-key-id",
                Algorithm = "RS256",
                Type = "JWT",
                Issuer = "test-issuer",
                Subject = "test-subject",
                Audience = "test-audience",
                PurposeId = "test-purpose-id",
                KeyPath = "path/to/key",
                Duration = 60 // token duration in seconds
            };

            // Create the mock IOptions<ClientAssertionConfig> instance
            _mockOptions = new Mock<IOptions<ClientAssertionConfig>>();
            _mockOptions.Setup(o => o.Value).Returns(clientAssertionConfig);

            // Initialize OAuth2Service with the mocked dependencies
            _oauth2Service = new OAuth2Service(_mockOptions.Object, _mockHttpClientFactory.Object);
        }

        [Fact]
        public async Task RequestAccessTokenAsync_ThrowsExceptionOnInvalidJsonResponse()
        {
            // Arrange: Invalid JSON Mock
            _handlerMock
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.OK,
                    Content = new StringContent("invalid_json_response"),
                });

            // Act & Assert: Verify that an InvalidOperationException is thrown on an invalid JSON response
            var exception = await Assert.ThrowsAsync<InvalidOperationException>(() => _oauth2Service.RequestAccessTokenAsync("valid_client_assertion"));
            Assert.Contains("Failed to deserialize", exception.Message, StringComparison.OrdinalIgnoreCase);
        }

        [Fact]
        public async Task RequestAccessTokenAsync_ThrowsArgumentException_WhenClientAssertionIsNull()
        {
            await Assert.ThrowsAsync<ArgumentException>(() => _oauth2Service.RequestAccessTokenAsync(null!));
        }

        [Fact]
        public async Task RequestAccessTokenAsync_ThrowsArgumentException_WhenClientAssertionIsEmpty()
        {
            await Assert.ThrowsAsync<ArgumentException>(() => _oauth2Service.RequestAccessTokenAsync(string.Empty));
        }

        [Fact]
        public async Task RequestAccessTokenAsync_ThrowsArgumentException_WhenClientAssertionIsWhitespace()
        {
            await Assert.ThrowsAsync<ArgumentException>(() => _oauth2Service.RequestAccessTokenAsync("   "));
        }

        [Fact]
        public async Task RequestAccessTokenAsync_ThrowsHttpRequestException_OnNonSuccessStatusCode()
        {
            // Arrange
            _handlerMock
                .Protected()
                .Setup<Task<HttpResponseMessage>>(
                    "SendAsync",
                    ItExpr.IsAny<HttpRequestMessage>(),
                    ItExpr.IsAny<CancellationToken>()
                )
                .ReturnsAsync(new HttpResponseMessage
                {
                    StatusCode = HttpStatusCode.Unauthorized,
                    Content = new StringContent("Unauthorized"),
                });

            // Act & Assert
            await Assert.ThrowsAsync<HttpRequestException>(() => _oauth2Service.RequestAccessTokenAsync("valid_client_assertion"));
        }

        [Fact]
        public async Task GenerateClientAssertionAsync_ThrowsOperationCanceledException_WhenCancelled()
        {
            // Arrange
            using var cts = new CancellationTokenSource();
            cts.Cancel();

            // Act & Assert
            await Assert.ThrowsAsync<OperationCanceledException>(() => _oauth2Service.GenerateClientAssertionAsync(cts.Token));
        }

        [Fact]
        public void Constructor_ThrowsArgumentNullException_WhenConfigIsNull()
        {
            Assert.Throws<ArgumentNullException>(() => new OAuth2Service(null!, _mockHttpClientFactory.Object));
        }

        [Fact]
        public void Constructor_ThrowsArgumentNullException_WhenHttpClientFactoryIsNull()
        {
            Assert.Throws<ArgumentNullException>(() => new OAuth2Service(_mockOptions.Object, null!));
        }
    }
}
