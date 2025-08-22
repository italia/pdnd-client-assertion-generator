// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using Moq;
using PDNDClientAssertionGenerator.Interfaces;
using PDNDClientAssertionGenerator.Models;
using PDNDClientAssertionGenerator.Services;

namespace PDNDClientAssertionGenerator.Tests
{
    public class ClientAssertionGeneratorServiceTests
    {
        [Fact]
        public async Task GetClientAssertionAsync_ShouldCall_GenerateClientAssertionAsync()
        {
            // Arrange
            var oauth2ServiceMock = new Mock<IOAuth2Service>();
            oauth2ServiceMock
                .Setup(o => o.GenerateClientAssertionAsync(It.IsAny<CancellationToken>()))
                .ReturnsAsync("assertion");

            var sut = new ClientAssertionGeneratorService(oauth2ServiceMock.Object);

            // Act
            var result = await sut.GetClientAssertionAsync();

            // Assert
            Assert.Equal("assertion", result);
            oauth2ServiceMock.Verify(
                o => o.GenerateClientAssertionAsync(It.IsAny<CancellationToken>()),
                Times.Once);
        }

        [Fact]
        public async Task GetTokenAsync_ShouldCall_RequestAccessTokenAsync_WithClientAssertion()
        {
            // Arrange
            var expected = new PDNDTokenResponse
            {
                TokenType = "Bearer",
                ExpiresIn = 3600,
                AccessToken = "abc"
            };

            var oauth2ServiceMock = new Mock<IOAuth2Service>();
            oauth2ServiceMock
                .Setup(o => o.RequestAccessTokenAsync("testClientAssertion", It.IsAny<CancellationToken>()))
                .ReturnsAsync(expected);

            var sut = new ClientAssertionGeneratorService(oauth2ServiceMock.Object);

            // Act
            var token = await sut.GetTokenAsync("testClientAssertion");

            // Assert
            Assert.Same(expected, token);
            oauth2ServiceMock.Verify(
                o => o.RequestAccessTokenAsync("testClientAssertion", It.IsAny<CancellationToken>()),
                Times.Once);
        }
    }
}