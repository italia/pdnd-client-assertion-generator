// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using PDNDClientAssertionGenerator.Utils;

namespace PDNDClientAssertionGenerator.Tests
{
    public class DateTimeUtilsTests
    {
        [Fact]
        public void ToUnixTimestamp_ShouldReturnCorrectUnixTimestamp_ForGivenDateTime()
        {
            // Arrange
            DateTime dateTime = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            long expectedUnixTimestamp = 1704067200;

            // Act
            long actualUnixTimestamp = dateTime.ToUnixTimestamp();

            // Assert
            Assert.Equal(expectedUnixTimestamp, actualUnixTimestamp);
        }

        [Fact]
        public void ToUnixTimestamp_ShouldHandleDateTimeInDifferentTimeZones_Correctly()
        {
            // Arrange
            DateTime dateTimeLocal = new DateTime(2024, 1, 1, 0, 0, 0, DateTimeKind.Local);
            DateTime dateTimeUtc = dateTimeLocal.ToUniversalTime();
            long expectedUnixTimestamp = new DateTimeOffset(dateTimeUtc).ToUnixTimeSeconds();

            // Act
            long actualUnixTimestamp = dateTimeLocal.ToUnixTimestamp();

            // Assert
            Assert.Equal(expectedUnixTimestamp, actualUnixTimestamp);
        }

        [Fact]
        public void ToUnixTimestamp_ShouldReturnCorrectUnixTimestamp_ForEpochStart()
        {
            // Arrange
            DateTime epochStart = new DateTime(1970, 1, 1, 0, 0, 0, DateTimeKind.Utc);
            long expectedUnixTimestamp = 0;

            // Act
            long actualUnixTimestamp = epochStart.ToUnixTimestamp();

            // Assert
            Assert.Equal(expectedUnixTimestamp, actualUnixTimestamp);
        }
    }
}
