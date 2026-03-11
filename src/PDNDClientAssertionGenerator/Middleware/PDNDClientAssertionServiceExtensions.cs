// (c) 2024 Francesco Del Re <francesco.delre.87@gmail.com>
// This code is licensed under MIT license (see LICENSE.txt for details)
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.DependencyInjection.Extensions;
using PDNDClientAssertionGenerator.Configuration;
using PDNDClientAssertionGenerator.Interfaces;
using PDNDClientAssertionGenerator.Services;

namespace PDNDClientAssertionGenerator.Middleware
{
    public static class PDNDClientAssertionServiceExtensions
    {
        /// <summary>
        /// Configures the services required for the PDND Client Assertion process.
        /// This method sets up the configuration for `ClientAssertionConfig` and registers necessary services.
        /// </summary>
        /// <param name="services">The IServiceCollection to which the services are added.</param>
        /// <param name="configuration">Optional IConfiguration instance. If not provided, a default configuration is built from appsettings.json and environment variables.</param>
        /// <returns>The updated IServiceCollection instance.</returns>
        public static IServiceCollection AddPDNDClientAssertionServices(this IServiceCollection services, IConfiguration? configuration = null)
        {
            // Use the provided configuration or build a default one
            configuration ??= new ConfigurationManager()
                .SetBasePath(Directory.GetCurrentDirectory())
                .AddJsonFile("appsettings.json", optional: false, reloadOnChange: true)
                .AddEnvironmentVariables()
                .Build();

            // Ensure that the configuration contains required sections and values
            var configSection = configuration.GetSection("ClientAssertionConfig");
            if (!configSection.Exists())
            {
                throw new InvalidOperationException("Missing 'ClientAssertionConfig' section in appsettings.json.");
            }

            // Register ClientAssertionConfig using the IOptions pattern with Bind
            services.Configure<ClientAssertionConfig>(config =>
            {
                configSection.Bind(config);
            });

            // Register IHttpClientFactory
            services.AddHttpClient();

            // Register OAuth2Service and ClientAssertionGeneratorService as scoped services
            services.AddScoped<IOAuth2Service, OAuth2Service>();
            services.AddScoped<IClientAssertionGenerator, ClientAssertionGeneratorService>();

            // Return the updated service collection
            return services;
        }
    }
}
