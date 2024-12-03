using LetsRenew;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using NLog.Extensions.Logging;

var environmentName = Environment.GetEnvironmentVariable("DOTNET_ENVIRONMENT");

var config = new ConfigurationBuilder()
    .SetBasePath(AppContext.BaseDirectory)
    .AddJsonFile($"appsettings.json", true, true)
    .AddJsonFile($"appsettings.{environmentName}.json", true, true)
    .Build();
    
var services = new ServiceCollection();

services.AddLogging(builder =>
{
    builder.ClearProviders();
    builder.SetMinimumLevel(Microsoft.Extensions.Logging.LogLevel.Trace);
    builder.AddNLog(new NLogLoggingConfiguration(config.GetSection("NLog")));
});

services.AddOptions();
services.Configure<AppSettings>(config.GetSection("AppSettings"));


services.AddSingleton<CertService>();

var serviceProvider = services.BuildServiceProvider();

var svc = serviceProvider.GetRequiredService<CertService>();

svc.EnsureAllDirectoriesExistAsync();
await svc.UpdateAllCertificatesAsync();