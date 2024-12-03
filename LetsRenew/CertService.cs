using System.Security.Cryptography.X509Certificates;
using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Directory = System.IO.Directory;

namespace LetsRenew;

public class CertService
{
    private readonly ILogger<CertService> _logger;
    private readonly AppSettings _appSettings;

    public CertService(ILogger<CertService> logger, IOptions<AppSettings> options)
    {
        _logger = logger;
        _appSettings = options.Value;
    }
    
    public void EnsureAllDirectoriesExistAsync()
    {
        if(!Directory.Exists(_appSettings.ChallengeDir))
            Directory.CreateDirectory(_appSettings.ChallengeDir);
        
        if(!Directory.Exists(_appSettings.CertDir))
            Directory.CreateDirectory(_appSettings.CertDir);
        
        if(!Directory.Exists(_appSettings.AccDir))
            Directory.CreateDirectory(_appSettings.AccDir);
    }

    public async Task UpdateAllCertificatesAsync()
    {
        foreach(var profile in _appSettings.Profiles)
        {
            _logger.LogInformation($"Checking profile {profile.Name}, Domains: {string.Join(", ", profile.Domains)}");
            try
            {
                await UpdateCertificateAsync(profile);
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Error updating certificate for {profile.Name}");
            }
        }
        
        _logger.LogInformation("Finished updating profiles");
    }
    
    private async Task UpdateCertificateAsync(Profile profile)
    {
        //_options.EnsureValid();
        
        var certFile = Path.Combine(_appSettings.CertDir, $"{profile.Domains.First()}.crt");
        if (File.Exists(certFile))
        {
            var exitingCert = X509CertificateLoader.LoadCertificateFromFile(certFile);
            var daysToExpire = exitingCert.NotAfter.Subtract(DateTime.Now).TotalDays;
            _logger.LogInformation($"Current cert expires in {daysToExpire} day(s)");
            if (daysToExpire > 7)
            {
                _logger.LogInformation($"Certificate is valid to {exitingCert.NotAfter}. No need to renew.");
                return;
            }
        }
        
        _logger.LogInformation($"Certificate needs to be renewed");
        
        var acc = await GetAcmeContextAsync();

        var order = await acc.NewOrder(profile.Domains.ToArray());

        foreach(var authContext in await order.Authorizations())
            await AuthorizeAsync(authContext);

        
        var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);
        var cert = await order.Generate(new CsrInfo()
        {
            CountryName = "CZ",
            State = "",
            Locality = "Prague",
            Organization = "artipa.software",
            OrganizationUnit = "",
            //CommonName = _options.Domains.First()
        }, privateKey, retryCount:5);

        foreach(var domain in profile.Domains)
            await ExportCertificate(domain, cert, privateKey);
    }
    
    private async Task AuthorizeAsync(IAuthorizationContext authContext)
    {
        _logger.LogInformation("Sending authorization request");
        
        var httpChallenge = await authContext.Http();
        var keyAuthz = httpChallenge.KeyAuthz;
        
        _logger.LogInformation($"  Token: {httpChallenge.Token}");
        _logger.LogInformation($"  File:  /.well-known/acme-challenge/{httpChallenge.Token}");
        _logger.LogInformation($"  Auth:  {keyAuthz}");

        var filePath = Path.Combine(_appSettings.ChallengeDir, httpChallenge.Token);
        await File.WriteAllTextAsync(filePath, keyAuthz);
        
        _logger.LogInformation($"Challenge saved to {filePath}");

        _logger.LogInformation("Waiting for challenge validation");
        
        var result = await httpChallenge.Validate();
        
        var maxWaitCounter = 60;
        while(result.Status == ChallengeStatus.Pending)
        {
            await Task.Delay(1000);
            Console.Write("."); 
            result = await httpChallenge.Resource();
            maxWaitCounter--;
            if (maxWaitCounter != 0) continue;
            var message =
                $"Error: Timed out while waiting for the domain result to change from pending to another value: {httpChallenge.Token}";
            throw new TimeoutException(message);
        }
        
        _logger.LogInformation($"  Result.Status: {result.Status}");
        _logger.LogInformation($"  Result.Url: {result.Url}");
        
        if(result.Error != null)
            _logger.LogInformation($"  Result.Error: {result.Error.Detail}");
        
        if(result.Status != ChallengeStatus.Valid)
            throw new Exception("Challenge validation failed");
    }

    private async Task ExportCertificate(string domain, CertificateChain? cert, IKey privateKey)
    {
        _logger.LogInformation($"Export certificate for {domain}");
        
        var fileNameBase = Path.Combine(_appSettings.CertDir, domain);

        if (File.Exists($"{fileNameBase}.crt"))
        {
            _logger.LogInformation("Backing up existing CRT");
            File.Copy($"{fileNameBase}.crt", $"{fileNameBase}_{DateTime.Now:yyyyMMddHHmms}.crt");
        }

        if (File.Exists($"{fileNameBase}.pfx"))
        {
            _logger.LogInformation("Backing up existing PFX");
            File.Copy($"{fileNameBase}.pfx", $"{fileNameBase}_{DateTime.Now:yyyyMMddHHmms}.pfx");
        }

        // Export CRT
        _logger.LogInformation("Exporting CRT");
        await File.WriteAllTextAsync($"{fileNameBase}.crt", cert.ToPem());

        // Export PFX
        _logger.LogInformation("Exporting PFX");
        var pfxBuilder = cert.ToPfx(privateKey);
        var pfx = pfxBuilder.Build(domain, "");
        await File.WriteAllBytesAsync($"{fileNameBase}.pfx", pfx);
    }
    
    private async Task<AcmeContext> GetAcmeContextAsync()
    {
        var fileName = $"{_appSettings.Email}{(_appSettings.IsStaging ? "_staging" : "")}.pem";
        var filePath = Path.Combine(_appSettings.AccDir, fileName);
        
        AcmeContext context = null;
        
        if (File.Exists(filePath))
        {
            // Load the saved account key
            var accountKey = KeyFactory.FromPem(await File.ReadAllTextAsync(filePath));
            context = new AcmeContext(GetServerUri(), accountKey);
            await context.Account();
            return context;
        }
            
        context = new AcmeContext(GetServerUri());
        var account = await context.NewAccount(_appSettings.Email, true);

        // Save the account key for later use
        var pemKey = context.AccountKey.ToPem();
        await File.WriteAllTextAsync(filePath, pemKey);
        
        return context;
    }
    
    private Uri GetServerUri()
    {
        return !_appSettings.IsStaging 
            ? WellKnownServers.LetsEncryptV2 
            : WellKnownServers.LetsEncryptStagingV2;
    }

    
}