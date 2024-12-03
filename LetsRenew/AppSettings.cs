namespace LetsRenew;

public class AppSettings
{
    public string ChallengeDir { get; set; }
    public string Email { get; set; }
    public string CertDir { get; set; }
    public string AccDir { get; set; }
    public bool IsStaging { get; set; }
    public IEnumerable<Profile> Profiles { get; set; } = new List<Profile>();
    
}