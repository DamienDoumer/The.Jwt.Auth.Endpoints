namespace Jwt.Auth.Endpoints.Settings;

public class JwtSettings
{
    public string Secret { get; set; }
    public int TokenLifeSpanInHours { get; set; }
    public string Issuer { get; set; }
    public string Audience { get; set; }
    public int RefreshTokenLifeSpanInDays { get; set; }

    public JwtSettings()
    {
        Secret = string.Empty;
        Issuer = string.Empty;
        Audience = string.Empty;
    }
}
