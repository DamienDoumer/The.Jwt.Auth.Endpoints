namespace AspNetCore.Jwt.Auth.Endpoints.Settings;

public class JwtSettings
{
    public string Secret { get; set; }
    public int TokenLifeSpanInMinutes { get; set; }
    public string Issuer { get; set; }
    public string Audience { get; set; }
    public int RefreshTokenLifeSpanInMinutes { get; set; }

    public JwtSettings()
    {
        Secret = string.Empty;
        Issuer = string.Empty;
        Audience = string.Empty;
    }
}
