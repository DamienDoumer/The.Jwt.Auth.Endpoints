namespace Jwt.Auth.Endpoints.Helpers;

public class AuthToken
{
    public string JwtToken { get; set; }
    public string RefreshToken { get; set; }
    public int JwtTokenLifeSpanInMinute { get; set; }
    public int RefreshTokenLifeSpanInMinutes  { get; set; }

    public AuthToken(string jwtToken, string refreshToken, 
        int jwtTokenLifeSpanInMinute, int refreshTokenLifeSpanInMinutes)
    {
        JwtToken = jwtToken;
        RefreshToken = refreshToken;
        JwtTokenLifeSpanInMinute = jwtTokenLifeSpanInMinute;
        RefreshTokenLifeSpanInMinutes = refreshTokenLifeSpanInMinutes;
    }
}
