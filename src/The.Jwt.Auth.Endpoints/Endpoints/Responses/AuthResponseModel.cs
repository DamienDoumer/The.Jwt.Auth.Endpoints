using The.Jwt.Auth.Endpoints.Helpers;

namespace The.Jwt.Auth.Endpoints.Endpoints.Responses;

public class AuthResponseModel
{
    public string Token { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; set; }
    public int TokenExpiryInMinutes { get; set; }
    public int RefreshTokenExpiryInMinutes { get; set; }

    public static AuthResponseModel FromAuthToken(AuthToken token)
    {
        return new AuthResponseModel
        {
            ExpiresAt = DateTimeOffset.Now.AddMinutes(token.JwtTokenLifeSpanInMinute).ToUniversalTime(),
            RefreshTokenExpiryInMinutes = token.RefreshTokenLifeSpanInMinutes,
            RefreshToken = token.RefreshToken,
            Token = token.JwtToken,
            TokenExpiryInMinutes = token.JwtTokenLifeSpanInMinute
        };
    }
}
