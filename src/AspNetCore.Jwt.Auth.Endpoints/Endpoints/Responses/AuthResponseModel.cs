namespace AspNetCore.Jwt.Auth.Endpoints.Endpoints.Responses;
public class AuthResponseModel
{
    public string Token { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public DateTimeOffset ExpiresAt { get; set; }
    public int TokenExpiryInMinutes { get; set; }
    public int RefreshTokenExpiryInMinutes { get; set; }
}
