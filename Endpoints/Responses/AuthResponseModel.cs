namespace Jwt.Auth.Endpoints.Endpoints.Responses;
public class AuthResponseModel
{
    public string Token { get; set; } = string.Empty;
    public string RefreshToken { get; set; } = string.Empty;
    public DateTime ExpiresAt { get; set; }
    public int TokenExpiryIn { get; set; }
    public int RefreshTokenExpiryIn { get; set; }
}
