namespace AspNetCore.Jwt.Auth.Endpoints.Helpers;
public interface IJwtTokenProvider
{
    Task<AuthToken> CreateToken(string userId);
}
