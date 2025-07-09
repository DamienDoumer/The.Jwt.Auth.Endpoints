namespace The.Jwt.Auth.Endpoints.Helpers;

public interface IRefreshTokenRepository
{
    Task<bool> AddOrUpdateRefreshToken(string userId, string refreshToken, DateTime expiryTime);
    Task<bool> DeleteRefreshToken(string userId, string refreshToken);
    Task<(string refreshToken, DateTime expiryTime)> GetRefreshToken(string userId);
}
