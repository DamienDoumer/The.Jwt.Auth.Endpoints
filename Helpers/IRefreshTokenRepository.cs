namespace Jwt.Auth.Endpoints.Helpers;

public interface IRefreshTokenRepository
{
    Task<bool> SaveRefreshToken(string userId, string refreshToken, DateTime expiryTime);
    Task<bool> DeleteRefreshToken(string userId, string refreshToken);
    Task<(string refreshToken, DateTime expiryTime)> GetRefreshToken(string userId);
}
