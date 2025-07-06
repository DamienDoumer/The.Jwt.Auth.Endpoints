using AspNetCore.Jwt.Auth.Endpoints.Helpers;

namespace AspNetCore.Jwt.Auth.Endpoints.TestAPI.Data;

public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly ApplicationDbContext _applicationDbContext;

    public RefreshTokenRepository(ApplicationDbContext applicationDbContext)
    {
        _applicationDbContext = applicationDbContext;
    }

    public async Task<bool> AddOrUpdateRefreshToken(string userId, string refreshToken, DateTime expiryTime)
    {

    }

    public async Task<bool> DeleteRefreshToken(string userId, string refreshToken)
    {
        throw new NotImplementedException();
    }

    public async Task<(string refreshToken, DateTime expiryTime)> GetRefreshToken(string userId)
    {
        throw new NotImplementedException();
    }
}
