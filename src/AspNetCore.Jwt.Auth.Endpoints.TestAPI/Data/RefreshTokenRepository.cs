using AspNetCore.Jwt.Auth.Endpoints.Helpers;
using Microsoft.EntityFrameworkCore;

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
        var user = await _applicationDbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
        if (user == null)
            return false;

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = expiryTime;
        
        await _applicationDbContext.SaveChangesAsync();
        return true;
    }

    public async Task<bool> DeleteRefreshToken(string userId, string refreshToken)
    {
        var user = await _applicationDbContext.Users.FirstOrDefaultAsync(u => u.Id == userId && u.RefreshToken == refreshToken);
        if (user == null)
            return false;

        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = DateTime.MinValue;
        
        await _applicationDbContext.SaveChangesAsync();
        return true;
    }

    public async Task<(string refreshToken, DateTime expiryTime)> GetRefreshToken(string userId)
    {
        var user = await _applicationDbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
        if (user == null || string.IsNullOrEmpty(user.RefreshToken))
            return (null!, DateTime.MinValue);

        return (user.RefreshToken, user.RefreshTokenExpiryTime);
    }
}
