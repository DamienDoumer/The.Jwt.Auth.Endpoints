﻿using System.Security.Claims;
using System.Security.Cryptography;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using The.Jwt.Auth.Endpoints.Settings;

namespace The.Jwt.Auth.Endpoints.Helpers;

public class DefaultJwtTokenProvider<TUser> : IJwtTokenProvider where TUser : IdentityUser
{
    private readonly UserManager<TUser> _userManager;
    private readonly JwtAuthEndpointsConfigOptions _jwtOptions;
    private readonly IRefreshTokenRepository _refreshTokenRepository;

    public DefaultJwtTokenProvider(UserManager<TUser> userManager, 
        IOptions<JwtAuthEndpointsConfigOptions> jwtOptions,
        IRefreshTokenRepository refreshTokenRepository)
    {
        _userManager = userManager;
        _jwtOptions = jwtOptions.Value;
        _refreshTokenRepository = refreshTokenRepository;
    }

    public async Task<AuthToken> CreateToken(string userId)
    {
        ArgumentNullException.ThrowIfNull(userId);

        var user = await _userManager.FindByIdAsync(userId);
        if (user == null)
            throw new ArgumentNullException(nameof(user));

        var issuedAt = DateTimeOffset.Now;
        var roles = await _userManager.GetRolesAsync(user!);

        var claims = new List<Claim>
            {
                new Claim(JwtRegisteredClaimNames.Sub, user!.Id),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Iat, issuedAt.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64),
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Email, user.Email!)
            };

        foreach (var role in roles)
        {
            claims.Add(new Claim(ClaimTypes.Role, role));
        }

        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtOptions.JwtSettings.Secret));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expiry = TimeSpan.FromMinutes(_jwtOptions.JwtSettings.TokenLifeSpanInMinutes);
        var expires = issuedAt.Add(expiry);

        var token = new JwtSecurityToken(
            issuer: _jwtOptions.JwtSettings.Issuer,
            audience: _jwtOptions.JwtSettings.Audience,
            claims: claims,
            notBefore: issuedAt.DateTime.ToUniversalTime(),
            expires: expires.DateTime.ToUniversalTime(),
            signingCredentials: creds
        );

        var refreshToken = GenerateRefreshToken();
        var refreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(_jwtOptions.JwtSettings.RefreshTokenLifeSpanInMinutes);

        await _refreshTokenRepository.AddOrUpdateRefreshToken(userId, refreshToken, refreshTokenExpiryTime);

        var tokenHandler = new JwtSecurityTokenHandler();
        var encryptedToken = tokenHandler.WriteToken(token);
        var authResponse = new AuthToken(encryptedToken,
                refreshToken, _jwtOptions.JwtSettings.TokenLifeSpanInMinutes,
                _jwtOptions.JwtSettings.RefreshTokenLifeSpanInMinutes);

        return authResponse;
    }

    private static string GenerateRefreshToken()
    {
        var randomNumber = new byte[64];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);
        return Convert.ToBase64String(randomNumber);
    }
}
