using System.Security.Claims;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using The.Jwt.Auth.Endpoints.Endpoints.Requests;
using The.Jwt.Auth.Endpoints.Endpoints.Responses;
using The.Jwt.Auth.Endpoints.Extensions;
using The.Jwt.Auth.Endpoints.Helpers;
using The.Jwt.Auth.Endpoints.Helpers.Exceptions;
using The.Jwt.Auth.Endpoints.Settings;

namespace The.Jwt.Auth.Endpoints.Endpoints;

internal static class RefreshTokenEndpoint
{
    public const string Name = "RefreshToken";

    public static IEndpointRouteBuilder MapRefreshTokenEndpoint<TUser>(this IEndpointRouteBuilder app)
        where TUser : IdentityUser
    {
        app.MapPost(AuthConstants.RefreshEndpoint, async (
                [FromBody] RefreshTokenRequestModel requestModel,
                [FromServices] IRefreshTokenRepository refreshTokenRepository,
                [FromServices] IOptions<JwtAuthEndpointsConfigOptions> configOptions,
                [FromServices] UserManager<TUser> userManager,
                [FromServices] IJwtTokenProvider jwtProvider,
                [FromServices] ILogger<TUser> logger) =>
        {
            logger.LogInformation("Token refresh attempt initiated");

            var validationResult = requestModel.ValidateModel();
            if (validationResult != null)
            {
                logger.LogWarning("Token refresh validation failed");
                return validationResult.CreateValidationErrorResult();
            }

            try
            {
                logger.LogDebug("Validating refresh token");
                var user = await userManager.CheckRefreshToken(requestModel.AccessToken,
                    refreshTokenRepository, requestModel.RefreshToken, configOptions.Value.JwtSettings);

                logger.LogInformation("Refresh token validated successfully for user: {UserId}", user.Id);

                var token = await jwtProvider.CreateToken(user.Id);
                logger.LogInformation("New access token generated for user: {UserId}", user.Id);

                return Results.Ok(new AuthResponseModel
                {
                    ExpiresAt = DateTimeOffset.Now.AddMinutes(token.JwtTokenLifeSpanInMinute),
                    RefreshTokenExpiryInMinutes = token.RefreshTokenLifeSpanInMinutes,
                    RefreshToken = token.RefreshToken,
                    Token = token.JwtToken,
                    TokenExpiryInMinutes = token.JwtTokenLifeSpanInMinute
                });
            }
            catch (BaseException e)
            {
                logger.LogWarning(e, "Token refresh failed. Error: {Message}", e.Message);
                return Results.Problem(new ProblemDetails
                {
                    Title = e.Message,
                    Status = e.StatusCode
                });
            }
            catch (SecurityTokenMalformedException e)
            {
                logger.LogWarning(e, "Malformed security token provided for refresh");
                return Results.Problem(new ProblemDetails
                {
                    Title = e.Message,
                    Status = StatusCodes.Status400BadRequest
                });
            }
            catch (Exception e)
            {
                logger.LogError(e, "Unexpected error during token refresh");
                return Results.Problem(new ProblemDetails
                {
                    Title = e.Message,
                    Status = StatusCodes.Status500InternalServerError
                });
            }
        })
            .WithName(Name)
            .AllowAnonymous()
            .Produces<AuthResponseModel>(StatusCodes.Status200OK)
            .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
            .WithTags(AuthEndpointExtentions.Tag);

        return app;
    }

    public static async Task<TUser> CheckRefreshToken<TUser>(this UserManager<TUser> userManager,
        string jwtToken, IRefreshTokenRepository refreshTokenRepository,
        string refreshToken, JwtSettings jwtSettings) where TUser : IdentityUser
    {
        var claimPrincipal = GetPrincipalFromExpiredToken(jwtToken, jwtSettings);
        if (claimPrincipal == null || claimPrincipal.Identity == null)
        {
            throw new BadRequestException("Invalid JWT token passed to refresh.");
        }

        var userId = claimPrincipal.Claims.FirstOrDefault(c => c.Type == ClaimTypes.NameIdentifier)!.Value;
        var user = await userManager.FindByIdAsync(userId);
        var userRefreshToken = await refreshTokenRepository.GetRefreshToken(userId);

        if (user == null || refreshToken != userRefreshToken.refreshToken
            || userRefreshToken.expiryTime <= DateTime.Now)
        {
            throw new BadRequestException("Invalid Refresh token passed to refresh.");
        }

        return user;
    }

    private static ClaimsPrincipal? GetPrincipalFromExpiredToken(string? token, JwtSettings jwtSettings)
    {
        var tokenValidationParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings.Secret)),
            ValidateLifetime = false
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenValidationParameters, out SecurityToken securityToken);
        if (securityToken is not JwtSecurityToken jwtSecurityToken ||
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCultureIgnoreCase))
            throw new SecurityTokenException("Invalid token");

        return principal;
    }
}
