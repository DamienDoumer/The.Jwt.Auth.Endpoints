using Microsoft.Extensions.Logging;
using The.Jwt.Auth.Endpoints.Endpoints.Requests;
using The.Jwt.Auth.Endpoints.Endpoints.Responses;
using The.Jwt.Auth.Endpoints.Extensions;
using The.Jwt.Auth.Endpoints.Helpers;
using The.Jwt.Auth.Endpoints.Helpers.Exceptions;
using The.Jwt.Auth.Endpoints.Settings;

namespace The.Jwt.Auth.Endpoints.Endpoints;

static internal class LoginEndpoint
{
    public const string Name = "Login";

    public static IEndpointRouteBuilder MapLoginEndpoint<TUser>(this IEndpointRouteBuilder app)
        where TUser : IdentityUser
    {
        app.MapPost(AuthConstants.LoginEndpoint, async (
                [FromBody] LoginRequestModel loginRequestModel,
                [FromServices] UserManager<TUser> userManager,
                [FromServices] SignInManager<TUser> signInManager,
                [FromServices] IJwtTokenProvider jwtProvider,
                [FromServices] ILogger<TUser> logger) =>
        {
            logger.LogInformation("Login attempt for email: {Email}", loginRequestModel.Email);

            var validationResult = loginRequestModel.ValidateModel();
            if (validationResult != null)
            {
                logger.LogWarning("Login validation failed for email: {Email}", loginRequestModel.Email);
                return validationResult.CreateValidationErrorResult();
            }

            try
            {
                var result = await signInManager.PasswordSignInAsync(loginRequestModel.Email,
                        loginRequestModel.Password, false, false);
                if (!result.Succeeded)
                {
                    logger.LogWarning("Failed login attempt for email: {Email}. Invalid credentials.", loginRequestModel.Email);
                    return Results.Problem(new ProblemDetails
                    {
                        Title = "Email or password not correct.",
                        Status = StatusCodes.Status401Unauthorized
                    });
                }

                var user = await userManager.FindByEmailAsync(loginRequestModel.Email);
                if (user is { EmailConfirmed: false })
                {
                    logger.LogWarning("Login attempt for unconfirmed email: {Email}, UserId: {UserId}",
                        loginRequestModel.Email, user.Id);
                    return Results.Problem(new ProblemDetails
                    {
                        Title = "Please confirm your email before logging in.",
                        Status = StatusCodes.Status401Unauthorized
                    });
                }

                var token = await jwtProvider.CreateToken(user!.Id);
                logger.LogInformation("User logged in successfully. Email: {Email}, UserId: {UserId}",
                    loginRequestModel.Email, user.Id);

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
                logger.LogWarning(e, "Login failed for email: {Email}. Error: {Message}",
                    loginRequestModel.Email, e.Message);
                return Results.Problem(new ProblemDetails
                {
                    Title = e.Message,
                    Status = e.StatusCode
                });
            }
            catch (Exception e)
            {
                logger.LogError(e, "Unexpected error during login for email: {Email}", loginRequestModel.Email);
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
}
