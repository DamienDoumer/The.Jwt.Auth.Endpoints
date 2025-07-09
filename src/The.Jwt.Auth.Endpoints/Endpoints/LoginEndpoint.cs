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
                [FromServices] IJwtTokenProvider jwtProvider) =>
        {
            var validationResult = loginRequestModel.ValidateModel();
            if (validationResult != null)
            {
                return validationResult.CreateValidationErrorResult();
            }
            
            try
            {

                var result = await signInManager.PasswordSignInAsync(loginRequestModel.Email,
                        loginRequestModel.Password, false, false);
                if (!result.Succeeded)
                    return Results.Problem(new ProblemDetails
                    {
                        Title = "Email or password not correct.",
                        Status = StatusCodes.Status401Unauthorized
                    });

                var user = await userManager.FindByEmailAsync(loginRequestModel.Email);
                if (user is { EmailConfirmed: false })
                    return Results.Problem(new ProblemDetails
                    {
                        Title = "Please confirm your email before logging in.",
                        Status = StatusCodes.Status401Unauthorized
                    });

                var token = await jwtProvider.CreateToken(user!.Id);
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
                return Results.Problem(new ProblemDetails
                {
                    Title = e.Message,
                    Status = e.StatusCode
                });
            }
            catch (Exception e)
            {
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
