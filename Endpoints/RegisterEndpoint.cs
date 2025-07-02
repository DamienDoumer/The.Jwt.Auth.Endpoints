using Jwt.Auth.Endpoints.Endpoints.Responses;
using Jwt.Auth.Endpoints.Extensions;
using Jwt.Auth.Endpoints.Helpers;
using Jwt.Auth.Endpoints.Helpers.Exceptions;
using Jwt.Auth.Endpoints.UseCases;
using Microsoft.Extensions.Options;
using System.ComponentModel.DataAnnotations;

namespace Jwt.Auth.Endpoints.Endpoints;

static internal class RegisterEndpoint
{
    public const string Name = "Register";

    public static IEndpointRouteBuilder MapRegisterEndpoint<TUser>(this IEndpointRouteBuilder app)
        where TUser : IdentityUser
    {
        app.MapPost(AuthConstants.RegisterEndpoint, async (
                [FromBody] RegisterRequestModel registerRequestModel,
                [FromServices] IServiceProvider serviceProvider) =>
        {
            //Prior to .NET 10, validation won't work properly on minimal APIs
            //TODO: Use Email validation attributes to validate this.
            //EmailAddressAttribute emailAddressAttribute = new EmailAddressAttribute();

            try
            {
                var refreshTokenRepository = serviceProvider.GetRequiredService<IRefreshTokenRepository>();
                var configOptions = serviceProvider.GetRequiredService<IOptions<JwtAuthEndpointsConfigOptions>>();
                var userManager = serviceProvider.GetRequiredService<UserManager<TUser>>();
                var signInManager = serviceProvider.GetRequiredService<SignInManager<TUser>>();
                var jwtProvider = serviceProvider.GetRequiredService<IJwtTokenProvider>();
                var userFactory = serviceProvider.GetRequiredService<IIdentityUserFactory<TUser>>();

                var result = await signInManager.PasswordSignInAsync(registerRequestModel.Email,
                        registerRequestModel.Password, false, false);
                if (!result.Succeeded)
                    return Results.Problem(new ProblemDetails
                    {
                        Title = "Email or password not correct.",
                        Status = StatusCodes.Status401Unauthorized
                    });

                var user = await userManager.FindByEmailAsync(registerRequestModel.Email);
                if (user != null)
                    return Results.Problem(new ProblemDetails
                    {
                        Title = "User already exists.",
                        Status = StatusCodes.Status400BadRequest
                    });

                user = await userManager.Register(userFactory, registerRequestModel.FirstName,
                        registerRequestModel.LastName, registerRequestModel.Email, registerRequestModel.Password);

                //TODO: In stable versions, implement Email confirmation flow, and remove this:
                user.EmailConfirmed = true;
                await userManager.UpdateAsync(user);

                var token = await jwtProvider.CreateToken(user.Id);
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
