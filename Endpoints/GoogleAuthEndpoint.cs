using Jwt.Auth.Endpoints.Endpoints.Responses;
using Jwt.Auth.Endpoints.Extensions;
using Jwt.Auth.Endpoints.Helpers;
using Jwt.Auth.Endpoints.UseCases;
using Microsoft.Extensions.Options;

namespace Jwt.Auth.Endpoints.Endpoints;

internal static class GoogleAuthEndpoint
{
    public const string Name = "GoogleSocialAuthentication";

    public static IEndpointRouteBuilder MapGoogleAuthenticationEndpoint<TUser>(this IEndpointRouteBuilder app)
        where TUser : IdentityUser, new()
    {
        app.MapPost(AuthConstants.GoogleEndpoint,
                async (
                    [FromBody] GoogleAuthRequestModel googleAuthRequest,
                    [FromServices] IServiceProvider serviceProvider) =>
                {
                    var firebaseToken = await FirebaseAdmin.Auth.FirebaseAuth.DefaultInstance
                        .VerifyIdTokenAsync(googleAuthRequest.Token);

                    var picture = firebaseToken.Claims[JwtRegisteredClaimNames.Picture]?.ToString();
                    var email = firebaseToken.Claims[JwtRegisteredClaimNames.Email]?.ToString();

                    var userFactory = serviceProvider.GetRequiredService<IIdentityUserFactory<TUser>>();
                    var configOptions = serviceProvider.GetRequiredService<IOptions<JwtAuthEndpointsConfigOptions>>();
                    var userManager = serviceProvider.GetRequiredService<UserManager<TUser>>();
                    var user = await userManager.FindByEmailAsync(email!);

                    if (user != null)
                    {
                        //User exists, create a token for this user

                    }

                    var displayName = firebaseToken.Claims["name"].ToString()!;
                    var names = displayName.Split(' ');
                    var result = await userManager.Signup(userFactory,
                            names.First(), names.Last(), email!, isSocialAuth: true);

                    return Results.Ok(result);
                })
        .WithName(Name)
        .AllowAnonymous()
        .Produces<AuthResponseModel>(StatusCodes.Status200OK)
        .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
        .WithTags(AuthEndpointExtentions.Tag);

        return app;
    }
}
