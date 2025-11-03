using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using The.Jwt.Auth.Endpoints.Endpoints.Requests;
using The.Jwt.Auth.Endpoints.Endpoints.Responses;
using The.Jwt.Auth.Endpoints.Extensions;
using The.Jwt.Auth.Endpoints.Helpers;
using The.Jwt.Auth.Endpoints.Helpers.Exceptions;
using The.Jwt.Auth.Endpoints.Settings;
using The.Jwt.Auth.Endpoints.UseCases;

namespace The.Jwt.Auth.Endpoints.Endpoints;

internal static class GoogleAuthEndpoint
{
    public const string Name = "GoogleSocialAuthentication";

    public static IEndpointRouteBuilder MapGoogleAuthenticationEndpoint<TUser>(this IEndpointRouteBuilder app)
        where TUser : IdentityUser
    {
        app.MapPost(AuthConstants.GoogleEndpoint,
                async ([FromBody] GoogleAuthRequestModel googleAuthRequest,
                       [FromServices] IIdentityUserFactory<TUser> userFactory,
                       [FromServices] IOptions<JwtAuthEndpointsConfigOptions> configOptions,
                       [FromServices] UserManager<TUser> userManager,
                       [FromServices] IJwtTokenProvider jwtProvider,
                       [FromServices] IWelcomeActionService welcomeActionService,
                       [FromServices] ILogger<TUser> logger) =>
                {
                    logger.LogInformation("Google authentication attempt initiated");

                    var validationResult = googleAuthRequest.ValidateModel();
                    if (validationResult != null)
                    {
                        logger.LogWarning("Google authentication validation failed");
                        return validationResult.CreateValidationErrorResult();
                    }

                    try
                    {
                        logger.LogDebug("Verifying Firebase ID token");
                        var firebaseToken = await FirebaseAdmin.Auth.FirebaseAuth.DefaultInstance
                            .VerifyIdTokenAsync(googleAuthRequest.Token);

                        var picture = firebaseToken.Claims[JwtRegisteredClaimNames.Picture]?.ToString();
                        var email = firebaseToken.Claims[JwtRegisteredClaimNames.Email].ToString();

                        logger.LogInformation("Firebase token verified for email: {Email}", email);

                        var user = await userManager.FindByEmailAsync(email!);
                        AuthToken? token = null;

                        if (user != null)
                        {
                            logger.LogInformation("Existing user authenticated via Google. Email: {Email}, UserId: {UserId}",
                                email, user.Id);
                            token = await jwtProvider.CreateToken(user.Id);
                            return Results.Ok(AuthResponseModel.FromAuthToken(token));
                        }

                        logger.LogInformation("Creating new user from Google authentication. Email: {Email}", email);
                        var displayName = firebaseToken.Claims[JwtRegisteredClaimNames.Name].ToString()!;
                        var names = displayName.Split(' ', StringSplitOptions.RemoveEmptyEntries);
                        var result = await userManager.Register(userFactory,
                                names.First(), names.Last(), email!, isSocialAuth: true);

                        logger.LogInformation("New user created via Google authentication. Email: {Email}, UserId: {UserId}",
                            email, result.Id);

                        // Perform welcome actions for the new user
                        logger.LogDebug("Executing welcome actions for Google user: {UserId}", result.Id);
                        await welcomeActionService.PerformWelcomeActionsAsync(
                            result.Id,
                            result.Email!,
                            result.UserName!);

                        token = await jwtProvider.CreateToken(result.Id);
                        logger.LogInformation("Google authentication completed successfully. Email: {Email}, UserId: {UserId}",
                            email, result.Id);
                        return Results.Ok(AuthResponseModel.FromAuthToken(token));
                    }
                    catch (BaseException e)
                    {
                        logger.LogWarning(e, "Google authentication failed. Error: {Message}", e.Message);
                        return Results.Problem(new ProblemDetails
                        {
                            Title = e.Message,
                            Status = e.StatusCode
                        });
                    }
                    catch (Exception e)
                    {
                        if (e.Source == "FirebaseAdmin")
                        {
                            logger.LogWarning(e, "Firebase token verification failed. Error: {Message}", e.Message);
                            return Results.Problem(new ProblemDetails
                            {
                                Title = e.Message,
                                Status = StatusCodes.Status400BadRequest
                            });
                        }

                        logger.LogError(e, "Unexpected error during Google authentication");
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
