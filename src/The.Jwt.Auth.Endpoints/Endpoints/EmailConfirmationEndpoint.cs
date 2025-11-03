using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using The.Jwt.Auth.Endpoints.Endpoints.Responses;
using The.Jwt.Auth.Endpoints.Extensions;
using The.Jwt.Auth.Endpoints.Helpers.Exceptions;
using The.Jwt.Auth.Endpoints.Settings;

namespace The.Jwt.Auth.Endpoints.Endpoints;

internal static class EmailConfirmationEndpoint
{
    public const string Name = "EmailConfirmation";

    public static IEndpointRouteBuilder MapEmailConfirmationEndpoint<TUser>(this IEndpointRouteBuilder app)
        where TUser : IdentityUser
    {
        app.MapGet(AuthConstants.EmailConfirmationEndpoint,
                async ([FromQuery] string userId, [FromQuery] string token,
                       [FromServices] UserManager<TUser> userManager,
                       [FromServices] ILogger<TUser> logger) =>
                {
                    logger.LogInformation("Email confirmation attempt for userId: {UserId}", userId);

                    try
                    {
                        var user = await userManager.FindByIdAsync(userId);
                        if (user == null)
                        {
                            logger.LogWarning("Email confirmation failed. User not found: {UserId}", userId);
                            return Results.Problem(new ProblemDetails
                            {
                                Title = "User not found.",
                                Status = StatusCodes.Status404NotFound
                            });
                        }

                        if (await userManager.IsEmailConfirmedAsync(user))
                        {
                            logger.LogInformation("Email already confirmed for user: {UserId}, Email: {Email}",
                                userId, user.Email);
                            return Results.Ok(new EmailConfirmationResponseModel
                            {
                                Success = true,
                                Message = "Email is already confirmed."
                            });
                        }

                        logger.LogDebug("Processing email confirmation token for user: {UserId}", userId);
                        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
                        var result = await userManager.ConfirmEmailAsync(user, decodedToken);
                        if (result.Succeeded)
                        {
                            logger.LogInformation("Email confirmed successfully for user: {UserId}, Email: {Email}",
                                userId, user.Email);
                            return Results.Ok(new EmailConfirmationResponseModel
                            {
                                Success = true,
                                Message = "Email confirmed successfully."
                            });
                        }

                        var errors = result.Errors.Select(e => e.Description).ToList();
                        logger.LogWarning("Email confirmation failed for user: {UserId}. Errors: {Errors}",
                            userId, string.Join(", ", errors));
                        return Results.Problem(new ProblemDetails
                        {
                            Title = string.Join(", ", errors),
                            Status = StatusCodes.Status400BadRequest
                        });
                    }
                    catch (FormatException e)
                    {
                        logger.LogWarning(e, "Invalid email confirmation token format for user: {UserId}", userId);
                        return Results.Problem(new ProblemDetails
                        {
                            Title = "The token is invalid.",
                            Status = StatusCodes.Status400BadRequest
                        });
                    }
                    catch (BaseException e)
                    {
                        logger.LogWarning(e, "Email confirmation failed for user: {UserId}. Error: {Message}",
                            userId, e.Message);
                        return Results.Problem(new ProblemDetails
                        {
                            Title = e.Message,
                            Status = e.StatusCode
                        });
                    }
                    catch (Exception e)
                    {
                        logger.LogError(e, "Unexpected error during email confirmation for user: {UserId}", userId);
                        return Results.Problem(new ProblemDetails
                        {
                            Title = e.Message,
                            Status = StatusCodes.Status500InternalServerError
                        });
                    }
                })
        .WithName(Name)
        .AllowAnonymous()
        .Produces<EmailConfirmationResponseModel>(StatusCodes.Status200OK)
        .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
        .Produces<ProblemDetails>(StatusCodes.Status404NotFound)
        .WithTags(AuthEndpointExtentions.Tag);

        return app;
    }
}