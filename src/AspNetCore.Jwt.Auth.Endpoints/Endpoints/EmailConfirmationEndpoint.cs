using AspNetCore.Jwt.Auth.Endpoints.Endpoints.Responses;
using AspNetCore.Jwt.Auth.Endpoints.Extensions;
using AspNetCore.Jwt.Auth.Endpoints.Helpers.Exceptions;
using AspNetCore.Jwt.Auth.Endpoints.Settings;
using Microsoft.AspNetCore.WebUtilities;

namespace AspNetCore.Jwt.Auth.Endpoints.Endpoints;

internal static class EmailConfirmationEndpoint
{
    public const string Name = "EmailConfirmation";

    public static IEndpointRouteBuilder MapEmailConfirmationEndpoint<TUser>(this IEndpointRouteBuilder app)
        where TUser : IdentityUser
    {
        app.MapGet(AuthConstants.EmailConfirmationEndpoint,
                async ([FromQuery] string userId, [FromQuery] string token,
                       [FromServices] UserManager<TUser> userManager) =>
                {
                    try
                    {
                        var user = await userManager.FindByIdAsync(userId);
                        if (user == null)
                        {
                            return Results.Problem(new ProblemDetails
                            {
                                Title = "User not found.",
                                Status = StatusCodes.Status404NotFound
                            });
                        }

                        if (await userManager.IsEmailConfirmedAsync(user))
                        {
                            return Results.Ok(new EmailConfirmationResponseModel
                            {
                                Success = true,
                                Message = "Email is already confirmed."
                            });
                        }

                        var decodedToken = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(token));
                        var result = await userManager.ConfirmEmailAsync(user, decodedToken);
                        if (result.Succeeded)
                        {
                            return Results.Ok(new EmailConfirmationResponseModel
                            {
                                Success = true,
                                Message = "Email confirmed successfully."
                            });
                        }

                        var errors = result.Errors.Select(e => e.Description).ToList();
                        return Results.Problem(new ProblemDetails
                        {
                            Title = string.Join(", ", errors),
                            Status = StatusCodes.Status400BadRequest
                        });
                    }
                    catch (FormatException e)
                    {
                        return Results.Problem(new ProblemDetails
                        {
                            Title = "The token is invalid.",
                            Status = StatusCodes.Status400BadRequest
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
        .Produces<EmailConfirmationResponseModel>(StatusCodes.Status200OK)
        .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
        .Produces<ProblemDetails>(StatusCodes.Status404NotFound)
        .WithTags(AuthEndpointExtentions.Tag);

        return app;
    }
}