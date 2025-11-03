using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using The.Jwt.Auth.Endpoints.Endpoints.Requests;
using The.Jwt.Auth.Endpoints.Endpoints.Responses;
using The.Jwt.Auth.Endpoints.Extensions;
using The.Jwt.Auth.Endpoints.Helpers;
using The.Jwt.Auth.Endpoints.Helpers.Exceptions;
using The.Jwt.Auth.Endpoints.Settings;

namespace The.Jwt.Auth.Endpoints.Endpoints;

static internal class ResetPasswordEndpoint
{
    public const string Name = "ResetPassword";

    public static IEndpointRouteBuilder MapResetPasswordEndpoint<TUser>(this IEndpointRouteBuilder app)
        where TUser : IdentityUser
    {
        app.MapPost(AuthConstants.ResetPasswordEndpoint, async (
            [FromBody] ResetPasswordRequestModel request,
            [FromServices] UserManager<TUser> userManager,
            [FromServices] ILogger<TUser> logger) =>
        {
            logger.LogInformation("Password reset attempt for email: {Email}", request.Email);

            var validationResult = request.ValidateModel();
            if (validationResult != null)
            {
                logger.LogWarning("Reset password validation failed for email: {Email}", request.Email);
                return validationResult.CreateValidationErrorResult();
            }

            try
            {
                var user = await userManager.FindByEmailAsync(request.Email);
                if (user == null || !await userManager.IsEmailConfirmedAsync(user))
                {
                    logger.LogWarning("Invalid password reset request for email: {Email}. User not found or email not confirmed.",
                        request.Email);
                    return Results.Problem(new ProblemDetails
                    {
                        Title = "Invalid password reset request.",
                        Status = StatusCodes.Status400BadRequest
                    });
                }

                logger.LogDebug("Processing password reset for user: {UserId}, Email: {Email}",
                    user.Id, request.Email);
                var code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token));
                var result = await userManager.ResetPasswordAsync(user, code, request.NewPassword);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    logger.LogWarning("Password reset failed for user: {UserId}, Email: {Email}. Errors: {Errors}",
                        user.Id, request.Email, errors);
                    return Results.Problem(new ProblemDetails
                    {
                        Title = $"Password reset failed: {errors}",
                        Status = StatusCodes.Status400BadRequest
                    });
                }

                logger.LogInformation("Password reset successfully for user: {UserId}, Email: {Email}",
                    user.Id, request.Email);
                return Results.Ok(new GenericResponseModel
                {
                    Success = true,
                    Message = "Password has been successfully reset."
                });
            }
            catch (FormatException e)
            {
                logger.LogWarning(e, "Invalid password reset token format for email: {Email}", request.Email);
                return Results.Problem(new ProblemDetails
                {
                    Title = "The token is not valid",
                    Status = StatusCodes.Status400BadRequest
                });
            }
            catch (BaseException e)
            {
                logger.LogWarning(e, "Password reset failed for email: {Email}. Error: {Message}",
                    request.Email, e.Message);
                return Results.Problem(new ProblemDetails
                {
                    Title = e.Message,
                    Status = e.StatusCode
                });
            }
            catch (Exception e)
            {
                logger.LogError(e, "Unexpected error during password reset for email: {Email}", request.Email);
                return Results.Problem(new ProblemDetails
                {
                    Title = e.Message,
                    Status = StatusCodes.Status500InternalServerError
                });
            }
        })
        .WithName(Name)
        .AllowAnonymous()
        .Produces<GenericResponseModel>(StatusCodes.Status200OK)
        .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
        .WithTags(AuthEndpointExtentions.Tag);

        return app;
    }
}