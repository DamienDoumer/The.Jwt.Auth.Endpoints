using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using The.Jwt.Auth.Endpoints.Endpoints.Requests;
using The.Jwt.Auth.Endpoints.Endpoints.Responses;
using The.Jwt.Auth.Endpoints.Extensions;
using The.Jwt.Auth.Endpoints.Helpers;
using The.Jwt.Auth.Endpoints.Helpers.Exceptions;
using The.Jwt.Auth.Endpoints.Settings;

namespace The.Jwt.Auth.Endpoints.Endpoints;

static internal class ForgotPasswordEndpoint
{
    public const string Name = "ForgotPassword";

    public static IEndpointRouteBuilder MapForgotPasswordEndpoint<TUser>(this IEndpointRouteBuilder app)
        where TUser : IdentityUser
    {
        app.MapPost(AuthConstants.ForgotPasswordEndpoint, async (
                [FromBody] ForgotPasswordRequestModel request,
                [FromServices] UserManager<TUser> userManager,
                [FromServices] IEmailSender<TUser> emailSender,
                [FromServices] IHttpContextAccessor httpContextAccessor,
                [FromServices] ILogger<TUser> logger) =>
            {
                logger.LogInformation("Password reset request for email: {Email}", request.Email);

                var resultMessage =
                    "If an account with that email exists, you will receive a password reset link shortly.";
                var validationResult = request.ValidateModel();
                if (validationResult != null)
                {
                    logger.LogWarning("Forgot password validation failed for email: {Email}", request.Email);
                    return validationResult.CreateValidationErrorResult();
                }

                try
                {
                    var user = await userManager.FindByEmailAsync(request.Email);
                    if (user == null)
                    {
                        // Don't reveal that the user does not exist, but log it
                        logger.LogInformation("Password reset requested for non-existent email: {Email}", request.Email);
                        return Results.Ok(new GenericResponseModel
                        {
                            Success = true,
                            Message = resultMessage
                        });
                    }

                    logger.LogInformation("Generating password reset token for user: {UserId}, Email: {Email}",
                        user.Id, request.Email);
                    var token = await userManager.GeneratePasswordResetTokenAsync(user);
                    var base64Token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));

                    logger.LogDebug("Sending password reset email to: {Email}", request.Email);
                    await emailSender.SendPasswordResetCodeAsync(user, request.Email, base64Token);

                    logger.LogInformation("Password reset email sent successfully to: {Email}", request.Email);
                    return Results.Ok(new GenericResponseModel
                    {
                        Success = true,
                        Message = resultMessage
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