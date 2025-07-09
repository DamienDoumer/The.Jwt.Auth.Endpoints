using Microsoft.AspNetCore.WebUtilities;
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
                [FromServices] IHttpContextAccessor httpContextAccessor) =>
            {
                var resultMessage =
                    "If an account with that email exists, you will receive a password reset link shortly.";
                var validationResult = request.ValidateModel();
                if (validationResult != null)
                {
                    return validationResult.CreateValidationErrorResult();
                }

                try
                {
                    var user = await userManager.FindByEmailAsync(request.Email);
                    if (user == null)
                    {
                        // Don't reveal that the user does not exist
                        return Results.Ok(new GenericResponseModel
                        {
                            Success = true,
                            Message = resultMessage
                        });
                    }

                    var token = await userManager.GeneratePasswordResetTokenAsync(user);
                    var base64Token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(token));
                    
                    await emailSender.SendPasswordResetCodeAsync(user, request.Email, base64Token);

                    return Results.Ok(new GenericResponseModel
                    {
                        Success = true,
                        Message = resultMessage
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
        .Produces<GenericResponseModel>(StatusCodes.Status200OK)
        .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
        .WithTags(AuthEndpointExtentions.Tag);

        return app;
    }
}