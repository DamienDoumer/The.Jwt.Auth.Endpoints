using Microsoft.AspNetCore.WebUtilities;
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
            [FromServices] UserManager<TUser> userManager) =>
        {
            var validationResult = request.ValidateModel();
            if (validationResult != null)
            {
                return validationResult.CreateValidationErrorResult();
            }

            try
            {
                var user = await userManager.FindByEmailAsync(request.Email);
                if (user == null || !await userManager.IsEmailConfirmedAsync(user))
                {
                    return Results.Problem(new ProblemDetails
                    {
                        Title = "Invalid password reset request.",
                        Status = StatusCodes.Status400BadRequest
                    });
                }

                var code = Encoding.UTF8.GetString(WebEncoders.Base64UrlDecode(request.Token));
                var result = await userManager.ResetPasswordAsync(user, code, request.NewPassword);
                if (!result.Succeeded)
                {
                    var errors = string.Join(", ", result.Errors.Select(e => e.Description));
                    return Results.Problem(new ProblemDetails
                    {
                        Title = $"Password reset failed: {errors}",
                        Status = StatusCodes.Status400BadRequest
                    });
                }

                return Results.Ok(new GenericResponseModel
                {
                    Success = true,
                    Message = "Password has been successfully reset."
                });
            }
            catch (FormatException e)
            {
                return Results.Problem(new ProblemDetails
                {
                    Title = "The token is not valid",
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
        .Produces<GenericResponseModel>(StatusCodes.Status200OK)
        .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
        .WithTags(AuthEndpointExtentions.Tag);

        return app;
    }
}