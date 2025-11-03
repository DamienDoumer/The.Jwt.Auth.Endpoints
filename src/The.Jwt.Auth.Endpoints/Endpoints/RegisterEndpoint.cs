using System.Text.Encodings.Web;
using Microsoft.AspNetCore.WebUtilities;
using Microsoft.Extensions.Logging;
using The.Jwt.Auth.Endpoints.Endpoints.Requests;
using The.Jwt.Auth.Endpoints.Endpoints.Responses;
using The.Jwt.Auth.Endpoints.Extensions;
using The.Jwt.Auth.Endpoints.Helpers;
using The.Jwt.Auth.Endpoints.Helpers.Exceptions;
using The.Jwt.Auth.Endpoints.Settings;
using The.Jwt.Auth.Endpoints.UseCases;

namespace The.Jwt.Auth.Endpoints.Endpoints;

static internal class RegisterEndpoint
{
    public const string Name = "Register";

    public static IEndpointRouteBuilder MapRegisterEndpoint<TUser>(this IEndpointRouteBuilder app)
        where TUser : IdentityUser
    {
        app.MapPost(AuthConstants.RegisterEndpoint, async (
                [FromBody] RegisterRequestModel registerRequestModel,
                [FromServices] UserManager<TUser> userManager,
                [FromServices] IJwtTokenProvider jwtProvider,
                [FromServices] IIdentityUserFactory<TUser> userFactory,
                [FromServices] IEmailSender<TUser> emailSender,
                [FromServices] IHttpContextAccessor httpContextAccessor,
                [FromServices] IWelcomeActionService welcomeActionService,
                [FromServices] ILogger<TUser> logger) =>
        {
            logger.LogInformation("User registration attempt for email: {Email}", registerRequestModel.Email);

            var validationResult = registerRequestModel.ValidateModel();
            if (validationResult != null)
            {
                logger.LogWarning("Registration validation failed for email: {Email}", registerRequestModel.Email);
                return validationResult.CreateValidationErrorResult();
            }

            try
            {
                var user = await userManager.FindByEmailAsync(registerRequestModel.Email);
                if (user != null)
                {
                    logger.LogWarning("Registration attempt for existing email: {Email}", registerRequestModel.Email);
                    return Results.Problem(new ProblemDetails
                    {
                        Title = "User already exists.",
                        Status = StatusCodes.Status400BadRequest
                    });
                }

                user = await userManager.Register(userFactory, registerRequestModel.FirstName,
                        registerRequestModel.LastName, registerRequestModel.Email, registerRequestModel.Password);

                logger.LogInformation("User created successfully. Email: {Email}, UserId: {UserId}",
                    registerRequestModel.Email, user.Id);

                // Perform welcome actions for the new user
                logger.LogDebug("Executing welcome actions for user: {UserId}", user.Id);
                await welcomeActionService.PerformWelcomeActionsAsync(
                    user.Id,
                    user.Email!,
                    user.UserName!);

                var emailConfirmationToken = await userManager.GenerateEmailConfirmationTokenAsync(user);

                var httpContext = httpContextAccessor.HttpContext!;
                var base64Token = WebEncoders.Base64UrlEncode(Encoding.UTF8.GetBytes(emailConfirmationToken));
                var confirmationLink = $"{httpContext.Request.Scheme}://{httpContext.Request.Host}/" +
                                     $"{AuthConstants.EmailConfirmationEndpoint}?userId={user.Id}&token={base64Token}";

                logger.LogDebug("Sending confirmation email to: {Email}", user.Email);
                await emailSender.SendConfirmationLinkAsync(user, user.Email!,
                    HtmlEncoder.Default.Encode(confirmationLink));

                var token = await jwtProvider.CreateToken(user.Id);

                logger.LogInformation("User registration completed successfully. Email: {Email}, UserId: {UserId}",
                    registerRequestModel.Email, user.Id);

                return Results.Ok(new RegisterResponseModel
                {
                    Message = "Registration successful. Please check your email for confirmation instructions.",
                    RequiresEmailConfirmation = true,
                    AuthResponse = AuthResponseModel.FromAuthToken(token)
                });
            }
            catch (BaseException e)
            {
                logger.LogWarning(e, "Registration failed for email: {Email}. Error: {Message}",
                    registerRequestModel.Email, e.Message);
                return Results.Problem(new ProblemDetails
                {
                    Title = e.Message,
                    Status = e.StatusCode
                });
            }
            catch (Exception e)
            {
                logger.LogError(e, "Unexpected error during registration for email: {Email}",
                    registerRequestModel.Email);
                return Results.Problem(new ProblemDetails
                {
                    Title = e.Message,
                    Status = StatusCodes.Status500InternalServerError
                });
            }
        })
            .WithName(Name)
            .AllowAnonymous()
            .Produces<RegisterResponseModel>(StatusCodes.Status200OK)
            .Produces<ProblemDetails>(StatusCodes.Status400BadRequest)
            .WithTags(AuthEndpointExtentions.Tag);

        return app;
    }
}
