using AspNetCore.Jwt.Auth.Endpoints.Endpoints.Requests;
using AspNetCore.Jwt.Auth.Endpoints.Endpoints.Responses;
using AspNetCore.Jwt.Auth.Endpoints.Extensions;
using AspNetCore.Jwt.Auth.Endpoints.Helpers;
using AspNetCore.Jwt.Auth.Endpoints.Helpers.Exceptions;
using AspNetCore.Jwt.Auth.Endpoints.Settings;
using AspNetCore.Jwt.Auth.Endpoints.UseCases;
using Microsoft.Extensions.Options;

namespace AspNetCore.Jwt.Auth.Endpoints.Endpoints;

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
                [FromServices] IIdentityUserFactory<TUser> userFactory) =>
        {
            var validationResult = registerRequestModel.ValidateModel();
            if (validationResult != null)
            {
                return validationResult.CreateValidationErrorResult();
            }

            try
            {

                var user = await userManager.FindByEmailAsync(registerRequestModel.Email);
                if (user != null)
                    return Results.Problem(new ProblemDetails
                    {
                        Title = "User already exists.",
                        Status = StatusCodes.Status400BadRequest
                    });

                user = await userManager.Register(userFactory, registerRequestModel.FirstName,
                        registerRequestModel.LastName, registerRequestModel.Email, registerRequestModel.Password);

                var token = await jwtProvider.CreateToken(user.Id);
                return Results.Ok(AuthResponseModel.FromAuthToken(token));
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
