using Jwt.Auth.Endpoints.Helpers;
using Jwt.Auth.Endpoints.Helpers.Exceptions;

namespace Jwt.Auth.Endpoints.UseCases;

internal static class SignupUseCaseExtension
{
    public static async Task<TUser> Signup<TUser>(
        this UserManager<TUser> userManager,
        IIdentityUserFactory<TUser> identityUserFactory,
        string firstName, string secondName, string email,
        string? password = null, string? picture = null, 
        bool isSocialAuth = false) where TUser : IdentityUser
    {
        
        var newUser = identityUserFactory.CreateUser(firstName, secondName, email, password);
        IdentityResult result = null!;

        //If it is social auth, we asume the auth provider already verified the user's email.
        if (!isSocialAuth)
        {
            newUser.EmailConfirmed = true;
        }

        if (!string.IsNullOrWhiteSpace(password))
        {
            result = await userManager.CreateAsync(newUser, password);
        }

        if (!result.Succeeded)
        {
            var errors = result.Errors.Select(e => e.Description).ToList();
            throw new BadRequestException(
                string.Join(", ", errors)
            );
        }

        return newUser;
    }
}
