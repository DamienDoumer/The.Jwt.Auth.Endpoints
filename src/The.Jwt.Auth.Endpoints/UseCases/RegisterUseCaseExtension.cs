using The.Jwt.Auth.Endpoints.Helpers;
using The.Jwt.Auth.Endpoints.Helpers.Exceptions;

namespace The.Jwt.Auth.Endpoints.UseCases;

internal static class RegisterUseCaseExtension
{
    public static async Task<TUser> Register<TUser>(
        this UserManager<TUser> userManager,
        IIdentityUserFactory<TUser> identityUserFactory,
        string firstName, string secondName, string email,
        string? password = null, string? picture = null, 
        bool isSocialAuth = false) where TUser : IdentityUser
    {
        var newUser = identityUserFactory.CreateUser(firstName, secondName, email, password);
        IdentityResult result = null!;

        //If it is social auth, we assume the auth provider already verified the user's email.
        newUser.EmailConfirmed = isSocialAuth;

        if (!string.IsNullOrWhiteSpace(password))
        {
            result = await userManager.CreateAsync(newUser, password);
        }
        else
        {
            result = await userManager.CreateAsync(newUser);
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
