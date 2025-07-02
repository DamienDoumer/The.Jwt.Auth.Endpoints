namespace Jwt.Auth.Endpoints.Helpers;

public interface IIdentityUserFactory<TUser> where TUser : IdentityUser
{
    TUser CreateUser(
        string firstName, string secondName, string email,
        string? picture = null);
}
