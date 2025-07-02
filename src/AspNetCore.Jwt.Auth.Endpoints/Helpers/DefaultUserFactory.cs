namespace AspNetCore.Jwt.Auth.Endpoints.Helpers;
internal class DefaultUserFactory : IIdentityUserFactory<IdentityUser>
{
    public IdentityUser CreateUser(string firstName, string secondName, string email, string? picture = null)
    {
        return CreateUser(email);
    }

    private IdentityUser CreateUser(string email)
    {
        return new IdentityUser
        {
            UserName = email,
            Email = email,
        };
    }
}
