using AspNetCore.Jwt.Auth.Endpoints.Helpers;
using AspNetCore.Jwt.Auth.Endpoints.TestAPI.Data.Models;

namespace AspNetCore.Jwt.Auth.Endpoints.TestAPI.Data;

public class SimpleUserFactory : IIdentityUserFactory<ApplicationUser>
{
    public ApplicationUser CreateUser(string firstName, string secondName, string email, string? picture = null)
    {
        return new ApplicationUser
        {
            FirstName = firstName,
            LastName = secondName,
            Email = email,
            PictureUrl = picture ?? string.Empty,
            UserName = email
        };
    }
}
