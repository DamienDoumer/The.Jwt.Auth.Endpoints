using The.Jwt.Auth.Endpoints.Helpers;
using The.Jwt.Auth.Endpoints.TestApi.Data.Models;

namespace The.Jwt.Auth.Endpoints.TestApi.Data;

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
