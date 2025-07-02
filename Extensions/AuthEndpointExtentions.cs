using Jwt.Auth.Endpoints.Endpoints;

namespace Jwt.Auth.Endpoints.Extensions;

public static class AuthEndpointExtentions
{
    public static IEndpointRouteBuilder MapAuthenticationEndpoints<TUser>(this IEndpointRouteBuilder builder) 
        where TUser : IdentityUser
    {
        builder.MapGoogleAuthenticationEndpoint<TUser>();

        return builder;
    }

    public static string[] Tag { get; set; } = { "Authentication" };
}
