using AspNetCore.Jwt.Auth.Endpoints.Endpoints;

namespace AspNetCore.Jwt.Auth.Endpoints.Extensions;

public static class AuthEndpointExtentions
{
    public static IEndpointRouteBuilder MapAuthenticationEndpoints<TUser>(this IEndpointRouteBuilder builder) 
        where TUser : IdentityUser
    {
        builder
            .MapGoogleAuthenticationEndpoint<TUser>()
            .MapLoginEndpoint<TUser>()
            .MapRegisterEndpoint<TUser>()
            .MapRefreshTokenEndpoint<TUser>();

        return builder;
    }

    public static string[] Tag { get; set; } = { "Authentication" };
}
