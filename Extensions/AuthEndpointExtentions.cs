namespace Jwt.Auth.Endpoints.Extensions;

public static class AuthEndpointExtentions
{
    public static IEndpointRouteBuilder MapAuthenticationEndpoints(this IEndpointRouteBuilder builder)
    {

        return builder;
    }

    public static string[] Tag { get; set; } = { "Authentication" };
}
