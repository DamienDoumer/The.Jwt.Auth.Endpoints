using AspNetCore.Jwt.Auth.Endpoints.Endpoints;
using AspNetCore.Jwt.Auth.Endpoints.Settings;
using Microsoft.Extensions.Options;

namespace AspNetCore.Jwt.Auth.Endpoints.Extensions;

public static class AuthEndpointExtentions
{
    public static IEndpointRouteBuilder MapAuthenticationEndpoints<TUser>(this IEndpointRouteBuilder builder) 
        where TUser : IdentityUser
    {
        var configOptions = builder.ServiceProvider.GetRequiredService<IOptions<JwtAuthEndpointsConfigOptions>>();
        
        var endpointBuilder = builder
            .MapLoginEndpoint<TUser>()
            .MapRegisterEndpoint<TUser>()
            .MapRefreshTokenEndpoint<TUser>()
            .MapEmailConfirmationEndpoint<TUser>()
            .MapForgotPasswordEndpoint<TUser>()
            .MapResetPasswordEndpoint<TUser>();

        if (configOptions.Value.GoogleFirebaseAuthOptions != null)
        {
            endpointBuilder.MapGoogleAuthenticationEndpoint<TUser>();
        }

        return builder;
    }

    public static string[] Tag { get; set; } = ["Authentication"];
}
