using AspNetCore.Jwt.Auth.Endpoints.Helpers;
using AspNetCore.Jwt.Auth.Endpoints.Settings;
using FirebaseAdmin;
using Google.Apis.Auth.OAuth2;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;

namespace AspNetCore.Jwt.Auth.Endpoints.Extensions;

public static class IdentityBuilderExtensions
{
    public static IEndpointRouteBuilder MapJwtAuthEndpoints<TUser>(this IEndpointRouteBuilder builder)
        where TUser : IdentityUser
    {
        ArgumentNullException.ThrowIfNull(builder);

        RouteGroupBuilder group = builder.MapGroup("");
        group.MapAuthenticationEndpoints<TUser>();

        return builder;
    }

    public static IServiceCollection AddJwtAuthEndpoints<TUser>(this IServiceCollection services,
        Action<JwtAuthEndpointsConfigOptions> config) where TUser : IdentityUser, new()
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(config);

        services.AddSingleton<IValidateOptions<JwtAuthEndpointsConfigOptions>, JwtAuthEndpointsConfigValidator>();
        services.TryAddSingleton<IIdentityUserFactory<IdentityUser>, DefaultUserFactory>();
        services.TryAddSingleton<IJwtTokenProvider, DefaultJwtTokenProvider>();
        var builder = services.AddOptions<JwtAuthEndpointsConfigOptions>();
        var opts = new JwtAuthEndpointsConfigOptions();

        builder.Configure(config);

        services.PostConfigure<JwtAuthEndpointsConfigOptions>(options =>
        {
            if (options.GoogleFirebaseAuthOptions != null)
            {
                FirebaseApp.Create(options.GoogleFirebaseAuthOptions);
            }
            
            services.AddAuthentication(opt =>
            {
                opt.DefaultAuthenticateScheme = opt.DefaultAuthenticateScheme;
                opt.DefaultChallengeScheme = opt.DefaultChallengeScheme;
                opt.DefaultScheme = opt.DefaultScheme;
                opt.DefaultForbidScheme = opt.DefaultForbidScheme;
                opt.DefaultSignInScheme = opt.DefaultSignInScheme;
                opt.DefaultSignOutScheme = opt.DefaultSignOutScheme;
                opt.RequireAuthenticatedSignIn = opt.RequireAuthenticatedSignIn;
            })
            .AddJwtBearer(opt =>
            {
                opt.RequireHttpsMetadata = options.JwtAuthSchemeOptions.RequireHttpsMetadata;
                opt.MetadataAddress = options.JwtAuthSchemeOptions.MetadataAddress;
                opt.Authority = options.JwtAuthSchemeOptions.Authority;
                opt.Audience = options.JwtAuthSchemeOptions.Audience;
                opt.Challenge = options.JwtAuthSchemeOptions.Challenge;
                opt.Events = options.JwtAuthSchemeOptions.Events;
                opt.BackchannelHttpHandler = options.JwtAuthSchemeOptions.BackchannelHttpHandler;
                opt.Backchannel = options.JwtAuthSchemeOptions.Backchannel;
                opt.BackchannelTimeout = options.JwtAuthSchemeOptions.BackchannelTimeout;
                opt.Configuration = options.JwtAuthSchemeOptions.Configuration;
                opt.ConfigurationManager = options.JwtAuthSchemeOptions.ConfigurationManager;
                opt.RefreshOnIssuerKeyNotFound = options.JwtAuthSchemeOptions.RefreshOnIssuerKeyNotFound;
                opt.TokenValidationParameters = options.JwtAuthSchemeOptions.TokenValidationParameters;
                opt.SaveToken = options.JwtAuthSchemeOptions.SaveToken;
                opt.IncludeErrorDetails = options.JwtAuthSchemeOptions.IncludeErrorDetails;
                opt.MapInboundClaims = options.JwtAuthSchemeOptions.MapInboundClaims;
                opt.AutomaticRefreshInterval = options.JwtAuthSchemeOptions.AutomaticRefreshInterval;
                opt.RefreshInterval = options.JwtAuthSchemeOptions.RefreshInterval;
                opt.UseSecurityTokenValidators = options.JwtAuthSchemeOptions.UseSecurityTokenValidators;
                // TokenHandlers is a list, so copy elements if needed
                opt.TokenHandlers.Clear();
                foreach (var handler in options.JwtAuthSchemeOptions.TokenHandlers)
                {
                    opt.TokenHandlers.Add(handler);
                }
            });
        });

        return services;
    }
}
