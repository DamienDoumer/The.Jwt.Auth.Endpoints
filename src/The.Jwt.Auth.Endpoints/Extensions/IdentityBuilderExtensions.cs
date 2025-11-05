using FirebaseAdmin;
using Microsoft.Extensions.DependencyInjection.Extensions;
using Microsoft.Extensions.Options;
using The.Jwt.Auth.Endpoints.Helpers;
using The.Jwt.Auth.Endpoints.Settings;

namespace The.Jwt.Auth.Endpoints.Extensions;

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
        Action<JwtAuthEndpointsConfigOptions> configureOptions) where TUser : IdentityUser, new()
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(configureOptions);

        services.Configure(configureOptions);
        services.AddSingleton<IValidateOptions<JwtAuthEndpointsConfigOptions>, JwtAuthEndpointsConfigValidator>();
        services.TryAddScoped<IJwtTokenProvider, DefaultJwtTokenProvider<TUser>>();
        services.TryAddScoped<IWelcomeActionService, DefaultWelcomeActionService>();

        var config = new JwtAuthEndpointsConfigOptions();
        configureOptions(config);
        if (config.GoogleFirebaseAuthOptions != null && FirebaseApp.DefaultInstance == null)
        {
            FirebaseApp.Create(config.GoogleFirebaseAuthOptions);
        }

        // Configure authentication and JWT bearer
        services.AddAuthentication(options =>
        {
            var config = new JwtAuthEndpointsConfigOptions();
            configureOptions(config);

            options.DefaultAuthenticateScheme = config.AuthenticationScheme.DefaultAuthenticateScheme;
            options.DefaultChallengeScheme = config.AuthenticationScheme.DefaultChallengeScheme;
            options.DefaultScheme = config.AuthenticationScheme.DefaultScheme;
        })
        .AddJwtBearer(options =>
        {
            var config = new JwtAuthEndpointsConfigOptions();
            configureOptions(config);

            var jwt = config.JwtAuthSchemeOptions;

            options.RequireHttpsMetadata = jwt.RequireHttpsMetadata;
            options.MetadataAddress = jwt.MetadataAddress;
            options.Authority = jwt.Authority;
            options.Audience = jwt.Audience;
            options.Challenge = jwt.Challenge;
            options.Events = jwt.Events;
            options.BackchannelHttpHandler = jwt.BackchannelHttpHandler;
            options.Backchannel = jwt.Backchannel;
            options.BackchannelTimeout = jwt.BackchannelTimeout;
            options.Configuration = jwt.Configuration;
            options.ConfigurationManager = jwt.ConfigurationManager;
            options.RefreshOnIssuerKeyNotFound = jwt.RefreshOnIssuerKeyNotFound;
            options.TokenValidationParameters = jwt.TokenValidationParameters;
            options.SaveToken = jwt.SaveToken;
            options.IncludeErrorDetails = jwt.IncludeErrorDetails;
            options.MapInboundClaims = jwt.MapInboundClaims;
            options.AutomaticRefreshInterval = jwt.AutomaticRefreshInterval;
            options.RefreshInterval = jwt.RefreshInterval;
            options.UseSecurityTokenValidators = jwt.UseSecurityTokenValidators;

            options.TokenHandlers.Clear();
            foreach (var handler in jwt.TokenHandlers)
            {
                options.TokenHandlers.Add(handler);
            }
        });

        return services;
    }
}
