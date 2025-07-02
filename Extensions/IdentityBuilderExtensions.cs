using Jwt.Auth.Endpoints.Helpers;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.DependencyInjection.Extensions;

namespace Jwt.IdentityEndpoints.Extensions;
public static class IdentityBuilderExtensions
{
    public static IServiceCollection AddJwtAuthEndpoints<TUser>(this IServiceCollection services,
        Action<JwtAuthEndpointsConfigOptions> config) where TUser : IdentityUser, new()
    {
        ArgumentNullException.ThrowIfNull(services);
        ArgumentNullException.ThrowIfNull(config);

        services.TryAddSingleton<IIdentityUserFactory<IdentityUser>, DefaultUserFactory>();
        var builder = services.AddOptions<JwtAuthEndpointsConfigOptions>();
        var opts = new JwtAuthEndpointsConfigOptions();

        builder.Configure(config);

        services.PostConfigure<JwtAuthEndpointsConfigOptions>(options =>
        {
            if (options.JwtSettings == null ||
                (
                    string.IsNullOrWhiteSpace(options.JwtSettings.Audience) ||
                    string.IsNullOrWhiteSpace(options.JwtSettings.Issuer) ||
                    string.IsNullOrWhiteSpace(options.JwtSettings.Secret) ||
                    options.JwtSettings.RefreshTokenLifeSpanInDays == 0 ||
                    options.JwtSettings.TokenLifeSpanInHours == 0
                ))
            {
                throw new InvalidOperationException("Please configure properly your \"JwtSettings\" " +
                        "Make sure every property has a value other than the default value.");
            }

            if (!(options.UserFactory != null &&
            (
                options.AuthenticationScheme.DefaultAuthenticateScheme == JwtBearerDefaults.AuthenticationScheme &&
                options.AuthenticationScheme.DefaultChallengeScheme == JwtBearerDefaults.AuthenticationScheme &&
                options.AuthenticationScheme.DefaultScheme == JwtBearerDefaults.AuthenticationScheme
            ) &&
            options.JwtAuthSchemeOptions != null))
            {
                throw new InvalidOperationException("Please check your JwtAuthEndpointsConfigOptions's configurations and make sure that " +
                   "these conditions are met: UserFactory should not be null, " +
                   "AuthenticationScheme's DefaultAuthenticateScheme, DefaultChallengeScheme, DefaultScheme " +
                   "should not be modified, and that your JwtOptions should be set.");
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
