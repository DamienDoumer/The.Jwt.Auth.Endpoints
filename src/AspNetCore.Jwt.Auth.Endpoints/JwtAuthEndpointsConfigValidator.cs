using AspNetCore.Jwt.Auth.Endpoints.Helpers;
using AspNetCore.Jwt.Auth.Endpoints.Settings;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;

namespace AspNetCore.Jwt.Auth.Endpoints;

public class JwtAuthEndpointsConfigValidator : IValidateOptions<JwtAuthEndpointsConfigOptions>
{
    private readonly IServiceProvider _serviceProvider;

    public JwtAuthEndpointsConfigValidator(IServiceProvider serviceProvider)
    {
        _serviceProvider = serviceProvider;
    }

    public ValidateOptionsResult Validate(string name, JwtAuthEndpointsConfigOptions options)
    {
        var refreshTokenRepo = _serviceProvider.GetService<IRefreshTokenRepository>();

        if (refreshTokenRepo == null)
        {
            return ValidateOptionsResult.Fail("IRefreshTokenRepository must be registered in the service container.");
        }

        if (options.UserFactory == null)
        {
            return ValidateOptionsResult.Fail("UserFactory must be configured.");
        }

        if (options.JwtSettings == null ||
            (
                string.IsNullOrWhiteSpace(options.JwtSettings.Audience) ||
                string.IsNullOrWhiteSpace(options.JwtSettings.Issuer) ||
                string.IsNullOrWhiteSpace(options.JwtSettings.Secret) ||
                options.JwtSettings.RefreshTokenLifeSpanInMinutes == 0 ||
                options.JwtSettings.TokenLifeSpanInMinutes == 0
            ))
        {
            return ValidateOptionsResult.Fail("Please configure properly your \"JwtSettings\" " +
                    "Make sure every property has a value other than the default value.");
        }

        if (!(
        (
            options.AuthenticationScheme.DefaultAuthenticateScheme == JwtBearerDefaults.AuthenticationScheme &&
            options.AuthenticationScheme.DefaultChallengeScheme == JwtBearerDefaults.AuthenticationScheme &&
            options.AuthenticationScheme.DefaultScheme == JwtBearerDefaults.AuthenticationScheme
        ) &&
        options.JwtAuthSchemeOptions != null))
        {
            return ValidateOptionsResult.Fail("Please check your JwtAuthEndpointsConfigOptions's configurations and make sure that " +
               "these conditions are met: UserFactory should not be null, " +
               "AuthenticationScheme's DefaultAuthenticateScheme, DefaultChallengeScheme, DefaultScheme " +
               "should not be modified, and that your JwtOptions should be set.");
        }

        return ValidateOptionsResult.Success;
    }
}
