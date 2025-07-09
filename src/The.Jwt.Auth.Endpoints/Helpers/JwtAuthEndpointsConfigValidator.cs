using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.Extensions.Options;
using The.Jwt.Auth.Endpoints.Settings;

namespace The.Jwt.Auth.Endpoints.Helpers;

public class JwtAuthEndpointsConfigValidator : IValidateOptions<JwtAuthEndpointsConfigOptions>
{
    public ValidateOptionsResult Validate(string name, JwtAuthEndpointsConfigOptions options)
    {
        if (options.JwtSettings == null ||
            
                string.IsNullOrWhiteSpace(options.JwtSettings.Audience) ||
                string.IsNullOrWhiteSpace(options.JwtSettings.Issuer) ||
                string.IsNullOrWhiteSpace(options.JwtSettings.Secret) ||
                options.JwtSettings.RefreshTokenLifeSpanInMinutes == 0 ||
                options.JwtSettings.TokenLifeSpanInMinutes == 0
            )
        {
            return ValidateOptionsResult.Fail("Please configure properly your \"JwtSettings\" " +
                    "Make sure every property has a value other than the default value.");
        }

        if (!(
        
            options.AuthenticationScheme.DefaultAuthenticateScheme == JwtBearerDefaults.AuthenticationScheme &&
            options.AuthenticationScheme.DefaultChallengeScheme == JwtBearerDefaults.AuthenticationScheme &&
            options.AuthenticationScheme.DefaultScheme == JwtBearerDefaults.AuthenticationScheme
         &&
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
