using FirebaseAdmin;
using Jwt.Auth.Endpoints.Helpers;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace Jwt.Auth.Endpoints.Settings;

public class JwtAuthEndpointsConfigOptions
{
    public JwtBearerOptions JwtAuthSchemeOptions { get; set; }
    public JwtSettings JwtSettings { get; set; }
    public AuthenticationOptions AuthenticationScheme { get; private set; }
    public AppOptions? GoogleFirebaseAuthOptions { get; set; }
    /// <summary>
    /// This is a factory used to instantiate identity users with total flexibility.
    /// </summary>
    public IIdentityUserFactory<IdentityUser> UserFactory { get; set; }

    public JwtAuthEndpointsConfigOptions(JwtBearerOptions jwtOptions,
        IIdentityUserFactory<IdentityUser> userFactory,
        AppOptions? googleFirebaseAuthOptions = default) : this()
    {
        UserFactory = userFactory;
        GoogleFirebaseAuthOptions = googleFirebaseAuthOptions;
        JwtAuthSchemeOptions = jwtOptions;
    }

    public JwtAuthEndpointsConfigOptions()
    {
        JwtAuthSchemeOptions = new JwtBearerOptions();
        JwtSettings = new JwtSettings();
        JwtSettings = new JwtSettings();
        UserFactory = new DefaultUserFactory();
        AuthenticationScheme = new AuthenticationOptions
        {
            DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme,
            DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme,
            DefaultScheme = JwtBearerDefaults.AuthenticationScheme
        };
    }
}
