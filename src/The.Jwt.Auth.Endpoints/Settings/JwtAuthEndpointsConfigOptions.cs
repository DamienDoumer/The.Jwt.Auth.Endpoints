using FirebaseAdmin;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;

namespace The.Jwt.Auth.Endpoints.Settings;

public class JwtAuthEndpointsConfigOptions
{
    public JwtBearerOptions JwtAuthSchemeOptions { get; set; }
    public JwtSettings JwtSettings { get; set; }
    public AuthenticationOptions AuthenticationScheme { get; private set; }
    public AppOptions? GoogleFirebaseAuthOptions { get; set; }

    public JwtAuthEndpointsConfigOptions(JwtBearerOptions jwtOptions,
        AppOptions? googleFirebaseAuthOptions = default) : this()
    {
        GoogleFirebaseAuthOptions = googleFirebaseAuthOptions;
        JwtAuthSchemeOptions = jwtOptions;
    }

    public JwtAuthEndpointsConfigOptions()
    {
        JwtAuthSchemeOptions = new JwtBearerOptions();
        JwtSettings = new JwtSettings();
        JwtSettings = new JwtSettings();
        AuthenticationScheme = new AuthenticationOptions
        {
            DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme,
            DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme,
            DefaultScheme = JwtBearerDefaults.AuthenticationScheme
        };
    }
}
