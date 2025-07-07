namespace AspNetCore.Jwt.Auth.Endpoints.Settings;

internal class AuthConstants
{
    public const string AuthEnpointGroup = "api/auth";
    public const string RegisterEndpoint = $"{AuthEnpointGroup}/register";
    public const string LoginEndpoint = $"{AuthEnpointGroup}/login";
    public const string GoogleEndpoint = $"{AuthEnpointGroup}/social/google";
    public const string RefreshEndpoint = $"{AuthEnpointGroup}/refresh";
    public const string EmailConfirmationEndpoint = $"{AuthEnpointGroup}/confirmEmail";
    public const string ResendConfirmationEmailEndpoint = $"{AuthEnpointGroup}/resendConfirmationEmail";
    public const string ForgotPasswordpoint = $"{AuthEnpointGroup}/forgotPassword";
    public const string ResetPasswordpoint = $"{AuthEnpointGroup}/resetPassword";
}
