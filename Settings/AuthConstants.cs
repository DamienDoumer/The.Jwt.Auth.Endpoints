namespace Jwt.Auth.Endpoints.Settings;

internal class AuthConstants
{
    public const string AuthEnpointGroup = "auth";
    public const string SignupEndpoint = $"{AuthEnpointGroup}/signup";
    public const string SigninEndpoint = $"{AuthEnpointGroup}/signin";
    public const string GoogleEndpoint = $"{AuthEnpointGroup}/social/google";
    public const string RefreshEndpoint = $"{AuthEnpointGroup}/refresh";
    public const string ResendConfirmationEmailEndpoint = $"{AuthEnpointGroup}/resendConfirmationEmail";
    public const string ForgotPasswordpoint = $"{AuthEnpointGroup}/forgotPassword";
    public const string ResetPasswordpoint = $"{AuthEnpointGroup}/resetPassword";
}
