namespace AspNetCore.Jwt.Auth.Endpoints.Endpoints.Responses;

public class RegisterResponseModel
{
    public string Message { get; set; } = string.Empty;
    public bool RequiresEmailConfirmation { get; set; }
    public AuthResponseModel? AuthResponse { get; set; }
}