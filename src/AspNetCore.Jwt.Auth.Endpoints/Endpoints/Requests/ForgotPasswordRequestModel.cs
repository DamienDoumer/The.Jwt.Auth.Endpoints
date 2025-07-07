using System.ComponentModel.DataAnnotations;

namespace AspNetCore.Jwt.Auth.Endpoints.Endpoints.Requests;

public class ForgotPasswordRequestModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}