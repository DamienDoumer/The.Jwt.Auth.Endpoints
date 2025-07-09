using System.ComponentModel.DataAnnotations;

namespace The.Jwt.Auth.Endpoints.Endpoints.Requests;

public class ForgotPasswordRequestModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
}