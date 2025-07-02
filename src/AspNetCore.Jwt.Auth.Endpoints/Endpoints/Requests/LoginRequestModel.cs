using System.ComponentModel.DataAnnotations;

namespace AspNetCore.Jwt.Auth.Endpoints.Endpoints.Requests;
public class LoginRequestModel
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
}
