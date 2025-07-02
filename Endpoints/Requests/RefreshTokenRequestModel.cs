using System.ComponentModel.DataAnnotations;

namespace Jwt.Auth.Endpoints.Endpoints.Requests;

public class RefreshTokenRequestModel
{
    [Required]
    [MaxLength(1000)]
    public string RefreshToken { get; set; }
    [Required]
    [MaxLength(1000)]
    public string AccessToken { get; set; }

    public RefreshTokenRequestModel()
    {
        RefreshToken = string.Empty;
        AccessToken = string.Empty;
    }
}
