using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Jwt.Auth.Endpoints.TestAPI.Data.Models;

public class ApplicationUser : IdentityUser
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public DateTime? LastLoginAt { get; set; }
    public string RefreshToken { get; set; } = string.Empty;
    public DateTime RefreshTokenExpiryTime { get; set; }
    public string PictureUrl { get; set; } = string.Empty;
}