# Doumer.AspNetCore.Jwt.Auth.Endpoints

[![.NET](https://img.shields.io/badge/.NET-9.0-blue.svg)](https://dotnet.microsoft.com/)
[![ASP.NET Core](https://img.shields.io/badge/ASP.NET%20Core-9.0-blue.svg)](https://docs.microsoft.com/aspnet/core)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A complete, production-ready JWT authentication library for ASP.NET Core applications. This library provides pre-built authentication endpoints using minimal APIs, following modern ASP.NET Core patterns and security best practices.

## Why Doumer.AspNetCore.Jwt.Auth.Endpoints?

Microsoft released [Identity endpoints](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-api-authorization?view=aspnetcore-9.0) as part of .NET 8, but with limitations:
Uses proprietary tokens instead of standard JWT, and has limited customization.

This library provides the same functionality as Identity endpoints but with:
 **Standard JWT tokens** with full customization.

## Installation
Just add the nugget package to your project (__Doumer.AspNetCore.Jwt.Auth.Endpoints__)
```
dotnet add package Doumer.AspNetCore.Jwt.Auth.Endpoints
```
## Features

- 🔐 **Complete Authentication Flow**: Login, registration, email confirmation, password reset
- 🔄 **JWT Token Management**: Access tokens with refresh token support
- 📧 **Email Integration**: Configurable email confirmation and password reset
- 🌐 **Google Social Auth**: Optional Firebase Google authentication

## API Endpoints

Once configured, the library provides the following endpoints:

| Endpoint | Method | Description |
|----------|--------|-------------|
| `/api/auth/register` | POST | User registration with email confirmation |
| `/api/auth/login` | POST | User login with email/password |
| `/api/auth/refresh` | POST | Refresh JWT access token |
| `/api/auth/confirmEmail` | GET | Confirm user email address |
| `/api/auth/forgotPassword` | POST | Initiate password reset process |
| `/api/auth/resetPassword` | POST | Complete password reset |
| `/api/auth/social/google` | POST | Google Firebase authentication *(optional)* |

## Quick Start

### 1. Installation

```bash
dotnet add package AspNetCore.Jwt.Auth.Endpoints
```

### 2. Basic Setup

#### Create Your User Model
```csharp
public class ApplicationUser : IdentityUser
{
    public string? FirstName { get; set; }
    public string? LastName { get; set; }
    public DateTime CreatedAt { get; set; }
    public DateTime? LastLoginAt { get; set; }
    public string RefreshToken { get; set; } = string.Empty;
    public DateTime RefreshTokenExpiryTime { get; set; }
    public string PictureUrl { get; set; } = string.Empty;
}
```

#### Configure Services in Program.cs
```csharp
using AspNetCore.Jwt.Auth.Endpoints.Extensions;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

// Add Entity Framework
builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));

// Configure ASP.NET Core Identity
builder.Services.AddIdentity<ApplicationUser, IdentityRole>(options =>
{
    options.Password.RequireDigit = true;
    options.Password.RequiredLength = 8;
    options.Password.RequireNonAlphanumeric = false;
    options.Password.RequireUppercase = true;
    options.Password.RequireLowercase = false;
    
    options.User.RequireUniqueEmail = true;
    
    options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(15);
    options.Lockout.MaxFailedAccessAttempts = 5;
    options.Lockout.AllowedForNewUsers = true;
})
.AddEntityFrameworkStores<ApplicationDbContext>()
.AddDefaultTokenProviders();

// Required service implementations
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
builder.Services.AddScoped<IIdentityUserFactory<ApplicationUser>, SimpleUserFactory>();
builder.Services.AddScoped<IEmailSender<ApplicationUser>, EmailSender>();

// Configure JWT Authentication
builder.Services.AddJwtAuthEndpoints<ApplicationUser>(options =>
{
    // JWT Settings
    options.JwtSettings.Secret = "your-super-secret-key-that-should-be-at-least-32-characters-long";
    options.JwtSettings.Issuer = "https://yourapp.com";
    options.JwtSettings.Audience = "YourApp";
    options.JwtSettings.TokenLifeSpanInMinutes = 60;
    options.JwtSettings.RefreshTokenLifeSpanInMinutes = 1440; // 24 hours
    
    // JWT Bearer Token Validation
    options.JwtAuthSchemeOptions.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "https://yourapp.com",
        ValidAudience = "YourApp",
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your-super-secret-key-that-should-be-at-least-32-characters-long"))
    };
    
    // Optional: Google Firebase Auth
    options.GoogleFirebaseAuthOptions = new AppOptions()
    {
        Credential = GoogleCredential.FromFile("FirebaseServiceAccountFile.json")
    };
});

var app = builder.Build();

// Configure pipeline
app.UseAuthentication();
app.UseAuthorization();

// Map JWT authentication endpoints
app.MapJwtAuthEndpoints<ApplicationUser>();

app.Run();
```

### 3. Required Implementations

#### User Factory
```csharp
public class SimpleUserFactory : IIdentityUserFactory<ApplicationUser>
{
    public ApplicationUser CreateUser(string firstName, string lastName, string email, string? picture = null)
    {
        return new ApplicationUser
        {
            UserName = email,
            Email = email,
            FirstName = firstName,
            LastName = lastName,
            CreatedAt = DateTime.UtcNow,
            PictureUrl = picture ?? string.Empty
        };
    }
}
```

#### Refresh Token Repository
```csharp
public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly ApplicationDbContext _context;

    public RefreshTokenRepository(ApplicationDbContext context)
    {
        _context = context;
    }

    public async Task<string> GenerateRefreshTokenAsync(string userId)
    {
        var refreshToken = Convert.ToBase64String(RandomNumberGenerator.GetBytes(64));
        
        var user = await _context.Users.FindAsync(userId);
        if (user != null)
        {
            user.RefreshToken = refreshToken;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(30);
            await _context.SaveChangesAsync();
        }
        
        return refreshToken;
    }

    public async Task<bool> ValidateRefreshTokenAsync(string userId, string refreshToken)
    {
        var user = await _context.Users.FindAsync(userId);
        return user != null && 
               user.RefreshToken == refreshToken && 
               user.RefreshTokenExpiryTime > DateTime.UtcNow;
    }

    public async Task RevokeRefreshTokenAsync(string userId)
    {
        var user = await _context.Users.FindAsync(userId);
        if (user != null)
        {
            user.RefreshToken = string.Empty;
            user.RefreshTokenExpiryTime = DateTime.UtcNow.AddDays(-1);
            await _context.SaveChangesAsync();
        }
    }
}
```

#### Email Sender
```csharp
public class EmailSender : IEmailSender<ApplicationUser>
{
    private readonly ILogger<EmailSender> _logger;
    private readonly IConfiguration _configuration;

    public EmailSender(ILogger<EmailSender> logger, IConfiguration configuration)
    {
        _logger = logger;
        _configuration = configuration;
    }

    public async Task SendConfirmationLinkAsync(ApplicationUser user, string email, string confirmationLink)
    {
        _logger.LogInformation("Sending confirmation email to {Email}", email);
        
        // TODO: Implement your email sending logic here
        // Example: using SendGrid, SMTP, or other email service
        
        await Task.CompletedTask;
    }

    public async Task SendPasswordResetLinkAsync(ApplicationUser user, string email, string resetLink)
    {
        _logger.LogInformation("Sending password reset email to {Email}", email);
        
        // TODO: Implement your password reset email logic here
        
        await Task.CompletedTask;
    }

    public async Task SendPasswordResetCodeAsync(ApplicationUser user, string email, string resetCode)
    {
        _logger.LogInformation("Sending password reset code to {Email}", email);
        
        // TODO: Implement your password reset code logic here
        
        await Task.CompletedTask;
    }
}
```

### Example Usage

#### Register User
```bash
POST /api/auth/register
Content-Type: application/json

{
  "firstName": "John",
  "lastName": "Doe",
  "email": "john.doe@example.com",
  "password": "SecurePassword123"
}
```

#### Login
```bash
POST /api/auth/login
Content-Type: application/json

{
  "email": "john.doe@example.com",
  "password": "SecurePassword123"
}
```

#### Refresh Token
```bash
POST /api/auth/refresh
Content-Type: application/json

{
  "accessToken": "your-access-token",
  "refreshToken": "your-refresh-token"
}
```

#### Forgot Password
```bash
POST /api/auth/forgotPassword
Content-Type: application/json

{
  "email": "john.doe@example.com"
}
```

#### Reset Password
```bash
POST /api/auth/resetPassword
Content-Type: application/json

{
  "email": "john.doe@example.com",
  "token": "reset-token-from-email",
  "newPassword": "NewSecurePassword123"
}
```

## Google Social Authentication

To enable Google authentication through Firebase:

### 1. Configure Firebase
1. Create a Firebase project in the [Firebase Console](https://console.firebase.google.com/)
2. Enable Authentication and configure Google as a sign-in provider
3. Download the Service Account Key JSON file
4. Place the file in your project root and set its Build Action to **Content** and **Copy Always**

### 2. Configure in Code
```csharp
builder.Services.AddJwtAuthEndpoints<ApplicationUser>(options =>
{
    // ... other configurations
    
    options.GoogleFirebaseAuthOptions = new AppOptions()
    {
        Credential = GoogleCredential.FromFile("FirebaseServiceAccountFile.json")
    };
});
```

### 3. Usage
```bash
POST /api/auth/social/google
Content-Type: application/json

{
  "idToken": "firebase-id-token-from-client"
}
```

## Configuration Options

### JWT Settings
```csharp
public class JwtSettings
{
    public string Secret { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public string Audience { get; set; } = string.Empty;
    public int TokenLifeSpanInMinutes { get; set; } = 60;
    public int RefreshTokenLifeSpanInMinutes { get; set; } = 1440;
}
```

### Main Configuration
```csharp
public class JwtAuthEndpointsConfigOptions
{
    public JwtSettings JwtSettings { get; set; } = new();
    public JwtBearerOptions JwtAuthSchemeOptions { get; set; } = new();
    public AppOptions? GoogleFirebaseAuthOptions { get; set; }
}
```

## Security Features

- **JWT Token Validation**: Comprehensive token validation with configurable parameters
- **Refresh Token Rotation**: Secure refresh token implementation
- **Email Confirmation**: Required email verification for new accounts
- **Password Reset**: Secure password reset with time-limited tokens
- **Input Validation**: Comprehensive validation using Data Annotations
- **Error Handling**: Consistent error responses that don't leak sensitive information
- **Account Lockout**: Configurable account lockout after failed attempts

## Testing

The library includes comprehensive integration tests. To run them:

```bash
dotnet test
```

## Advanced Usage

### Custom User Factory
Implement `IIdentityUserFactory<TUser>` to control user creation:

```csharp
public class CustomUserFactory : IIdentityUserFactory<ApplicationUser>
{
    public ApplicationUser CreateUser(string firstName, string lastName, string email, string? picture = null)
    {
        return new ApplicationUser
        {
            UserName = email,
            Email = email,
            FirstName = firstName,
            LastName = lastName,
            CreatedAt = DateTime.UtcNow,
            PictureUrl = picture ?? string.Empty,
            // Add custom logic here
        };
    }
}
```

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License. See the [LICENSE](./LICENSE) file for the full license text.

## Support

For issues, questions, or feature requests, please create an issue in the [GitHub repository](https://github.com/your-username/AspNetCore.Jwt.Auth.Endpoints).