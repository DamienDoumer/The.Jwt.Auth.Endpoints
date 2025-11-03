# The.Jwt.Auth.Endpoints

[![.NET](https://img.shields.io/badge/.NET-9.0-blue.svg)](https://dotnet.microsoft.com/)
[![ASP.NET Core](https://img.shields.io/badge/ASP.NET%20Core-9.0-blue.svg)](https://docs.microsoft.com/aspnet/core)
[![License](https://img.shields.io/badge/License-MIT-green.svg)](LICENSE)

A complete, production-ready JWT authentication library for ASP.NET Core applications. This library provides pre-built authentication endpoints using minimal APIs, following modern ASP.NET Core patterns and security best practices.

## Why The.Jwt.Auth.Endpoints?

Microsoft released [Identity endpoints](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-api-authorization?view=aspnetcore-9.0) as part of .NET 8, but with limitations:
Uses proprietary tokens instead of standard JWT, and has limited customization.

This library provides the same functionality as Identity endpoints but with:
 **Standard JWT tokens** with more customization.

## Installation
Just add the nugget package to your project (__The.Jwt.Auth.Endpoints__)
```
dotnet add package The.Jwt.Auth.Endpoints
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
dotnet add package The.Jwt.Auth.Endpoints
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
using The.Jwt.Auth.Endpoints.Extensions;
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
builder.Services.AddScoped<IWelcomeActionService, YourWelcomeActionService>();

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
Here's a sample implementation, but you could do what ever you want, as long as it stores the token in a database.
```csharp
public class RefreshTokenRepository : IRefreshTokenRepository
{
    private readonly ApplicationDbContext _applicationDbContext;

    public RefreshTokenRepository(ApplicationDbContext applicationDbContext)
    {
        _applicationDbContext = applicationDbContext;
    }

    public async Task<bool> AddOrUpdateRefreshToken(string userId, string refreshToken, DateTime expiryTime)
    {
        var user = await _applicationDbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
        if (user == null)
            return false;

        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = expiryTime;
        
        await _applicationDbContext.SaveChangesAsync();
        return true;
    }

    public async Task<bool> DeleteRefreshToken(string userId, string refreshToken)
    {
        var user = await _applicationDbContext.Users.FirstOrDefaultAsync(u => u.Id == userId && u.RefreshToken == refreshToken);
        if (user == null)
            return false;

        user.RefreshToken = null;
        user.RefreshTokenExpiryTime = DateTime.MinValue;
        
        await _applicationDbContext.SaveChangesAsync();
        return true;
    }

    public async Task<(string refreshToken, DateTime expiryTime)> GetRefreshToken(string userId)
    {
        var user = await _applicationDbContext.Users.FirstOrDefaultAsync(u => u.Id == userId);
        if (user == null || string.IsNullOrEmpty(user.RefreshToken))
            return (null!, DateTime.MinValue);

        return (user.RefreshToken, user.RefreshTokenExpiryTime);
    }
```

#### Email Sender
```csharp
public class EmailSender : IEmailSender<ApplicationUser>
{
    //Your implementation...
}
```

#### Welcome Action Service
The `IWelcomeActionService` is **required** and will be called automatically after a user account is successfully created (both during registration and Google social authentication).

```csharp
public class YourWelcomeActionService : IWelcomeActionService
{
    private readonly ILogger<YourWelcomeActionService> _logger;
    private readonly IEmailService _emailService; // Your email service

    public YourWelcomeActionService(
        ILogger<YourWelcomeActionService> logger,
        IEmailService emailService)
    {
        _logger = logger;
        _emailService = emailService;
    }

    public async Task PerformWelcomeActionsAsync(string userId, string userEmail, string username)
    {
        _logger.LogInformation("Performing welcome actions for user {UserId}", userId);

        // Send welcome email
        await _emailService.SendWelcomeEmailAsync(userEmail, username);

        // Create default user data, initialize preferences, etc.
        // Add any other welcome actions your application requires

        _logger.LogInformation("Welcome actions completed for user {UserId}", userId);
    }
}
```

**Note:** This service is called after:
- New user registration via `/api/auth/register`
- New user creation via Google authentication at `/api/auth/social/google`

It is **not** called when existing users log in.

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

For issues, questions, or feature requests, please create an issue in the [GitHub repository](https://github.com/DamienDoumer/The.Jwt.Auth.Endpoints).