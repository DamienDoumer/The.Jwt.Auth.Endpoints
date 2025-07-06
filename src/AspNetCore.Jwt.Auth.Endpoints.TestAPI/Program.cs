using AspNetCore.Jwt.Auth.Endpoints.Extensions;
using AspNetCore.Jwt.Auth.Endpoints.TestAPI.Data;
using AspNetCore.Jwt.Auth.Endpoints.TestAPI.Data.Models;
using FirebaseAdmin;
using Google.Apis.Auth.OAuth2;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using AspNetCore.Jwt.Auth.Endpoints.Helpers;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
// Learn more about configuring OpenAPI at https://aka.ms/aspnet/openapi
builder.Services.AddOpenApi();

builder.Services.AddDbContext<ApplicationDbContext>(options =>
    options.UseSqlite(builder.Configuration.GetConnectionString("DefaultConnection") ?? "Data Source=app.db"));

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

//***NOTE***: This is Required, for the JWT AUTH TO WORK
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();

// Configure JWT Authentication
builder.Services.AddJwtAuthEndpoints<ApplicationUser>(options =>
{
    // Configure JWT settings
    options.JwtSettings.Secret = "your-super-secret-key";
    options.JwtSettings.Issuer = "TestAPI";
    options.JwtSettings.Audience = "TestAPI";
    options.JwtSettings.TokenLifeSpanInMinutes = 60;
    options.JwtSettings.RefreshTokenLifeSpanInMinutes = 1440; // 24 hours
    
    // Configure JWT Bearer options
    options.JwtAuthSchemeOptions.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidateLifetime = true,
        ValidateIssuerSigningKey = true,
        ValidIssuer = "TestAPI",
        ValidAudience = "TestAPI",
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your-super-secret-key"))
    };
    
    // NOTE: Google Firebase Auth is optional - leave null if not using
    options.GoogleFirebaseAuthOptions = new AppOptions()
    {
        Credential = GoogleCredential.FromFile("FirebaseServiceAccountFile.json")
    };
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();

app.UseAuthentication();
app.UseAuthorization();

app.MapControllers();

// Map JWT authentication endpoints
app.MapJwtAuthEndpoints<ApplicationUser>();

// Ensure database is created
using (var scope = app.Services.CreateScope())
{
    var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();
    context.Database.EnsureCreated();
}

app.Run();
