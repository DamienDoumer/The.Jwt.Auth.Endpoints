using The.Jwt.Auth.Endpoints.TestApi.Data;
using The.Jwt.Auth.Endpoints.TestApi.Data.Models;
using FirebaseAdmin;
using Google.Apis.Auth.OAuth2;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using The.Jwt.Auth.Endpoints.TestApi;
using The.Jwt.Auth.Endpoints.Extensions;
using The.Jwt.Auth.Endpoints.Helpers;

var builder = WebApplication.CreateBuilder(args);

builder.Services.AddControllers();
// Learn more about configuring Swagger/OpenAPI at https://aka.ms/aspnetcore/swashbuckle
builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen();

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

//***NOTE***: These are Required, for the JWT AUTH TO WORK
builder.Services.AddScoped<IRefreshTokenRepository, RefreshTokenRepository>();
builder.Services.AddScoped<IIdentityUserFactory<ApplicationUser>, SimpleUserFactory>();
builder.Services.AddScoped<IEmailSender<ApplicationUser>, EmailSender>();

// Configure JWT Authentication
builder.Services.AddJwtAuthEndpoints<ApplicationUser>(options =>
{
    // Configure JWT settings
    options.JwtSettings.Secret = "your-super-secret-key-that-should-be-at-least-32-characters-long";
    options.JwtSettings.Issuer = "https://TestAPI";
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
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes("your-super-secret-key-that-should-be-at-least-32-characters-long"))
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
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "TestAPI v1");
        c.RoutePrefix = string.Empty; // Launch Swagger UI at the app's root
    });
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

namespace The.Jwt.Auth.Endpoints.TestApi
{
    public partial class Program
    {
    }
}