using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.Mvc.Testing;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.EntityFrameworkCore;
using AspNetCore.Jwt.Auth.Endpoints.TestAPI.Data;
using AspNetCore.Jwt.Auth.Endpoints.TestAPI.Data.Models;
using Microsoft.AspNetCore.Identity;
using AspNetCore.Jwt.Auth.Endpoints.Helpers;
using AspNetCore.Jwt.Auth.Endpoints.Extensions;
using Microsoft.IdentityModel.Tokens;
using System.Text;
using AspNetCore.Jwt.Auth.Endpoints.TestAPI;
using Microsoft.Extensions.Configuration;

namespace AspNetCore.Jwt.Auth.Endpoints.Tests;

public class TestWebApplicationFactory : WebApplicationFactory<Program>, IAsyncLifetime
{
    private readonly string _connectionString = $"Data Source=test_db_{Guid.NewGuid()}.db";
    public MockEmailSender MockEmailSender { get; } = new();

    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
            // Remove existing DbContext registration
            var descriptor = services.SingleOrDefault(d => d.ServiceType == typeof(DbContextOptions<ApplicationDbContext>));
            if (descriptor != null)
            {
                services.Remove(descriptor);
            }

            // Remove existing EmailSender registration
            var emailSenderDescriptor = services.SingleOrDefault(d => d.ServiceType == typeof(IEmailSender<ApplicationUser>));
            if (emailSenderDescriptor != null)
            {
                services.Remove(emailSenderDescriptor);
            }

            // Add SQLite database for testing with unique name
            services.AddDbContext<ApplicationDbContext>(options =>
            {
                options.UseSqlite(_connectionString);
            });

            // Add mock email sender
            services.AddSingleton<IEmailSender<ApplicationUser>>(MockEmailSender);
        });

        builder.UseEnvironment("Testing");
    }

    private async Task EnsureDatabaseCreated()
    {
        using var scope = Services.CreateScope();
        var context = scope.ServiceProvider.GetRequiredService<ApplicationDbContext>();

        //await context.Database.EnsureDeletedAsync();
        await context.Database.EnsureCreatedAsync();
    }

    public async Task InitializeAsync()
    {
        await EnsureDatabaseCreated();
    }

    public Task DisposeAsync()
    {
        // Clean up test database file
        if (File.Exists(_connectionString.Replace("Data Source=", "")))
        {
            File.Delete(_connectionString.Replace("Data Source=", ""));
        }
        
        return Task.CompletedTask;
    }
}