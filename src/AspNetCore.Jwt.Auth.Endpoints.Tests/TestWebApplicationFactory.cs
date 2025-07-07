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

public class TestWebApplicationFactory : WebApplicationFactory<Program>
{
    protected override void ConfigureWebHost(IWebHostBuilder builder)
    {
        builder.ConfigureServices(services =>
        {
        });

        builder.UseEnvironment("Testing");
    }
}