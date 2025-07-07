using System.Net;
using System.Net.Http.Json;
using System.Text;
using AspNetCore.Jwt.Auth.Endpoints.Endpoints.Requests;
using AspNetCore.Jwt.Auth.Endpoints.Endpoints.Responses;
using AspNetCore.Jwt.Auth.Endpoints.TestAPI.Data;
using AspNetCore.Jwt.Auth.Endpoints.TestAPI.Data.Models;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;

namespace AspNetCore.Jwt.Auth.Endpoints.Tests;

public class AuthEndpointsIntegrationTests : IClassFixture<TestWebApplicationFactory>
{
    private readonly HttpClient _client;
    private readonly TestWebApplicationFactory _factory;

    public AuthEndpointsIntegrationTests(TestWebApplicationFactory factory)
    {
        _factory = factory;
        _client = factory.CreateClient();
    }

    [Fact]
    public async Task RegisterEndpoint_WithValidData_ShouldReturnSuccessAndToken()
    {
        var registerRequest = new RegisterRequestModel
        {
            Email = "test@example.com",
            Password = "TestPassword123",
            FirstName = "John",
            LastName = "Doe"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        
        var content = await response.Content.ReadAsStringAsync();
        var authResponse = JsonConvert.DeserializeObject<AuthResponseModel>(content);
        
        authResponse.Should().NotBeNull();
        authResponse!.Token.Should().NotBeNullOrEmpty();
        authResponse.RefreshToken.Should().NotBeNullOrEmpty();
        authResponse.TokenExpiryInMinutes.Should().BeGreaterThan(0);
    }

    [Fact]
    public async Task RegisterEndpoint_WithDuplicateEmail_ShouldReturnBadRequest()
    {
        var registerRequest = new RegisterRequestModel
        {
            Email = "duplicate@example.com",
            Password = "TestPassword123",
            FirstName = "John",
            LastName = "Doe"
        };

        await _client.PostAsJsonAsync("/api/auth/register", registerRequest);
        var response = await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task LoginEndpoint_WithValidCredentials_ShouldReturnSuccessAndToken()
    {
        await SeedUserAsync("login@example.com", "TestPassword123");

        var loginRequest = new LoginRequestModel
        {
            Email = "login@example.com",
            Password = "TestPassword123"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        
        var content = await response.Content.ReadAsStringAsync();
        var authResponse = JsonConvert.DeserializeObject<AuthResponseModel>(content);
        
        authResponse.Should().NotBeNull();
        authResponse!.Token.Should().NotBeNullOrEmpty();
        authResponse.RefreshToken.Should().NotBeNullOrEmpty();
        
        var tokenHandler = new JwtSecurityTokenHandler();
        var token = tokenHandler.ReadJwtToken(authResponse.Token);
        token.Claims.Should().Contain(c => c.Type == ClaimTypes.Email && c.Value == "login@example.com");
    }

    [Fact]
    public async Task LoginEndpoint_WithInvalidCredentials_ShouldReturnUnauthorized()
    {
        var loginRequest = new LoginRequestModel
        {
            Email = "nonexistent@example.com",
            Password = "WrongPassword"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task LoginEndpoint_WithUnconfirmedEmail_ShouldReturnUnauthorized()
    {
        await SeedUserAsync("unconfirmed@example.com", "TestPassword123", emailConfirmed: false);

        var loginRequest = new LoginRequestModel
        {
            Email = "unconfirmed@example.com",
            Password = "TestPassword123"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task RefreshTokenEndpoint_WithValidTokens_ShouldReturnNewTokens()
    {
        var authResponse = await RegisterAndLoginUser("refresh@example.com", "TestPassword123");

        var refreshRequest = new RefreshTokenRequestModel
        {
            AccessToken = authResponse.Token,
            RefreshToken = authResponse.RefreshToken
        };

        var response = await _client.PostAsJsonAsync("/api/auth/refresh", refreshRequest);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        
        var content = await response.Content.ReadAsStringAsync();
        var newAuthResponse = JsonConvert.DeserializeObject<AuthResponseModel>(content);
        
        newAuthResponse.Should().NotBeNull();
        newAuthResponse!.Token.Should().NotBeNullOrEmpty();
        newAuthResponse.RefreshToken.Should().NotBeNullOrEmpty();
        newAuthResponse.Token.Should().NotBe(authResponse.Token);
    }

    [Fact]
    public async Task RefreshTokenEndpoint_WithInvalidRefreshToken_ShouldReturnBadRequest()
    {
        var authResponse = await RegisterAndLoginUser("refresh2@example.com", "TestPassword123");

        var refreshRequest = new RefreshTokenRequestModel
        {
            AccessToken = authResponse.Token,
            RefreshToken = "invalid-refresh-token"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/refresh", refreshRequest);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task RefreshTokenEndpoint_WithInvalidAccessToken_ShouldReturnBadRequest()
    {
        var authResponse = await RegisterAndLoginUser("refresh3@example.com", "TestPassword123");

        var refreshRequest = new RefreshTokenRequestModel
        {
            AccessToken = "invalid-access-token",
            RefreshToken = authResponse.RefreshToken
        };

        var response = await _client.PostAsJsonAsync("/api/auth/refresh", refreshRequest);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task RegisterEndpoint_WithInvalidEmail_ShouldReturnBadRequest()
    {
        var registerRequest = new RegisterRequestModel
        {
            Email = "invalid-email",
            Password = "TestPassword123",
            FirstName = "John",
            LastName = "Doe"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task LoginEndpoint_WithEmptyCredentials_ShouldReturnBadRequest()
    {
        var loginRequest = new LoginRequestModel
        {
            Email = "",
            Password = ""
        };

        var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);
        var stringContent = await response.Content.ReadAsStringAsync();

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    private async Task<AuthResponseModel> RegisterAndLoginUser(string email, string password)
    {
        var registerRequest = new RegisterRequestModel
        {
            Email = email,
            Password = password,
            FirstName = "Test",
            LastName = "User"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/register", registerRequest);
        var content = await response.Content.ReadAsStringAsync();
        return JsonConvert.DeserializeObject<AuthResponseModel>(content)!;
    }

    private async Task SeedUserAsync(string email, string password, bool emailConfirmed = true)
    {
        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        
        var user = new ApplicationUser
        {
            UserName = email,
            Email = email,
            EmailConfirmed = emailConfirmed,
            FirstName = "Test",
            LastName = "User"
        };

        await userManager.CreateAsync(user, password);
    }
}
