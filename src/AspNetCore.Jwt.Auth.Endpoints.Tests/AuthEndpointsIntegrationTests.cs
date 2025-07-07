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
        var authResponse = JsonConvert.DeserializeObject<RegisterResponseModel>(content);
        
        authResponse.Should().NotBeNull();
        authResponse!.AuthResponse!.Token.Should().NotBeNullOrEmpty();
        authResponse.AuthResponse!.RefreshToken.Should().NotBeNullOrEmpty();
        authResponse.AuthResponse!.TokenExpiryInMinutes.Should().BeGreaterThan(0);
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
            AccessToken = authResponse.AuthResponse!.Token,
            RefreshToken = authResponse.AuthResponse!.RefreshToken
        };

        var response = await _client.PostAsJsonAsync("/api/auth/refresh", refreshRequest);
        var responseString = await response.Content.ReadAsStringAsync();
        
        response.StatusCode.Should().Be(HttpStatusCode.OK);
        
        var content = await response.Content.ReadAsStringAsync();
        var newAuthResponse = JsonConvert.DeserializeObject<AuthResponseModel>(content);
        
        newAuthResponse.Should().NotBeNull();
        newAuthResponse!.Token.Should().NotBeNullOrEmpty();
        newAuthResponse.RefreshToken.Should().NotBeNullOrEmpty();
        newAuthResponse.Token.Should().NotBe(authResponse.AuthResponse!.Token);
    }

    [Fact]
    public async Task RefreshTokenEndpoint_WithInvalidRefreshToken_ShouldReturnBadRequest()
    {
        var authResponse = await RegisterAndLoginUser("refresh2@example.com", "TestPassword123");

        var refreshRequest = new RefreshTokenRequestModel
        {
            AccessToken = authResponse.AuthResponse!.Token,
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
            RefreshToken = authResponse.AuthResponse!.RefreshToken
        };

        var response = await _client.PostAsJsonAsync("/api/auth/refresh", refreshRequest);
        var responseString = await response.Content.ReadAsStringAsync();
        
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

    private async Task<RegisterResponseModel> RegisterAndLoginUser(string email, string password)
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
        return JsonConvert.DeserializeObject<RegisterResponseModel>(content)!;
    }

    [Fact]
    public async Task RegisterEndpoint_ShouldSendConfirmationEmail_AndReturnCorrectResponse()
    {
        // Clear any previous emails
        _factory.MockEmailSender.Clear();

        var registerRequest = new RegisterRequestModel
        {
            Email = "emailtest@example.com",
            Password = "TestPassword123",
            FirstName = "John",
            LastName = "Doe"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        
        var content = await response.Content.ReadAsStringAsync();
        var registerResponse = JsonConvert.DeserializeObject<RegisterResponseModel>(content);
        
        // Verify response structure
        registerResponse.Should().NotBeNull();
        registerResponse!.Message.Should().Contain("confirmation instructions");
        registerResponse.RequiresEmailConfirmation.Should().BeTrue();
        registerResponse.AuthResponse.Should().NotBeNull();
        registerResponse.AuthResponse!.Token.Should().NotBeNullOrEmpty();
        
        // Verify email was sent
        _factory.MockEmailSender.SentEmails.Should().HaveCount(1);
        var sentEmail = _factory.MockEmailSender.SentEmails.First();
        sentEmail.Type.Should().Be(EmailType.ConfirmationLink);
        sentEmail.Email.Should().Be("emailtest@example.com");
        sentEmail.Content.Should().Contain("/api/auth/confirmEmail");
        sentEmail.Content.Should().Contain("userId=");
        sentEmail.Content.Should().Contain("token=");
    }

    [Fact]
    public async Task EmailConfirmationEndpoint_WithValidToken_ShouldConfirmEmail()
    {
        // Clear any previous emails
        _factory.MockEmailSender.Clear();

        // Register user first
        var registerRequest = new RegisterRequestModel
        {
            Email = "confirm@example.com",
            Password = "TestPassword123",
            FirstName = "John",
            LastName = "Doe"
        };

        await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

        // Get the confirmation link from the sent email
        var sentEmail = _factory.MockEmailSender.SentEmails.First();
        var confirmationLink = sentEmail.Content;
        
        // Extract userId and token from the link
        var uri = new Uri(confirmationLink);
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        var userId = query["userId"];
        var token = query["token"];

        // Call confirmation endpoint
        var confirmationUrl = $"/api/auth/confirmEmail?userId={userId}&token={Uri.EscapeDataString(token!)}";
        var response = await _client.PostAsync(confirmationUrl, null);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        
        var content = await response.Content.ReadAsStringAsync();
        var confirmationResponse = JsonConvert.DeserializeObject<EmailConfirmationResponseModel>(content);
        
        confirmationResponse.Should().NotBeNull();
        confirmationResponse!.Success.Should().BeTrue();
        confirmationResponse.Message.Should().Be("Email confirmed successfully.");

        // Verify user can now login
        var loginRequest = new LoginRequestModel
        {
            Email = "confirm@example.com",
            Password = "TestPassword123"
        };

        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);
    }

    [Fact]
    public async Task EmailConfirmationEndpoint_WithInvalidToken_ShouldReturnBadRequest()
    {
        // Register user first
        var registerRequest = new RegisterRequestModel
        {
            Email = "invalidtoken@example.com",
            Password = "TestPassword123",
            FirstName = "John",
            LastName = "Doe"
        };

        await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

        // Get the user ID but use invalid token
        var sentEmail = _factory.MockEmailSender.SentEmails.First();
        var confirmationLink = sentEmail.Content;
        var uri = new Uri(confirmationLink);
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        var userId = query["userId"];

        var confirmationUrl = $"/api/auth/confirmEmail?userId={userId}&token=invalid-token";
        var response = await _client.PostAsync(confirmationUrl, null);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task EmailConfirmationEndpoint_WithInvalidUserId_ShouldReturnNotFound()
    {
        var confirmationUrl = "/api/auth/confirmEmail?userId=invalid-user-id&token=some-token";
        var response = await _client.PostAsync(confirmationUrl, null);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("User not found");
    }

    [Fact]
    public async Task EmailConfirmationEndpoint_WithAlreadyConfirmedEmail_ShouldReturnSuccess()
    {
        // Create a user with already confirmed email
        await SeedUserAsync("alreadyconfirmed@example.com", "TestPassword123", emailConfirmed: true);

        // Try to confirm again (this should still return success)
        var confirmationUrl = "/api/auth/confirmEmail?userId=some-id&token=some-token";
        
        // We need to get actual user ID for this test
        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByEmailAsync("alreadyconfirmed@example.com");
        
        confirmationUrl = $"/api/auth/confirmEmail?userId={user!.Id}&token=any-token";
        var response = await _client.PostAsync(confirmationUrl, null);

        response.StatusCode.Should().Be(HttpStatusCode.OK);
        
        var content = await response.Content.ReadAsStringAsync();
        var confirmationResponse = JsonConvert.DeserializeObject<EmailConfirmationResponseModel>(content);
        
        confirmationResponse.Should().NotBeNull();
        confirmationResponse!.Success.Should().BeTrue();
        confirmationResponse.Message.Should().Be("Email is already confirmed.");
    }

    [Fact]
    public async Task LoginEndpoint_WithUnconfirmedEmail_ShouldReturnUnauthorizedWithProperMessage()
    {
        // Clear any previous emails
        _factory.MockEmailSender.Clear();

        // Register user (which creates unconfirmed user)
        var registerRequest = new RegisterRequestModel
        {
            Email = "unconfirmedlogin@example.com",
            Password = "TestPassword123",
            FirstName = "John",
            LastName = "Doe"
        };

        await _client.PostAsJsonAsync("/api/auth/register", registerRequest);

        // Try to login without confirming email
        var loginRequest = new LoginRequestModel
        {
            Email = "unconfirmedlogin@example.com",
            Password = "TestPassword123"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);

        response.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
        
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("Please confirm your email before logging in");
    }

    [Fact]
    public async Task FullEmailConfirmationFlow_ShouldWorkEndToEnd()
    {
        // Clear any previous emails
        _factory.MockEmailSender.Clear();

        var email = "fullflow@example.com";
        var password = "TestPassword123";

        // Step 1: Register user
        var registerRequest = new RegisterRequestModel
        {
            Email = email,
            Password = password,
            FirstName = "Full",
            LastName = "Flow"
        };

        var registerResponse = await _client.PostAsJsonAsync("/api/auth/register", registerRequest);
        registerResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Step 2: Verify email was sent
        _factory.MockEmailSender.SentEmails.Should().HaveCount(1);
        var sentEmail = _factory.MockEmailSender.SentEmails.First();

        // Step 3: Extract confirmation link and confirm email
        var confirmationLink = sentEmail.Content;
        var uri = new Uri(confirmationLink);
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        var userId = query["userId"];
        var token = query["token"];

        var confirmationUrl = $"/api/auth/confirmEmail?userId={userId}&token={Uri.EscapeDataString(token!)}";
        var confirmationResponse = await _client.PostAsync(confirmationUrl, null);
        confirmationResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Step 4: Login should now work
        var loginRequest = new LoginRequestModel
        {
            Email = email,
            Password = password
        };

        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var loginContent = await loginResponse.Content.ReadAsStringAsync();
        var authResponse = JsonConvert.DeserializeObject<AuthResponseModel>(loginContent);
        
        authResponse.Should().NotBeNull();
        authResponse!.Token.Should().NotBeNullOrEmpty();
        authResponse.RefreshToken.Should().NotBeNullOrEmpty();
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
