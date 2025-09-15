using System.Net;
using System.Net.Http.Json;
using System.Text;
using The.Jwt.Auth.Endpoints.TestApi.Data;
using The.Jwt.Auth.Endpoints.TestApi.Data.Models;
using FluentAssertions;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Newtonsoft.Json;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text.Encodings.Web;
using The.Jwt.Auth.Endpoints.Endpoints.Requests;
using The.Jwt.Auth.Endpoints.Endpoints.Responses;

namespace The.Jwt.Auth.Endpoints.Tests;

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
        var confirmationLink = WebUtility.HtmlDecode(sentEmail.Content);
        
        // Extract userId and token from the link
        var uri = new Uri(confirmationLink);
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        var userId = query["userId"];
        var token = query["token"];

        // Call confirmation endpoint
        var confirmationUrl = $"/api/auth/confirmEmail?userId={userId}&token={Uri.EscapeDataString(token!)}";
        var response = await _client.GetAsync(confirmationUrl);

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
        var confirmationLink = WebUtility.HtmlDecode(sentEmail.Content);
        var uri = new Uri(confirmationLink);
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        var userId = query["userId"];

        var confirmationUrl = $"/api/auth/confirmEmail?userId={userId}&token=invalid-token";
        var response = await _client.GetAsync(confirmationUrl);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task EmailConfirmationEndpoint_WithInvalidUserId_ShouldReturnNotFound()
    {
        var confirmationUrl = "/api/auth/confirmEmail?userId=invalid-user-id&token=some-token";
        var response = await _client.GetAsync(confirmationUrl);

        response.StatusCode.Should().Be(HttpStatusCode.NotFound);
        
        var content = await response.Content.ReadAsStringAsync();
        content.Should().Contain("User not found");
    }

    [Fact]
    public async Task EmailConfirmationEndpoint_WithAlreadyConfirmedEmail_ShouldReturnSuccess()
    {
        // Create a user with already confirmed email
        await SeedUserAsync("alreadyconfirmed@example.com", "TestPassword123", emailConfirmed: true);
        
        // We need to get actual user ID for this test
        using var scope = _factory.Services.CreateScope();
        var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
        var user = await userManager.FindByEmailAsync("alreadyconfirmed@example.com");
        
        var confirmationUrl = $"/api/auth/confirmEmail?userId={user!.Id}&token=any-token";
        var response = await _client.GetAsync(confirmationUrl);

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
        var confirmationLink = WebUtility.HtmlDecode(sentEmail.Content);
        var uri = new Uri(confirmationLink);
        var query = System.Web.HttpUtility.ParseQueryString(uri.Query);
        var userId = query["userId"];
        var token = query["token"];

        var confirmationUrl = $"/api/auth/confirmEmail?userId={userId}&token={Uri.EscapeDataString(token!)}";
        var confirmationResponse = await _client.GetAsync(confirmationUrl);
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

    [Fact]
    public async Task ForgotPasswordEndpoint_WithValidEmail_ShouldReturnSuccessAndSendEmail()
    {
        // Clear any previous emails
        _factory.MockEmailSender.Clear();

        // Create a user first
        await SeedUserAsync("forgotpassword@example.com", "TestPassword123");

        var forgotPasswordRequest = new ForgotPasswordRequestModel
        {
            Email = "forgotpassword@example.com"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/forgotPassword", forgotPasswordRequest);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync();
        var forgotPasswordResponse = JsonConvert.DeserializeObject<GenericResponseModel>(content);

        forgotPasswordResponse.Should().NotBeNull();
        forgotPasswordResponse!.Success.Should().BeTrue();
        forgotPasswordResponse.Message.Should().Contain("password reset link");

        // Verify email was sent
        _factory.MockEmailSender.SentEmails.Should().HaveCount(1);
        var sentEmail = _factory.MockEmailSender.SentEmails.First();
        sentEmail.Type.Should().Be(EmailType.PasswordResetCode);
        sentEmail.Email.Should().Be("forgotpassword@example.com");
        sentEmail.Content.Should().NotBeNullOrEmpty();
    }

    [Fact]
    public async Task ForgotPasswordEndpoint_WithNonexistentEmail_ShouldReturnSuccessWithoutRevealingUserExistence()
    {
        var forgotPasswordRequest = new ForgotPasswordRequestModel
        {
            Email = "nonexistent@example.com"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/forgotPassword", forgotPasswordRequest);

        response.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await response.Content.ReadAsStringAsync();
        var forgotPasswordResponse = JsonConvert.DeserializeObject<GenericResponseModel>(content);

        forgotPasswordResponse.Should().NotBeNull();
        forgotPasswordResponse!.Success.Should().BeTrue();
        forgotPasswordResponse.Message.Should().Contain("password reset link");
    }

    [Fact]
    public async Task ForgotPasswordEndpoint_WithInvalidEmail_ShouldReturnBadRequest()
    {
        var forgotPasswordRequest = new ForgotPasswordRequestModel
        {
            Email = "invalid-email"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/forgotPassword", forgotPasswordRequest);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ResetPasswordEndpoint_WithValidToken_ShouldResetPassword()
    {
        // Clear any previous emails
        _factory.MockEmailSender.Clear();

        var email = "resetpassword@example.com";
        var originalPassword = "TestPassword123";
        var newPassword = "NewPassword456";

        // Create user
        await SeedUserAsync(email, originalPassword);

        // Request password reset
        var forgotPasswordRequest = new ForgotPasswordRequestModel { Email = email };
        await _client.PostAsJsonAsync("/api/auth/forgotPassword", forgotPasswordRequest);

        // Get reset token from email
        var sentEmail = _factory.MockEmailSender.SentEmails.First();
        var token = sentEmail.Content;

        // Reset password
        var resetPasswordRequest = new ResetPasswordRequestModel
        {
            Email = email,
            Token = token!,
            NewPassword = newPassword
        };

        var resetResponse = await _client.PostAsJsonAsync("/api/auth/resetPassword", resetPasswordRequest);

        resetResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        var content = await resetResponse.Content.ReadAsStringAsync();
        var resetPasswordResponse = JsonConvert.DeserializeObject<GenericResponseModel>(content);

        resetPasswordResponse.Should().NotBeNull();
        resetPasswordResponse!.Success.Should().BeTrue();
        resetPasswordResponse.Message.Should().Contain("successfully reset");

        // Verify can login with new password
        var loginRequest = new LoginRequestModel
        {
            Email = email,
            Password = newPassword
        };

        var loginResponse = await _client.PostAsJsonAsync("/api/auth/login", loginRequest);
        loginResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Verify cannot login with old password
        var oldPasswordLoginRequest = new LoginRequestModel
        {
            Email = email,
            Password = originalPassword
        };

        var oldPasswordLoginResponse = await _client.PostAsJsonAsync("/api/auth/login", oldPasswordLoginRequest);
        oldPasswordLoginResponse.StatusCode.Should().Be(HttpStatusCode.Unauthorized);
    }

    [Fact]
    public async Task ResetPasswordEndpoint_WithInvalidToken_ShouldReturnBadRequest()
    {
        var resetPasswordRequest = new ResetPasswordRequestModel
        {
            Email = "resetpassword2@example.com",
            Token = "invalid-token",
            NewPassword = "NewPassword456"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/resetPassword", resetPasswordRequest);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task ResetPasswordEndpoint_WithNonexistentUser_ShouldReturnBadRequest()
    {
        var resetPasswordRequest = new ResetPasswordRequestModel
        {
            Email = "nonexistent@example.com",
            Token = "some-token",
            NewPassword = "NewPassword456"
        };

        var response = await _client.PostAsJsonAsync("/api/auth/resetPassword", resetPasswordRequest);

        response.StatusCode.Should().Be(HttpStatusCode.BadRequest);
    }

    [Fact]
    public async Task PasswordResetFlow_ShouldWorkEndToEnd()
    {
        // Clear any previous emails
        _factory.MockEmailSender.Clear();

        var email = "passwordflowtest@example.com";
        var originalPassword = "OriginalPassword123";
        var newPassword = "NewPassword456";

        // Step 1: Create user
        await SeedUserAsync(email, originalPassword);

        // Step 2: Request password reset
        var forgotPasswordRequest = new ForgotPasswordRequestModel { Email = email };
        var forgotResponse = await _client.PostAsJsonAsync("/api/auth/forgotPassword", forgotPasswordRequest);
        forgotResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Step 3: Verify email was sent
        _factory.MockEmailSender.SentEmails.Should().HaveCount(1);
        var sentEmail = _factory.MockEmailSender.SentEmails.First();
        sentEmail.Type.Should().Be(EmailType.PasswordResetCode);

        var token = sentEmail.Content;

        var resetPasswordRequest = new ResetPasswordRequestModel
        {
            Email = email,
            Token = token!,
            NewPassword = newPassword
        };

        var resetResponse = await _client.PostAsJsonAsync("/api/auth/resetPassword", resetPasswordRequest);
        resetResponse.StatusCode.Should().Be(HttpStatusCode.OK);

        // Step 5: Verify can login with new password
        var loginRequest = new LoginRequestModel
        {
            Email = email,
            Password = newPassword
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
