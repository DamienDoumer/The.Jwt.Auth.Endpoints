using Microsoft.Extensions.Logging;

namespace The.Jwt.Auth.Endpoints.Helpers;
internal class DefaultWelcomeActionService(ILogger<DefaultWelcomeActionService> _logger) : IWelcomeActionService
{
    public Task PerformWelcomeActionsAsync(string userId, string userEmail, string username)
    {
        _logger.LogInformation("Performing welcome actions for new user. UserId: {UserId}, Email: {Email}, Username: {Username}",
            userId, userEmail, username);
        // Here you can add actual welcome actions like sending a welcome email,
        // creating default user settings, etc.
        return Task.CompletedTask;
    }
}
