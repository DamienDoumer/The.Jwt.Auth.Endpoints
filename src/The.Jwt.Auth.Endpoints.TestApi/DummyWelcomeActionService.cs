using The.Jwt.Auth.Endpoints.Helpers;

namespace The.Jwt.Auth.Endpoints.TestApi
{
    /// <summary>
    /// Dummy implementation of IWelcomeActionService for testing purposes.
    /// In production, replace this with your actual implementation.
    /// </summary>
    public class DummyWelcomeActionService : IWelcomeActionService
    {
        private readonly ILogger<DummyWelcomeActionService> _logger;

        public DummyWelcomeActionService(ILogger<DummyWelcomeActionService> logger)
        {
            _logger = logger;
        }

        public Task PerformWelcomeActionsAsync(string userId, string userEmail, string username)
        {
            _logger.LogInformation(
                "Welcome action performed for new user. UserId: {UserId}, Email: {Email}, Username: {Username}",
                userId, userEmail, username);

            // TODO: Add your custom welcome actions here, such as:
            // - Sending a welcome email
            // - Creating default user data
            // - Initializing user preferences
            // - Setting up user-specific resources

            return Task.CompletedTask;
        }
    }
}