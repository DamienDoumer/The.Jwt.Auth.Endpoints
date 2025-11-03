namespace The.Jwt.Auth.Endpoints.Helpers;

/// <summary>
/// Service interface for performing welcome actions after a user account is successfully created.
/// Implementations should handle tasks like sending welcome emails, creating default user data,
/// or any other post-registration actions.
/// </summary>
public interface IWelcomeActionService
{
    /// <summary>
    /// Performs welcome actions for a newly created user.
    /// </summary>
    /// <param name="userId">The unique identifier of the newly created user.</param>
    /// <param name="userEmail">The email address of the newly created user.</param>
    /// <param name="username">The username of the newly created user.</param>
    /// <returns>A task representing the asynchronous operation.</returns>
    Task PerformWelcomeActionsAsync(string userId, string userEmail, string username);
}
