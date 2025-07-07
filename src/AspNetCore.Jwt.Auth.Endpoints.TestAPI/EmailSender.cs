using AspNetCore.Jwt.Auth.Endpoints.TestAPI.Data.Models;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Jwt.Auth.Endpoints.TestAPI;

public class EmailSender : IEmailSender<ApplicationUser>
{
    private readonly ILogger<EmailSender> _logger;

    public EmailSender(ILogger<EmailSender> logger)
    {
        _logger = logger;
    }

    public Task SendConfirmationLinkAsync(ApplicationUser user, string email, string confirmationLink)
    {
        _logger.LogInformation("Sending confirmation email to {Email} with link: {Link}", email, confirmationLink);
        return Task.CompletedTask;
    }

    public Task SendPasswordResetLinkAsync(ApplicationUser user, string email, string resetLink)
    {
        _logger.LogInformation("Sending password reset email to {Email} with link: {Link}", email, resetLink);
        return Task.CompletedTask;
    }

    public Task SendPasswordResetCodeAsync(ApplicationUser user, string email, string resetCode)
    {
        _logger.LogInformation("Sending password reset code to {Email} with code: {Code}", email, resetCode);
        return Task.CompletedTask;
    }
}