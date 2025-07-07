using AspNetCore.Jwt.Auth.Endpoints.TestAPI.Data.Models;
using Microsoft.AspNetCore.Identity;

namespace AspNetCore.Jwt.Auth.Endpoints.Tests;

public class MockEmailSender : IEmailSender<ApplicationUser>
{
    public List<EmailSentRecord> SentEmails { get; } = new();

    public Task SendConfirmationLinkAsync(ApplicationUser user, string email, string confirmationLink)
    {
        SentEmails.Add(new EmailSentRecord
        {
            Type = EmailType.ConfirmationLink,
            User = user,
            Email = email,
            Content = confirmationLink,
            SentAt = DateTime.UtcNow
        });
        return Task.CompletedTask;
    }

    public Task SendPasswordResetLinkAsync(ApplicationUser user, string email, string resetLink)
    {
        SentEmails.Add(new EmailSentRecord
        {
            Type = EmailType.PasswordResetLink,
            User = user,
            Email = email,
            Content = resetLink,
            SentAt = DateTime.UtcNow
        });
        return Task.CompletedTask;
    }

    public Task SendPasswordResetCodeAsync(ApplicationUser user, string email, string resetCode)
    {
        SentEmails.Add(new EmailSentRecord
        {
            Type = EmailType.PasswordResetCode,
            User = user,
            Email = email,
            Content = resetCode,
            SentAt = DateTime.UtcNow
        });
        return Task.CompletedTask;
    }

    public void Clear()
    {
        SentEmails.Clear();
    }
}

public class EmailSentRecord
{
    public EmailType Type { get; set; }
    public ApplicationUser User { get; set; } = null!;
    public string Email { get; set; } = string.Empty;
    public string Content { get; set; } = string.Empty;
    public DateTime SentAt { get; set; }
}

public enum EmailType
{
    ConfirmationLink,
    PasswordResetLink,
    PasswordResetCode
}