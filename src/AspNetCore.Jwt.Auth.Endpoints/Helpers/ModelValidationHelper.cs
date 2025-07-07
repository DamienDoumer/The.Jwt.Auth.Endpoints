using System.ComponentModel.DataAnnotations;

namespace AspNetCore.Jwt.Auth.Endpoints.Helpers;

internal static class ModelValidationHelper
{
    public static ValidationResult? ValidateModel<T>(this T model) where T : class
    {
        var context = new ValidationContext(model);
        var results = new List<ValidationResult>();
        
        if (Validator.TryValidateObject(model, context, results, validateAllProperties: true))
        {
            return null;
        }
        
        return results.FirstOrDefault();
    }
    
    public static bool IsValidEmail(string email)
    {
        if (string.IsNullOrWhiteSpace(email))
            return false;
            
        var emailAttribute = new EmailAddressAttribute();
        return emailAttribute.IsValid(email);
    }
    
    public static IResult CreateValidationErrorResult(string errorMessage)
    {
        return Results.Problem(new ProblemDetails
        {
            Title = errorMessage,
            Status = StatusCodes.Status400BadRequest
        });
    }
    
    public static IResult CreateValidationErrorResult(this ValidationResult validationResult)
    {
        return Results.Problem(new ProblemDetails
        {
            Title = validationResult.ErrorMessage ?? "Validation failed",
            Status = StatusCodes.Status400BadRequest
        });
    }
}