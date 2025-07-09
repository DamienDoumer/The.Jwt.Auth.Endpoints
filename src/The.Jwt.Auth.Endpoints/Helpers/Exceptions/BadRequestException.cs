namespace The.Jwt.Auth.Endpoints.Helpers.Exceptions;

public class BadRequestException : BaseException
{
    public BadRequestException(string message, string errorCode)
        : base(message, errorCode, StatusCodes.Status400BadRequest) { }

    public BadRequestException(string message)
        : base(message, StatusCodes.Status400BadRequest) { }
}
