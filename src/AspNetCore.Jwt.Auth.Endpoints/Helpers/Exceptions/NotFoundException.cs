namespace Jwt.Auth.Endpoints.Helpers.Exceptions;

public class NotFoundException : BaseException
{
    public NotFoundException(string message, string errorCode)
        : base(message, errorCode, StatusCodes.Status404NotFound) { }

    public NotFoundException(string message)
        : base(message, string.Empty, StatusCodes.Status404NotFound) { }
}
