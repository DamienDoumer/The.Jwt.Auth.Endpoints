namespace The.Jwt.Auth.Endpoints.Helpers.Exceptions;

public class BaseException : Exception
{
    public string? ErrorCode { get; set; }
    public int? StatusCode { get; set; }

    public BaseException(
        string message,
        string errorCode,
        int statusCode = StatusCodes.Status500InternalServerError
    )
        : base(message)
    {
        ErrorCode = errorCode;
        StatusCode = statusCode;
    }

    public BaseException(string message, int statusCode)
        : base(message)
    {
        StatusCode = statusCode;
    }

    public BaseException(string message, string errorCode, Exception innerException)
        : base(message, innerException)
    {
        ErrorCode = errorCode;
    }
}
