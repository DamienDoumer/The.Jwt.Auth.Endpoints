# Why AspNetCore.Jwt.Auth.Endpoints ?

Not long ago, Microsoft release [Identity endpoints](https://learn.microsoft.com/en-us/aspnet/core/security/authentication/identity-api-authorization?view=aspnetcore-9.0) as part of .NET 8, but 
decided to make it:
- Difficult to extend
- Run with a proprietary token that is not JWT, and behaves in a kind of opaque way.

I thought it might be usefull to have a library that does exactly what Identity endpoints do, but with JWT tokens.

## NOTE
This is still in it earliest versions, and will very soon be available on nuget, and ready for simple scenarios in production.
This package will soon be ready for quick prototyping and it will be safe enough to deploy in productionm but,
it is recommended to leverage advanced authentication tools like Duende Identity server, for proper and secure authentication.
