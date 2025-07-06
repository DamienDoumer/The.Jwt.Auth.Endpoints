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

## Google Social Auth:
- Configure Firebase Auth
- In the firebase console, download the Service Account Key json file for your project.
- Add this file somewhere safe but accessible to your project. 
- In the demo project, adding it at the root of the project will be ok
  - Set the file's Build action to __Content__, and select __Copy Always__
- Then as shown in the test project, you can configure Google auth this way:
```
    options.GoogleFirebaseAuthOptions = new AppOptions()
    {
        Credential = GoogleCredential.FromFile("FirebaseServiceAccountFile.json")
    };
```