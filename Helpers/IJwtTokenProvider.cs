namespace Jwt.Auth.Endpoints.Helpers;
internal interface IJwtTokenProvider
{
    (string jwtToken, string refreshToken) CreateToken(string )
}
