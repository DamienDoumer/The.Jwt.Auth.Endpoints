using System.ComponentModel.DataAnnotations;

namespace The.Jwt.Auth.Endpoints.Endpoints.Requests;

internal class GoogleAuthRequestModel
{
    /// <summary>
    /// This corresponds to the firebase id token goten when the client
    /// performs the social auth's first part on its side. Then hands
    /// over the rest to the server.
    /// </summary>
    [Required]
    [StringLength(5000)]
    public string Token { get; set; }

    public GoogleAuthRequestModel()
    {
        Token = string.Empty;
    }
}
