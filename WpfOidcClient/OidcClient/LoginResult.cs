using IdentityModel.Client;
using System;
using System.Security.Claims;

namespace WpfOidcClient
{
    public class LoginResult
    {
        public bool IsSuccess { get; set; }

        public AuthorizeResponse AuthorizeResponse { get; set; }
        public ClaimsPrincipal Principal { get; set; }
        public string AccessToken { get; set; }
        public DateTime AccessTokenExpiration { get; set; }
    }
}