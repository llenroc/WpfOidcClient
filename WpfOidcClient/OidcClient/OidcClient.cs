using IdentityModel;
using IdentityModel.Client;
using Microsoft.IdentityModel.Protocols;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens;
using System.Linq;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using System.Threading.Tasks;

namespace WpfOidcClient
{
    public class OidcClient
    {
        readonly string _authority;
        private OpenIdConnectConfiguration _configuration;

        public OpenIdConnectConfiguration OpenIdConfiguration
        {
            get
            {
                if (_configuration == null)
                {
                    var manager = new ConfigurationManager<OpenIdConnectConfiguration>(_authority);
                    _configuration = AsyncHelper.RunSync(async () => await manager.GetConfigurationAsync());
                }

                return _configuration;
            }
        }

        public IList<X509Certificate2> SigningCertificates
        {
            get
            {
                var certs = new List<X509Certificate2>(
                    from key in _configuration.JsonWebKeySet.Keys
                    select new X509Certificate2(Convert.FromBase64String(key.X5c.First())));

                return certs;
            }
        }

        public OidcClient(string authority)
        {
            JwtSecurityTokenHandler.InboundClaimTypeMap = new Dictionary<string, string>();

            if (!authority.EndsWith("/"))
            {
                authority += "/";
            }

            _authority = authority + ".well-known/openid-configuration";
        }

        public LoginResult Validate(AuthorizeResponse response, string clientId, string state = "", string nonce = "")
        {
            var result = new LoginResult { AuthorizeResponse = response };

            if (response.IsError)
            {
                return result;
            }

            // validate state
            if (!string.Equals(response.State, state))
            {
                return result;
            }

            // validate id_token (issuer, audience, signature)
            var handler = new JwtSecurityTokenHandler();
            var parameters = new TokenValidationParameters
            {
                ValidIssuer = _configuration.Issuer,
                ValidAudience = clientId,
                IssuerSigningTokens = SigningCertificates.Select(c => new X509SecurityToken(c))
            };

            SecurityToken token;
            result.Principal = handler.ValidateToken(response.IdentityToken, parameters, out token);

            // validate nonce
            var nonceClaim = result.Principal.FindFirst("nonce");

            if (nonceClaim == null)
            {
                return result;
            }

            if (!string.Equals(nonce, nonceClaim.Value, StringComparison.OrdinalIgnoreCase))
            {
                return result;
            }

            // validate at_hash
            if (!string.IsNullOrEmpty(response.AccessToken))
            {
                var atHash = result.Principal.FindFirst("at_hash");
                if (atHash == null)
                {
                    return result;
                }

                // validate at_hash
                using (var algo = SHA256.Create())
                {
                    var hash = algo.ComputeHash(Encoding.ASCII.GetBytes(response.AccessToken));
                    byte[] h2 = new byte[16];
                    Array.Copy(hash, h2, 16);

                    var haseB64 = Base64Url.Encode(h2);

                    if (!haseB64.Equals(atHash.Value))
                    {
                        return result;
                    }

                    result.AccessToken = response.AccessToken;
                }
            }

            result.IsSuccess = true;
            return result;
        }
    }
}
