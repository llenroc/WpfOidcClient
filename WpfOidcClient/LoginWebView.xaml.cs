using IdentityModel;
using IdentityModel.Client;
using mshtml;
using System;
using System.Linq;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Navigation;

namespace WpfOidcClient
{
    public partial class LoginWebView : Window
    {
        public AuthorizeResponse AuthorizeResponse { get; set; }
        public event EventHandler<LoginResult> Done;

        OidcClient _client;
        string _clientId;
        string _redirectUri;
        string _state;
        string _nonce;

        public LoginWebView()
        {
            InitializeComponent();
            webView.Navigating += webView_Navigating;

            Closing += LoginWebView_Closing;
        }

        public void Start(
            OidcClient client,
            string clientId,
            string redirectUri,
            string scope = "openid",
            string responseType = "id_token",
            string responseMode = "fragment")
        {
            _redirectUri = redirectUri;
            _client = client;
            _clientId = clientId;

            _state = CryptoRandom.CreateUniqueId();
            _nonce = CryptoRandom.CreateUniqueId();
            
            var request = new AuthorizeRequest(client.OpenIdConfiguration.AuthorizationEndpoint);
            var url = request.CreateAuthorizeUrl(
                clientId,
                responseType,
                scope,
                redirectUri,
                _state,
                _nonce,
                responseMode: responseMode);

            this.Visibility = System.Windows.Visibility.Visible;
            webView.Navigate(url);
        }

        void LoginWebView_Closing(object sender, System.ComponentModel.CancelEventArgs e)
        {
            e.Cancel = true;
            this.Visibility = Visibility.Hidden;
        }

        private void webView_Navigating(object sender, NavigatingCancelEventArgs e)
        {
            if (e.Uri.ToString().StartsWith(_redirectUri))
            {
                if (e.Uri.AbsoluteUri.Contains("#"))
                {
                    AuthorizeResponse = new AuthorizeResponse(e.Uri.AbsoluteUri);
                }
                // form_post support
                else
                {
                    var document = (IHTMLDocument3)((WebBrowser)sender).Document;
                    var inputElements = document.getElementsByTagName("INPUT").OfType<IHTMLElement>();
                    var resultUrl = "?";

                    foreach (var input in inputElements)
                    {
                        resultUrl += input.getAttribute("name") + "=";
                        resultUrl += input.getAttribute("value") + "&";
                    }

                    resultUrl = resultUrl.TrimEnd('&');
                    AuthorizeResponse = new AuthorizeResponse(resultUrl);
                }

                e.Cancel = true;
                this.Visibility = Visibility.Hidden;

                ValidateResponse(AuthorizeResponse);
            }
        }

        private void ValidateResponse(AuthorizeResponse response)
        {
            var result = _client.Validate(response, _clientId, _state, _nonce);

            if (Done != null)
            {
                Done.Invoke(this, result);
            }
        }
    }
}