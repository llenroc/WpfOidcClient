using IdentityModel.Client;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Windows;
using System.Windows.Controls;
using System.Windows.Data;
using System.Windows.Documents;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using System.Windows.Navigation;
using System.Windows.Shapes;

namespace WpfOidcClient
{
    /// <summary>
    /// Interaction logic for MainWindow.xaml
    /// </summary>
    public partial class MainWindow : Window
    {
        LoginWebView _login;
        OidcClient _client;

        const string AUTHORITY = "https://localhost:44333/core";

        public MainWindow()
        {
            InitializeComponent();

            _login = new LoginWebView();
            _login.Done += _login_Done;

            _client = new OidcClient(AUTHORITY);

            Loaded += MainWindow_Loaded;
            IdentityTextBox.Visibility = Visibility.Hidden;
        }

        void MainWindow_Loaded(object sender, RoutedEventArgs e)
        {
            _login.Owner = this;
        }

        private void LoginButton_Click(object sender, RoutedEventArgs e)
        {
            _login.Start(
                _client,
                "implicitclient",
                "oob://localhost/wpfclient",
                scope: "openid email profile api1",
                responseType: "id_token token",
                responseMode: "form_post");
        }

        void _login_Done(object sender, LoginResult e)
        {
            if (!e.IsSuccess)
            {
                MessageBox.Show("Login failed.");
            }
            else
            {
                var sb = new StringBuilder(128);

                e.Principal.Claims.ToList().ForEach(c => sb.AppendFormat("{0}: {1}\n", c.Type, c.Value));
                
                if (!string.IsNullOrEmpty(e.AccessToken))
                {
                    sb.Append("access_token: " + e.AccessToken);
                }

                IdentityTextBox.Visibility = System.Windows.Visibility.Visible;
                IdentityTextBox.Text = sb.ToString();
            }
        }
    }
}