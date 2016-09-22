using Google.Apis.Auth.OAuth2;
using Google.Apis.Gmail.v1;
using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Runtime.InteropServices.WindowsRuntime;
using Windows.Foundation;
using Windows.Foundation.Collections;
using Windows.UI.Xaml;
using Windows.UI.Xaml.Controls;
using Windows.UI.Xaml.Controls.Primitives;
using Windows.UI.Xaml.Data;
using Windows.UI.Xaml.Input;
using Windows.UI.Xaml.Media;
using Windows.UI.Xaml.Navigation;
using Windows.ApplicationModel.Activation;
using System.Threading;
using System.Threading.Tasks;
using Google.Apis.Services;
using System.Collections.ObjectModel;
using Windows.Security.Cryptography;
using Windows.Security.Cryptography.Core;
using Windows.Storage;
using Windows.Storage.Streams;
using Google.Apis.Auth.OAuth2.Flows;
using Google.Apis.Auth.OAuth2.Responses;
using Google.Apis.Util.Store;
using HulloVoicemail.Common;
using System.Net.Http;
using System.Text;
using Windows.Data.Json;

// The Blank Page item template is documented at http://go.microsoft.com/fwlink/?LinkId=402352&clcid=0x409

namespace HulloVoicemail
{
    /// <summary>
    /// An empty page that can be used on its own or navigated to within a Frame.
    /// </summary>
    public sealed partial class MainPage : Page//, IWebAuthenticationContinuable
    {
        public static MainPage Current { get; private set; }
        private static readonly string[] Scopes = { GmailService.Scope.GmailReadonly };
        private TokenResponse _token;


        const string authorizationEndpoint = "https://accounts.google.com/o/oauth2/v2/auth";
        const string tokenEndpoint = "https://www.googleapis.com/oauth2/v4/token";
        const string redirectURI = "uwp.hullovoicemail:/oauth2redirect";
//        const string redirectURI = "http://localhost";
        const string clientID = "566731723208-25nl9jq03qjqhevmem2lgnji8krprno5.apps.googleusercontent.com";
//        const string clientID = "566731723208-3umqp8q4s3kn2ili3iip8gifao9mf9t7.apps.googleusercontent.com";

        /*
                private static string ApplicationName = "HulloVoicemail Client";
        */

        public static ClientSecrets Secrets = new ClientSecrets()
        {
            ClientId = "566731723208-3umqp8q4s3kn2ili3iip8gifao9mf9t7.apps.googleusercontent.com",
            ClientSecret = "sYiu8ytE5hbrSwFXJealyzbY"
        };

        private UserCredential _credential;
        private GmailService _service;

        public MainPage()
        {
            this.InitializeComponent();
        }

        private async Task AuthenticateAsync()
        {

            string state = randomDataBase64url(32);
            string code_verifier = randomDataBase64url(32);
            string code_challenge = base64urlencodeNoPadding(sha256(code_verifier));
            const string code_challenge_method = "S256";

            // Stores the state and code_verifier values into local settings.
            // Member variables of this class may not be present when the app is resumed with the
            // authorization response, so LocalSettings can be used to persist any needed values.
            ApplicationDataContainer localSettings = ApplicationData.Current.LocalSettings;
            localSettings.Values["state"] = state;
            localSettings.Values["code_verifier"] = code_verifier;

            // Creates the OAuth 2.0 authorization request.
            string authorizationRequest = string.Format("{0}?response_type=code&scope={6}&redirect_uri={1}&client_id={2}&state={3}&code_challenge={4}&code_challenge_method={5}",
                authorizationEndpoint,
                System.Uri.EscapeDataString(redirectURI),
                clientID,
                state,
                code_challenge,
                code_challenge_method,
                GmailService.Scope.GmailReadonly);

            // Opens the Authorization URI in the browser.
            var success = Windows.System.Launcher.LaunchUriAsync(new Uri(authorizationRequest));




            //if (_service != null)
            //    return;

            //_credential = await GoogleWebAuthorizationBroker.AuthorizeAsync(
            //    new Uri("ms-appx:///client_secrets.json"),
            //    new[] { GmailService.Scope.GmailReadonly },
            //    "user",
            //    CancellationToken.None);

            //var initializer = new BaseClientService.Initializer()
            //{
            //    HttpClientInitializer = _credential,
            //    ApplicationName = "HulloVoicemail Client"
            //};

        }

        protected override void OnNavigatedTo(NavigationEventArgs e)
        {
            if (e.Parameter is Uri)
            {
                // Gets URI from navigation parameters.
                Uri authorizationResponse = (Uri) e.Parameter;
                string queryString = authorizationResponse.Query;

                // Parses URI params into a dictionary
                // ref: http://stackoverflow.com/a/11957114/72176
                Dictionary<string, string> queryStringParams =
                    queryString.Substring(1).Split('&')
                        .ToDictionary(c => c.Split('=')[0],
                            c => Uri.UnescapeDataString(c.Split('=')[1]));

                if (queryStringParams.ContainsKey("error"))
                {
                    // Log some kind of error or something
                    return;
                }

                if (!queryStringParams.ContainsKey("code")
                    || !queryStringParams.ContainsKey("state"))
                {
                    // Log some kind of error or something
                    return;
                }

                // Gets the Authorization code & state
                string code = queryStringParams["code"];
                string incoming_state = queryStringParams["state"];

                // Retrieves the expected 'state' value from local settings (saved when the request was made).
                ApplicationDataContainer localSettings = ApplicationData.Current.LocalSettings;
                string expected_state = (String) localSettings.Values["state"];

                // Compares the receieved state to the expected value, to ensure that
                // this app made the request which resulted in authorization
                if (incoming_state != expected_state)
                {
                    // Log some kind of error or something
                    return;
                }

                // Resets expected state value to avoid a replay attack.
                localSettings.Values["state"] = null;

                // Authorization Code is now ready to use!
                //output(Environment.NewLine + "Authorization code: " + code);

                string code_verifier = (String) localSettings.Values["code_verifier"];
                performCodeExchangeAsync(code, code_verifier);
            }
        }

        async void performCodeExchangeAsync(string code, string code_verifier)
        {
            // Builds the Token request
            string tokenRequestBody = string.Format("code={0}&redirect_uri={1}&client_id={2}&code_verifier={3}&scope=&grant_type=authorization_code",
                code,
                System.Uri.EscapeDataString(redirectURI),
                clientID,
                code_verifier
                );
            StringContent content = new StringContent(tokenRequestBody, Encoding.UTF8, "application/x-www-form-urlencoded");

            // Performs the authorization code exchange.
            HttpClientHandler handler = new HttpClientHandler();
            handler.AllowAutoRedirect = true;
            HttpClient client = new HttpClient(handler);

            HttpResponseMessage response = await client.PostAsync(tokenEndpoint, content);
            string responseString = await response.Content.ReadAsStringAsync();

            if (!response.IsSuccessStatusCode)
            {
                // Log some kind of error or something
                return;
            }

            // Sets the Authentication header of our HTTP client using the acquired access token.
            JsonObject tokens = JsonObject.Parse(responseString);
            string refreshToken = tokens.GetNamedString("refresh_token");

            var token = new TokenResponse {RefreshToken = refreshToken};
            var flow = new GoogleAuthorizationCodeFlow(new GoogleAuthorizationCodeFlow.Initializer());
            //{
            //    ClientSecrets = Secrets
            //});
            var credentials = new UserCredential(flow, "user", token);
            var initializer = new BaseClientService.Initializer()
            {
                HttpClientInitializer = credentials,
                ApplicationName = "HulloVoicemail"
            };

            _service = new GmailService(initializer);
        }

        /// <summary>
        /// Returns URI-safe data with a given input length.
        /// </summary>
        /// <param name="length">Input length (nb. output will be longer)</param>
        /// <returns></returns>
        public static string randomDataBase64url(uint length)
        {
            IBuffer buffer = CryptographicBuffer.GenerateRandom(length);
            return base64urlencodeNoPadding(buffer);
        }

        /// <summary>
        /// Returns the SHA256 hash of the input string.
        /// </summary>
        /// <param name="inputStirng"></param>
        /// <returns></returns>
        public static IBuffer sha256(string inputStirng)
        {
            HashAlgorithmProvider sha = HashAlgorithmProvider.OpenAlgorithm(HashAlgorithmNames.Sha256);
            IBuffer buff = CryptographicBuffer.ConvertStringToBinary(inputStirng, BinaryStringEncoding.Utf8);
            return sha.HashData(buff);
        }

        /// <summary>
        /// Base64url no-padding encodes the given input buffer.
        /// </summary>
        /// <param name="buffer"></param>
        /// <returns></returns>
        public static string base64urlencodeNoPadding(IBuffer buffer)
        {
            string base64 = CryptographicBuffer.EncodeToBase64String(buffer);

            // Converts base64 to base64url.
            base64 = base64.Replace("+", "-");
            base64 = base64.Replace("/", "_");
            // Strips padding.
            base64 = base64.Replace("=", "");

            return base64;
        }

        private void button_Click(object sender, RoutedEventArgs e)
        {
            AuthenticateAsync();
        }

        private void Button1_OnClick(object sender, RoutedEventArgs e)
        {
            var request = _service.Users.Labels.List("me");

            var labels = request.Execute().Labels;
            ObservableCollection<string> listItems = new ObservableCollection<string>();

            foreach (var label in labels)
            {
                listItems.Add(label.Name);
            }

            listView.ItemsSource = listItems;
        }
    }
}