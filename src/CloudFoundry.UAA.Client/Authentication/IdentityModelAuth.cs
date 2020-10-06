using System.Collections.Generic;
using System.Net;
using System.Net.Http;
using IdentityModel.Client;

namespace CloudFoundry.UAA.Authentication
{
    using System;
    using System.Globalization;
    using System.Threading.Tasks;
    using CloudFoundry.CloudController.Common.Http;
    using CloudFoundry.UAA;
    using CloudFoundry.UAA.Exceptions;

    internal class IdentityModelAuth : IAuthentication
    {
        // CF defaults
        private string oauthClient = "cf";

        private string oauthSecret = string.Empty;
        private Uri oauthTarget;
        private IWebProxy httpProxy;
        private bool skipCertificateValidation;
        private Token token = new Token();

        internal IdentityModelAuth(Uri authenticationUri)
            : this(authenticationUri, null)
        {
        }

        internal IdentityModelAuth(Uri authenticationUri, IWebProxy httpProxy)
            : this(authenticationUri, httpProxy, false)
        {
        }

        internal IdentityModelAuth(Uri authenticationUri, IWebProxy httpProxy, bool skipCertificateValidation)
        {
            this.oauthTarget = authenticationUri;
            this.httpProxy = httpProxy;
            this.skipCertificateValidation = skipCertificateValidation;
        }

        public Uri OAuthUri
        {
            get
            {
                return this.oauthTarget;
            }
        }

        public async Task<Token> Authenticate(CloudCredentials credentials)
        {
            if (credentials == null)
            {
                throw new ArgumentNullException("credentials");
            }
            using (var httpClientHandler = new AcceptHeaderOverrideHttpClientHandler())
            {
                this.httpProxy = httpClientHandler.Proxy;
                

                httpClientHandler.OverrideAcceptHeader = "application/json";
                httpClientHandler.SkipCertificateValidation = this.skipCertificateValidation;

                var client = new HttpClient(httpClientHandler);
                var tokenRequest = new PasswordTokenRequest()
                {
                    Address = this.oauthTarget.ToString(),
                    ClientId = this.oauthClient,
                    ClientSecret = this.oauthSecret,
                    UserName = credentials.User,
                    Password = credentials.Password
                };
                tokenRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", "Y2Y6");
                var tokenResponse = await client.RequestPasswordTokenAsync(tokenRequest);
                this.token.Expires = DateTime.Now;


                CheckTokenResponseError(tokenResponse);

                this.token.AccessToken = tokenResponse.AccessToken;
                this.token.RefreshToken = tokenResponse.RefreshToken;
                this.token.Expires = this.token.Expires.AddSeconds(tokenResponse.ExpiresIn);
            }

            return this.token;
        }

        public async Task<Token> AuthenticateRefreshToken(string refreshToken)
        {
            this.token.Expires = DateTime.Now;
            var tokenResponse = await this.RefreshToken(refreshToken);
            this.token.Expires = this.token.Expires.AddSeconds(tokenResponse.ExpiresIn);
            this.token.AccessToken = tokenResponse.AccessToken;
            this.token.RefreshToken = tokenResponse.RefreshToken;

            return this.token;
        }

        public async Task<Token> AuthenticatePasscode(string passcode)
        {
            using (var httpClientHandler = new AcceptHeaderOverrideHttpClientHandler())
            {
                this.httpProxy = httpClientHandler.Proxy;


                httpClientHandler.OverrideAcceptHeader = "application/json";
                httpClientHandler.SkipCertificateValidation = this.skipCertificateValidation;

                var client = new HttpClient(httpClientHandler);
                var tokenRequest = new TokenRequest()
                {
                    Address = this.oauthTarget.ToString(),
                    ClientId = this.oauthClient,
                    GrantType = "password",
                    Parameters = new Dictionary<string, string> { { "passcode", passcode } }
                };
                tokenRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", "Y2Y6");
                var tokenResponse = await client.RequestTokenAsync(tokenRequest);
                this.token.Expires = DateTime.Now;


                CheckTokenResponseError(tokenResponse);

                this.token.AccessToken = tokenResponse.AccessToken;
                this.token.RefreshToken = tokenResponse.RefreshToken;
                this.token.Expires = this.token.Expires.AddSeconds(tokenResponse.ExpiresIn);
            }

            return this.token;
        }

        public async Task<Token> GetToken()
        {
            if (this.token == null)
            {
                return this.token;
            }

            // Check to see if token is about to expire
            if (this.token.Expires < DateTime.Now)
            {
                this.token.Expires = DateTime.Now;
                var tokenResponse = await this.RefreshToken(this.token.RefreshToken);

                this.token.AccessToken = tokenResponse.AccessToken;
                this.token.RefreshToken = tokenResponse.RefreshToken;
                this.token.Expires = this.token.Expires.AddSeconds(tokenResponse.ExpiresIn);
            }

            return this.token;
        }

        private static void CheckTokenResponseError(TokenResponse tokenResponse)
        {
            if (tokenResponse.IsError)
            {
                throw new AuthenticationException(
                    string.Format(
                    CultureInfo.InvariantCulture,
                    "Unable to connect to target. HTTP Error: {0}. HTTP Error Code {1}",
                    tokenResponse.HttpErrorReason,
                    tokenResponse.HttpStatusCode));
            }

            if (tokenResponse.IsError)
            {
                throw new AuthenticationException(
                    string.Format(
                    CultureInfo.InvariantCulture,
                    "Unable to connect to target. Error message: {0}",
                    tokenResponse.Error));
            }
        }

        private async Task<TokenResponse> RefreshToken(string refreshToken)
        {
            using (var httpClientHandler = new AcceptHeaderOverrideHttpClientHandler())
            {
                this.httpProxy = httpClientHandler.Proxy;


                httpClientHandler.OverrideAcceptHeader = "application/json";
                httpClientHandler.SkipCertificateValidation = this.skipCertificateValidation;
                var client = new HttpClient(httpClientHandler);
                
                var tokenRequest = new RefreshTokenRequest()
                {
                    Address = this.oauthTarget.ToString(),
                    RefreshToken = refreshToken
                };
                tokenRequest.Headers.Authorization = new System.Net.Http.Headers.AuthenticationHeaderValue("Basic", "Y2Y6");
                var tokenResponse = await client.RequestRefreshTokenAsync(tokenRequest);
                CheckTokenResponseError(tokenResponse);
                return tokenResponse;
            }
        }
    }
}
