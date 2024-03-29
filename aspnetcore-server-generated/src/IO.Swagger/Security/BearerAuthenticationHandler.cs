using System.Net.Http.Headers;
using System.Security.Claims;
using System.Text.Encodings.Web;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace IO.Swagger.Security
{
    /// <summary>
    /// class to handle bearer authentication.
    /// </summary>
    public class BearerAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        /// <summary>
        /// scheme name for authentication handler.
        /// </summary>
        public const string SchemeName = "Bearer";

        // super basic way to get the token without handling token issuing (not required by the assignment)
        private const string TOKEN = "d0n87s07SABD7d7hns8asgb8d7AS7duHiufhoshdba";

        public BearerAuthenticationHandler(IOptionsMonitor<AuthenticationSchemeOptions> options, ILoggerFactory logger, UrlEncoder encoder, ISystemClock clock) : base(options, logger, encoder, clock)
        {
        }

        /// <summary>
        /// verify that require authorization header exists.
        /// </summary>
        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            if (!Request.Headers.ContainsKey("Authorization"))
            {
                return AuthenticateResult.Fail("Missing Authorization Header");
            }
            AuthenticationHeaderValue authHeader;
            try
            {
                authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
            }
            catch
            {
                return AuthenticateResult.Fail("Invalid Authorization Header");
            }
            
            //handle token authorization
            if (authHeader.Scheme != SchemeName)
                return AuthenticateResult.Fail($"Unaccepted authentication type ({authHeader.Scheme})");

            if (authHeader.Parameter != TOKEN)
                return AuthenticateResult.Fail("Token unauthorised");

            // this was auto generated by swagger.
            // i don't need any claims logic for the assignment so i left it as is.
            var claims = new[] {
                new Claim(ClaimTypes.NameIdentifier, "changeme"),
                new Claim(ClaimTypes.Name, "changeme"),
            };
            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);
            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
    }
}
