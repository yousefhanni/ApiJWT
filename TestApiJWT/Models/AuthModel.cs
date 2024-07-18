namespace TestApiJWT.Models
{
    // AuthModel class is designed to encapsulate the authentication response details
    public class AuthModel
    {
        // Message indicating the result of the authentication process
        public string Message { get; set; }

        // Flag indicating whether the user is authenticated
        public bool IsAuthenticated { get; set; }

        // The username of the authenticated user
        public string Username { get; set; }

        // The email of the authenticated user
        public string Email { get; set; }

        // List of roles assigned to the authenticated user
        public List<string> Roles { get; set; }

        // JWT token generated for the authenticated user
        public string Token { get; set; }

        // Expiration date and time of the JWT token
        public DateTime ExpiresOn { get; set; }
    }
}
