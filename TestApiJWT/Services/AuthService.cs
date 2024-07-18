using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TestApiJWT.Helpers;
using TestApiJWT.Models;

namespace TestApiJWT.Services
{
    // AuthService class handles user registration and JWT token generation
    public class AuthService : IAuthService
    {
        private readonly UserManager<ApplicationUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JWTSettings _jwt;

        // Constructor initializes the AuthService with necessary dependencies
        public AuthService(UserManager<ApplicationUser> userManager, RoleManager<IdentityRole> roleManager, IOptions<JWTSettings> jwt)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwt = jwt.Value;
        }

        // Method to register a new user and return authentication details
        public async Task<AuthModel> RegisterAsync(RegisterModel model)
        {
            // 1. Check if the email is already registered
            if (await _userManager.FindByEmailAsync(model.Email) is not null)
                return new AuthModel { Message = "Email is already registered!" };

            // 2. Check if the username is already taken
            if (await _userManager.FindByNameAsync(model.Username) is not null)
                return new AuthModel { Message = "Username is already registered!" };

            // 3. If email and username are unique, create a new ApplicationUser
            var user = new ApplicationUser
            {
                UserName = model.Username,
                Email = model.Email,
                FirstName = model.FirstName,
                LastName = model.LastName
            };

            // Attempt to create the user with the provided password
            var result = await _userManager.CreateAsync(user, model.Password);

            // If user creation fails, return the error messages
            if (!result.Succeeded)
            {
                var errors = string.Empty;
                foreach (var error in result.Errors)
                    errors += $"{error.Description},";

                return new AuthModel { Message = errors };
            }

            // Assign a default role to the new user (e.g., "User")
            await _userManager.AddToRoleAsync(user, "User");

            // Create a JWT token for the newly registered user
            var jwtSecurityToken = await CreateJwtToken(user);

            // Return authentication details including the JWT token
            return new AuthModel
            {
                Message = "Registration and authentication successful.",
                Email = user.Email,
                ExpiresOn = jwtSecurityToken.ValidTo,
                IsAuthenticated = true,
                Roles = new List<string> { "User" },
                Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken),
                Username = user.UserName
            };
        }

        public async Task<AuthModel> LoginAsync(LoginModel model)
        {
            var authModel = new AuthModel();

            // Find the user by their email
            var user = await _userManager.FindByEmailAsync(model.Email);

            // If user is null or password is incorrect, return with an error message
            if (user is null || !await _userManager.CheckPasswordAsync(user, model.Password))
            {
                authModel.Message = "Email or Password is incorrect!";
                return authModel;
            }

            // Generate a JWT token for the authenticated user
            var jwtSecurityToken = await CreateJwtToken(user);

            // Get the list of roles assigned to the user
            var rolesList = await _userManager.GetRolesAsync(user);

            // Populate the authModel with successful login details
            authModel.IsAuthenticated = true;
            authModel.Token = new JwtSecurityTokenHandler().WriteToken(jwtSecurityToken);
            authModel.Email = user.Email;
            authModel.Username = user.UserName;
            authModel.ExpiresOn = jwtSecurityToken.ValidTo;
            authModel.Roles = rolesList.ToList();

            return authModel;
        }

        public async Task<string> AddRoleAsync(AddRoleModel model)
        {
            // Find the user by their ID
            var user = await _userManager.FindByIdAsync(model.UserId);

            // Check if the user exists and the role exists
            if (user is null || !await _roleManager.RoleExistsAsync(model.Role))
                return "Invalid user ID or Role";

            // Check if the user is already in the role
            if (await _userManager.IsInRoleAsync(user, model.Role))
                return "User already assigned to this role";

            // Add the user to the role
            var result = await _userManager.AddToRoleAsync(user, model.Role);

            // Return the result of the operation
            return result.Succeeded ? string.Empty : "Something went wrong";
        }


        // Method to create a JWT token for the user
        private async Task<JwtSecurityToken> CreateJwtToken(ApplicationUser user)
        {
            // Retrieve user claims and roles
            var userClaims = await _userManager.GetClaimsAsync(user);
            var roles = await _userManager.GetRolesAsync(user);
            var roleClaims = new List<Claim>();

            // Create claims for each role
            foreach (var role in roles)
                roleClaims.Add(new Claim("roles", role));

            // Combine user claims and role claims
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.UserName),
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim("uid", user.Id)
            }
            .Union(userClaims)
            .Union(roleClaims);

            // Define signing credentials using the symmetric security key
            var symmetricSecurityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwt.Key));
            var signingCredentials = new SigningCredentials(symmetricSecurityKey, SecurityAlgorithms.HmacSha256);

            // Create the JWT token with issuer, audience, claims, and expiration
            var jwtSecurityToken = new JwtSecurityToken(
                issuer: _jwt.Issuer,
                audience: _jwt.Audience,
                claims: claims,
                expires: DateTime.Now.AddDays(_jwt.DurationInDays),
                signingCredentials: signingCredentials);

            return jwtSecurityToken;
        }
    }
}
