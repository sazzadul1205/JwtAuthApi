using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace JwtAuthApi.Services
{
    public class JwtService
    {
        private readonly IConfiguration _configuration;

        public JwtService(IConfiguration configuration)
        {
            _configuration = configuration;
        }

        public string GenerateToken(string username)
        {
            // Load JWT settings from appsettings.json and User Secrets
            var jwtSettings = _configuration.GetSection("Jwt");

            // Read the secret key; stop the application if it is missing
            var secretKey = jwtSettings["SecretKey"] ?? throw new InvalidOperationException("Jwt:SecretKey is not configured.");

            // Convert the secret key into the format JWT uses to verify token signatures
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKey));

            // Select the signing algorithm
            var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            // Store the user's identity in the token
            var claims = new[]
            {
                new Claim(ClaimTypes.Name, username)
            };

            // Create the JWT
            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(
                    double.Parse(jwtSettings["ExpirationMinutes"]!)),
                signingCredentials: credentials
            );

            // Convert the token into a string
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}