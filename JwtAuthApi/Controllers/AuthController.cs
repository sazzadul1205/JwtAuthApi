using JwtAuthApi.Data;
using JwtAuthApi.DTOs;
using JwtAuthApi.Models;
using JwtAuthApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;

namespace JwtAuthApi.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AppDbContext _context;
        private readonly JwtService _jwtService;

        public AuthController(
            AppDbContext context,
            JwtService jwtService)
        {
            _context = context;
            _jwtService = jwtService;
        }

        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            // Check whether the username is already registered
            bool usernameExists = await _context.Users.AnyAsync(u => u.Username == request.Username);


            // If User name Exsisit Return Conflict message 
            if (usernameExists)
            {
                // Sends a 409 Conflict Response 
                return Conflict(new
                {
                    message = "Username is already taken."
                });
            }

            // Hash the password before storing it
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(request.Password);
            
            // Create the database user
            var user = new User
            {
                Username = request.Username,
                PasswordHash = passwordHash,
                CreatedAt = DateTime.UtcNow
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok(new
            {
                message = "Registration successful."
            });

        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            // Find the registered user
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == request.Username);

            // Reject unknown usernames
            if (user == null)
            {
                return Unauthorized(new
                {
                    message = "Invalid username or password."
                });
            }

            // Verify the submitted password against its stored hash
            bool passwordIsValid = BCrypt.Net.BCrypt.Verify(request.Password,user.PasswordHash);

            // Send the Same Message as the USername Rejection 
            if (!passwordIsValid)
            {
                return Unauthorized(new
                {
                    message = "Invalid username or password."
                });
            }


            // Generate a JWT for the authenticated user
            var token = _jwtService.GenerateToken(request.Username);

            return Ok(new
            {
                accessToken = token,
                tokenType = "Bearer"
            });
        }

        [Authorize]
        [HttpGet("me")]
        public IActionResult Me()
        {
            var response = new UserProfileResponse
            {
                // Get the User From the Token 
                Username = User.Identity?.Name ?? string.Empty
            };

            return Ok(response);
        }

        [Authorize]
        [HttpPut("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            // Get the User From the Token 
            var username = User.Identity?.Name;

            // If no User Found Send 401 
            if (username == null)
            {
                return Unauthorized();
            }

            // Get the User Data
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Username == username);

            // If no User Found Send 401 
            if (user == null)
            {
                return Unauthorized();
            }

            // Varify Curent Password With DB Saved Password
            bool currentPasswordIsValid = BCrypt.Net.BCrypt.Verify(request.CurrentPassword,user.PasswordHash);

            // If Varification Fails the send 400 and a Message 
            if (!currentPasswordIsValid)
            {
                return BadRequest(new
                {
                    message = "Current password is incorrect."
                });
            }

            // Hash the New Password
            user.PasswordHash = BCrypt.Net.BCrypt.HashPassword(request.NewPassword);

            await _context.SaveChangesAsync();

            return Ok(new
            {
                message = "Password changed successfully."
            });

        }

    }
}
