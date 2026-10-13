
using JwtAuthApi.DTOs;
using JwtAuthApi.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthApi.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtService _jwtService;

        public AuthController(
            JwtService jwtService,
            UserManager<IdentityUser> userManager)
        {
            _jwtService = jwtService;
            _userManager = userManager;
        }

        // Register a new user using ASP.NET Core Identity.
        [HttpPost("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterRequest request)
        {
            // Create a new Identity user.
            var user = new IdentityUser
            {
                UserName = request.Username
            };

            // Identity hashes the password and saves the user.
            var result = await _userManager.CreateAsync(user,request.Password);

            // Return validation errors if registration fails.
            if (!result.Succeeded)
            {
                return BadRequest(new
                {
                    errors = result.Errors.Select(error => error.Description)
                });
            }

            return Ok(new
            {
                message = "Registration successful."
            });
        }

        // Authenticate a user and issue a JWT access token.
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest request)
        {
            // Find the user by username.
            var user = await _userManager.FindByNameAsync(request.Username);

            // Reject unknown usernames.
            if (user == null)
            {
                return Unauthorized(new
                {
                    message = "Invalid username or password."
                });
            }

            // Verify the password using Identity.
            bool passwordIsValid = await _userManager.CheckPasswordAsync(user,request.Password);

            // Reject incorrect passwords.
            if (!passwordIsValid)
            {
                return Unauthorized(new
                {
                    message = "Invalid username or password."
                });
            }

            // Generate a JWT for the authenticated user.
            var token = _jwtService.GenerateToken(user.UserName!);

            return Ok(new
            {
                accessToken = token,
                tokenType = "Bearer"
            });
        }

        // Return the current user's profile using the JWT identity.
        [Authorize]
        [HttpGet("me")]
        public IActionResult Me()
        {
            var response = new UserProfileResponse
            {
                Username = User.Identity?.Name ?? string.Empty
            };

            return Ok(response);
        }

        // Change the password of the authenticated user.
        [Authorize]
        [HttpPut("change-password")]
        public async Task<IActionResult> ChangePassword([FromBody] ChangePasswordRequest request)
        {
            // Read the username from the authenticated token.
            var username = User.Identity?.Name;

            if (username == null)
            {
                return Unauthorized();
            }

            // Find the corresponding Identity user.
            var user = await _userManager.FindByNameAsync(username);

            if (user == null)
            {
                return Unauthorized();
            }

            // Verify the current password and set the new one.
            var result = await _userManager.ChangePasswordAsync(user,request.CurrentPassword,request.NewPassword);

            // Return errors if the password change fails.
            if (!result.Succeeded)
            {
                return BadRequest(new
                {
                    errors = result.Errors.Select(error => error.Description)
                });
            }

            return Ok(new
            {
                message = "Password changed successfully."
            });
        }
    }
}
