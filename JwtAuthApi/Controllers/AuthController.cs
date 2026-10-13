using JwtAuthApi.Models;
using JwtAuthApi.Services;
using Microsoft.AspNetCore.Mvc;

namespace JwtAuthApi.Controllers
{
    [Route("[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly JwtService _jwtService;

        public AuthController(JwtService jwtService)
        {
            _jwtService = jwtService;
        }

        [HttpPost("login")]
        public IActionResult Login([FromBody] LoginRequest request)
        {
            // Temporary test credentials
            if (request.Username != "testuser" || request.Password != "Pass123!")
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
    }
}
