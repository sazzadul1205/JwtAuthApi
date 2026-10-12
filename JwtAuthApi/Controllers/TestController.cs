using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Authorization;

namespace JwtAuthApi.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class TestController : Controller
    {
        [HttpGet("public")]
        public IActionResult Public()
        {
            return Ok(new
            {
                message = "This is a public endpoint."
            });
        }

        [Authorize]
        [HttpGet("private")]
        public IActionResult Private()
        {
            return Ok(new
            {
                message = "This is a Private endpoint."
            });
        }


        public IActionResult Index()
        {
            return View();
        }
    }
}
