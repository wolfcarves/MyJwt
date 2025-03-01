namespace MyJwt.Controllers.AuthController;

using Microsoft.AspNetCore.Mvc;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    public AuthController() { }

    [HttpGet]
    public IActionResult GetSession()
    {
        return Ok("Hello there");
    }
}