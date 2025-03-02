namespace MyJwt.Controllers.AuthController;

using Microsoft.AspNetCore.Mvc;
using MyJwt.DTO;
using MyJwt.Attributes;
using MyJwt.Services;
using Swashbuckle.AspNetCore.Annotations;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IJwtService _jwtService;

    public AuthController(IJwtService jwtService)
    {
        _jwtService = jwtService;
    }

    [HttpPost]
    [SwaggerOperation(
        Description = "'user' can be replaced with 'admin' to get priviledge to specific endpoint role"
    )]
    public IActionResult LoginUser([FromBody] UserDTO userDto)
    {
        if (userDto.Role.ToLower() == "user")
        {
            string token = _jwtService.GenerateToken("user");
            return Ok(new { token });
        }

        if (userDto.Role.ToLower() == "admin")
        {
            string token = _jwtService.GenerateToken("user");
            return Ok(new { token });
        }

        return BadRequest("Not a valid role");
    }


    [HttpGet]
    [JwtAuthorize]
    [UserAuthorize]
    public IActionResult GetUserData()
    {
        return Ok("test");
    }
}