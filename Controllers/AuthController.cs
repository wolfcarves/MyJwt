namespace MyJwt.Controllers.AuthController;

using Microsoft.AspNetCore.Mvc;
using MyJwt.DTO;
using MyJwt.Attributes;
using MyJwt.Services;
using Swashbuckle.AspNetCore.Annotations;

/*
I have 3 endpoints:

1 for login ( user | admin )
1 for fetching user data
1 for fetching admin data

Basically you can only fetch data from a specific endpoint depending on user role, you get the idea
*/

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private readonly IJwtService _jwtService;

    public AuthController(IJwtService jwtService)
    {
        _jwtService = jwtService;
    }

    [HttpPost("login")]
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
            string token = _jwtService.GenerateToken("admin");
            return Ok(new { token });
        }

        return BadRequest("Not a valid role");
    }

    [HttpGet("user")]
    [JwtAuthorize]
    [UserAuthorize]
    public IActionResult GetUserData()
    {
        return Ok("User Data");
    }

    [HttpGet("admin")]
    [JwtAuthorize]
    [AdminAuthorize]
    public IActionResult GetAdminData()
    {
        return Ok("Admin Data");
    }
}