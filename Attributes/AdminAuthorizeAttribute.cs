using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;
using Microsoft.IdentityModel.Tokens;

namespace MyJwt.Attributes;

public class AdminAuthorizeAttribute : ActionFilterAttribute
{
    public override async Task OnActionExecutionAsync(ActionExecutingContext context, ActionExecutionDelegate next)
    {
        if (!TryGetClaimsPrincipal(context, out var claimsPrincipal))
        {
            context.Result = new UnauthorizedResult();
            return;
        }

        var roleClaim = claimsPrincipal.FindFirst(ClaimTypes.Role)?.Value;

        Console.WriteLine($"roleClaim {roleClaim}");

        if (roleClaim != "admin")
        {
            context.Result = new JsonResult(new { message = "You only have admin rights" })
            {
                StatusCode = StatusCodes.Status403Forbidden
            };
            return;
        }

        context.HttpContext.User = claimsPrincipal;
        await next();
    }

    private static bool TryGetClaimsPrincipal(ActionExecutingContext context, out ClaimsPrincipal claimsPrincipal)
    {
        claimsPrincipal = new ClaimsPrincipal();
        var authorizationHeader = context.HttpContext.Request.Headers.Authorization.FirstOrDefault();

        if (string.IsNullOrEmpty(authorizationHeader) || !authorizationHeader.StartsWith("Bearer "))
        {
            return false;
        }

        var token = authorizationHeader["Bearer ".Length..].Trim();
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.UTF8.GetBytes("A_VERY_LONG_SECRET_KEY_SINCE_THIS_REQUIRED_VERY_LONG_SECREY_KEY_XD");

        try
        {
            var validationParameters = new TokenValidationParameters
            {
                ValidateIssuerSigningKey = true,
                IssuerSigningKey = new SymmetricSecurityKey(key),
                ValidateIssuer = true,
                ValidIssuer = "http://localhost:5000",
                ValidateAudience = true,
                ValidAudience = "http://localhost:5000",
                ValidateLifetime = true,
                ClockSkew = TimeSpan.Zero
            };

            claimsPrincipal = tokenHandler.ValidateToken(token, validationParameters, out _);
            return true;
        }
        catch
        {
            return false;
        }
    }
}
