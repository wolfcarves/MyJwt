namespace MyJwt.Services;

public interface IJwtService
{
    public string GenerateToken(string username);
}