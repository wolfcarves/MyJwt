using System.ComponentModel;

namespace MyJwt.DTO;

public class UserDTO
{

    [DefaultValue("user")]
    public string Role { get; set; }
}