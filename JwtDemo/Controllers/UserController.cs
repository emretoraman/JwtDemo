using JwtDemo.Models;
using JwtDemo.Services;
using Microsoft.AspNetCore.Mvc;
using System.Threading.Tasks;

namespace JwtDemo.Controllers
{
    [ApiController]
    [Route("[controller]")]
    public class UserController : ControllerBase
    {
        private readonly IUserService _userService;

        public UserController(IUserService userService)
        {
            _userService = userService;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterRequest request)
        {
            string response = await _userService.Register(request);
            return Ok(response);
        }

        [HttpPost("token")]
        public async Task<IActionResult> GetToken(TokenRequest request)
        {
            TokenResponse response = await _userService.GetToken(request);
            return Ok(response);
        }

        [HttpPost("addrole")]
        public async Task<IActionResult> AddRole(AddRoleRequest request)
        {
            string response = await _userService.AddRole(request);
            return Ok(response);
        }

    }
}
